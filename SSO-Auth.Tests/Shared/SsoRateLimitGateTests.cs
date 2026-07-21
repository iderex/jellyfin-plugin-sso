// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SsoRateLimitGate"/> — the shared per-client gate the rate-limited SSO endpoints
/// front themselves with (#128, #382, #516). These pin the gate's OWN behavior over the
/// <see cref="Jellyfin.Plugin.SSO_Auth.Api.SsoRateLimiter"/> it wraps: it reads the live config through
/// <see cref="Jellyfin.Plugin.SSO_Auth.SSOPlugin.Instance"/>, folds the endpoint class into the key so each
/// class carries an independent budget, and — this is the load-bearing availability invariant — never
/// throttles an unattributable or non-public client (fail open, availability over throttling), so a reverse
/// proxy's private/loopback peer address or a null connection address can never mass-lock-out the userbase.
///
/// The gate owns ONE process-wide <see cref="Jellyfin.Plugin.SSO_Auth.Api.SsoRateLimiter"/> static and reads
/// the process-wide <see cref="Jellyfin.Plugin.SSO_Auth.SSOPlugin.Instance"/>, so these run in the
/// non-parallel <c>SSOController</c> collection and each test uses a UNIQUE endpoint-class prefix, guaranteeing
/// its per-client counters cannot collide with a sibling test's (the gate keys on <c>class:client</c>).
/// </summary>
[Collection("SSOController")]
public class SsoRateLimitGateTests
{
    // Genuinely public addresses (1.0.0.0/8 is not in any blocked range), so NormalizeClientKey attributes
    // them and the limiter actually tracks a bucket. Distinct per test to reinforce the class-prefix isolation.
    private static readonly IPAddress PublicClient = IPAddress.Parse("1.2.3.4");

    // Seeds the process-wide SSOPlugin.Instance with a rate-limit config, exactly as the controller reads it.
    // The harness constructs the plugin (setting the static Instance) through the same mocked collaborators the
    // existing controller tests use; only the seeded configuration matters to the gate.
    private static void SeedConfig(bool enabled, int maxAttempts, int windowSeconds)
    {
        _ = new SsoControllerHarness(configure: c =>
        {
            c.EnableRateLimit = enabled;
            c.RateLimitMaxAttempts = maxAttempts;
            c.RateLimitWindowSeconds = windowSeconds;
        });
    }

    // remoteIp is nullable here on purpose: the no-attributable-address case (a null connection peer) is one
    // of the fail-open inputs under test. The gate's own NormalizeClientKey handles null (returns no key), so
    // forwarding it is the behavior being exercised, not a defect — hence the deliberate null-forgiving pass.
    private static ActionResult? Check(string endpointClass, IPAddress? remoteIp, HttpResponse response) =>
        SsoRateLimitGate.Check(endpointClass, remoteIp!, Substitute.For<ILogger>(), response);

    [Fact]
    public void OverBudget_Emits429_WithRetryAfterHeader()
    {
        // A budget of one: the first request is allowed (null = proceed), the second is over budget and is
        // refused with the throttled outcome rendered by the single mapper — a 429 carrying a Retry-After.
        SeedConfig(enabled: true, maxAttempts: 1, windowSeconds: 60);
        var response = new DefaultHttpContext().Response;
        const string EndpointClass = "gate-test-overbudget";

        Assert.Null(Check(EndpointClass, PublicClient, response));

        var throttled = Assert.IsType<ContentResult>(Check(EndpointClass, PublicClient, response));
        Assert.Equal(429, throttled.StatusCode);

        // The gate's documented contract is a 429 WITH a machine-readable Retry-After. Assert the header is
        // present and a positive whole-second delay bounded by the window (the gate clocks off DateTime.UtcNow,
        // so the exact value is not pinned, but a missing or non-positive header would be a regression).
        var retryAfter = response.Headers.RetryAfter.ToString();
        Assert.False(string.IsNullOrEmpty(retryAfter));
        var seconds = int.Parse(retryAfter, CultureInfo.InvariantCulture);
        Assert.InRange(seconds, 1, 60);
    }

    [Fact]
    public void DistinctEndpointClasses_HaveIndependentBudgets()
    {
        // The endpoint class is part of the key, so exhausting one class's budget for a client must not
        // throttle the SAME client on a different class — one login hitting challenge/callback/auth gets the
        // full budget at each stage rather than a third of it (#128).
        SeedConfig(enabled: true, maxAttempts: 1, windowSeconds: 60);
        var response = new DefaultHttpContext().Response;
        const string ClassA = "gate-test-classA";
        const string ClassB = "gate-test-classB";

        // Class A: drive the same client over its budget.
        Assert.Null(Check(ClassA, PublicClient, response));
        var throttledOnA = Assert.IsType<ContentResult>(Check(ClassA, PublicClient, response));
        Assert.Equal(429, throttledOnA.StatusCode);

        // Class B, same client: still has its own untouched budget — not collateral-throttled by class A.
        Assert.Null(Check(ClassB, PublicClient, new DefaultHttpContext().Response));
    }

    [Fact]
    public void Disabled_NeverThrottles_EvenOverBudget()
    {
        // With the limiter switched off in config the gate is a pass-through: no bucket, no 429, regardless of
        // volume. Guards against the gate throttling when the operator has not opted in.
        SeedConfig(enabled: false, maxAttempts: 1, windowSeconds: 60);
        const string EndpointClass = "gate-test-disabled";

        for (var i = 0; i < 10; i++)
        {
            Assert.Null(Check(EndpointClass, PublicClient, new DefaultHttpContext().Response));
        }
    }

    [Theory]
    [InlineData("127.0.0.1")] // loopback — a local reverse proxy's own peer address
    [InlineData("10.0.0.5")] // RFC1918 private — a proxy on the LAN
    [InlineData("100.64.0.1")] // CGNAT
    [InlineData("::1")] // IPv6 loopback
    [InlineData(null)] // no attributable connection address at all
    public void UnattributableOrNonPublicClient_NeverThrottled_FailOpen(string? ip)
    {
        // THE availability invariant: an unattributable / non-public client is NEVER throttled, so it can
        // never be permanently locked out. The config is fully enabled with a budget of one, so if the gate
        // ever flipped to fail-closed (creating a bucket for these sources and throttling them), the second
        // iteration would return a 429 and this test would fail. Every iteration must stay null (allowed).
        SeedConfig(enabled: true, maxAttempts: 1, windowSeconds: 60);
        var remote = ip is null ? null : IPAddress.Parse(ip);
        const string EndpointClass = "gate-test-failopen";

        for (var i = 0; i < 50; i++)
        {
            Assert.Null(Check(EndpointClass, remote, new DefaultHttpContext().Response));
        }
    }

    [Fact]
    public void FailOpen_IsNotVacuous_SameConfigThrottlesAnAttributablePublicClient()
    {
        // Proves the fail-open theory above is meaningful, not a limiter that is simply inert: under the very
        // same enabled, budget-of-one config, an attributable PUBLIC client IS throttled past its budget. So
        // the non-public client's pass-through is genuinely the fail-open exemption, not a disabled limiter.
        SeedConfig(enabled: true, maxAttempts: 1, windowSeconds: 60);
        const string EndpointClass = "gate-test-failopen-control";
        var client = IPAddress.Parse("1.9.8.7");

        Assert.Null(Check(EndpointClass, client, new DefaultHttpContext().Response));
        var throttled = Assert.IsType<ContentResult>(Check(EndpointClass, client, new DefaultHttpContext().Response));
        Assert.Equal(429, throttled.StatusCode);
    }
}
