// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Net;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// 429 response-shape pins for the login-path and outbound-fetch endpoints that were wired to the
/// shared rate-limit gate but not individually characterised (#928 U2). Each drives its endpoint over
/// the single-attempt budget and asserts the throttled response is byte-identical to the mapper's
/// contract: a 429 with the fixed plain-text body and a Retry-After within the window. The structural
/// "every such endpoint actually calls the gate" guarantee is <c>ArchitectureConformanceTests.
/// EveryMustThrottleEndpoint_CallsTheRateLimitGate</c>; these prove the wiring produces the right wire
/// response at each route. The already-pinned endpoints (SamlChallenge, OidCallback, Link, Unregister)
/// keep their own tests; this fills the remainder.
/// </summary>
[Collection("SSOController")]
public class SSOControllerRateLimitTests
{
    private const string ThrottledBody = "Too many attempts. Please wait a moment and try again.";

    private static SsoControllerHarness Throttling(IPAddress clientIp) => new SsoControllerHarness(
        c =>
        {
            c.EnableRateLimit = true;
            c.RateLimitMaxAttempts = 1;
            c.RateLimitWindowSeconds = 60;
        },
        clientIp);

    private static void AssertThrottled(SsoControllerHarness harness, ActionResult result)
    {
        var throttled = Assert.IsType<ContentResult>(result);
        Assert.Equal(429, throttled.StatusCode);
        Assert.Equal(ThrottledBody, throttled.Content);
        Assert.Equal("text/plain", throttled.ContentType);

        var retryAfter = harness.Controller.Response.Headers.RetryAfter.ToString();
        Assert.True(
            int.TryParse(retryAfter, out var seconds) && seconds >= 1 && seconds <= 60,
            $"Retry-After must be whole seconds within the 60s window; was '{retryAfter}'.");
    }

    [Fact]
    public async Task OidChallenge_OverRateLimit_Returns429()
    {
        // A dedicated public address per test so the process-static limiter counter is this test's alone.
        var harness = Throttling(IPAddress.Parse("8.8.8.1"));

        // The first call spends the single-attempt budget (the unknown provider then 400s, after the spend).
        await harness.Controller.OidChallenge("does-not-exist");

        AssertThrottled(harness, await harness.Controller.OidChallenge("does-not-exist"));
    }

    [Fact]
    public async Task OidAuth_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.2"));

        await harness.Controller.OidAuth("does-not-exist", new AuthResponse());

        AssertThrottled(harness, await harness.Controller.OidAuth("does-not-exist", new AuthResponse()));
    }

    [Fact]
    public async Task OidTest_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.3"));

        await harness.Controller.OidTest("does-not-exist");

        AssertThrottled(harness, await harness.Controller.OidTest("does-not-exist"));
    }

    [Fact]
    public async Task SamlCallback_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.4"));

        await harness.Controller.SamlCallback("does-not-exist");

        AssertThrottled(harness, await harness.Controller.SamlCallback("does-not-exist"));
    }

    [Fact]
    public void SamlMetadata_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.5"));

        harness.Controller.SamlMetadata("does-not-exist");

        AssertThrottled(harness, harness.Controller.SamlMetadata("does-not-exist"));
    }

    [Fact]
    public async Task SamlLogout_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.6"));

        await harness.Controller.SamlLogout("does-not-exist");

        AssertThrottled(harness, await harness.Controller.SamlLogout("does-not-exist"));
    }

    [Fact]
    public async Task SamlAuth_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.7"));

        await harness.Controller.SamlAuth("does-not-exist", new AuthResponse());

        AssertThrottled(harness, await harness.Controller.SamlAuth("does-not-exist", new AuthResponse()));
    }
}
