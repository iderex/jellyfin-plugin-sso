// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Reflection;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the <c>Unregister</c> endpoint via <see cref="SsoControllerHarness"/>: a known
/// user's SSO is revoked (its canonical links are dropped and the auth provider is persisted), and the
/// revoke returns Ok. The unknown-user guard is covered in <see cref="SSOControllerChallengeTests"/>.
/// </summary>
[Collection("SSOController")]
public class SSOControllerUnregisterTests
{
    private static readonly Guid UserId = Guid.Parse("44444444-4444-4444-4444-444444444444");

    [Fact]
    public async Task Unregister_KnownUser_PersistsProviderSwitch_ReturnsOk()
    {
        var harness = new SsoControllerHarness();
        var user = SeedUser(harness);

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        // The switch back to the local auth provider must be PERSISTED (a prior version only set it in memory).
        Assert.Equal("Jellyfin", user.AuthenticationProviderId);
        await harness.UserManager.Received(1).UpdateUserAsync(user);
    }

    [Fact]
    public async Task Unregister_KnownUser_RemovesTheUsersCanonicalLinks()
    {
        var harness = new SsoControllerHarness(c =>
            c.OidConfigs["keycloak"] = new OidConfig
            {
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-alice"] = UserId },
            });
        SeedUser(harness);

        await harness.Controller.Unregister("alice", "Jellyfin");

        // Revoking SSO must drop every canonical link pointing at the user, or the account could still sign in (#213).
        var links = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks);
        Assert.False(links.ContainsKey("sub-alice"));
    }

    [Fact]
    public async Task Unregister_KnownUser_RevokesTheTargetUsersActiveTokens()
    {
        var harness = new SsoControllerHarness();
        SeedUser(harness);

        await harness.Controller.Unregister("alice", "Jellyfin");

        // A hard revoke must also terminate the user's already-issued tokens, scoped to this one user; null
        // revokes all of their tokens (#440).
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public async Task Unregister_DoesNotRevokeTokensForOtherUsers()
    {
        var harness = new SsoControllerHarness();
        SeedUser(harness);
        var otherUser = Guid.Parse("55555555-5555-5555-5555-555555555555");

        await harness.Controller.Unregister("alice", "Jellyfin");

        // The revoke is scoped strictly to the resolved target — no other user's tokens may be swept.
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(otherUser, Arg.Any<string?>());
    }

    [Fact]
    public async Task Unregister_TokenRevokeNoOp_StillCompletesOk()
    {
        // With the mock's default (a completed no-op task) the revoke changes nothing; the unregister must
        // still persist the provider switch and return Ok.
        var harness = new SsoControllerHarness();
        var user = SeedUser(harness);

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        await harness.UserManager.Received(1).UpdateUserAsync(user);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public async Task Unregister_WhenTokenRevokeFails_LinksAlreadyRemovedAndProviderPersisted()
    {
        // The token revoke runs LAST, after the durable revoke is committed, so a failure there cannot leave
        // the unregister half-done: the links are already dropped and the provider switch persisted (#440).
        var harness = new SsoControllerHarness(c =>
            c.OidConfigs["keycloak"] = new OidConfig
            {
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-alice"] = UserId },
            });
        var user = SeedUser(harness);
        harness.SessionManager.RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>())
            .Returns(Task.FromException(new InvalidOperationException("session store unavailable")));

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Controller.Unregister("alice", "Jellyfin"));

        var links = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks);
        Assert.False(links.ContainsKey("sub-alice"));
        Assert.Equal("Jellyfin", user.AuthenticationProviderId);
        await harness.UserManager.Received(1).UpdateUserAsync(user);
    }

    [Fact]
    public async Task Unregister_AuthorizedOverRateLimit_Returns429()
    {
        // #516: the admin SSO-revoke is throttled by the shared gate under its own "unregister" class. A burst
        // past the configured budget is refused with the same 429 the login path renders, before any work runs.
        var harness = new SsoControllerHarness(
            c =>
            {
                c.EnableRateLimit = true;
                c.RateLimitMaxAttempts = 1;
                c.RateLimitWindowSeconds = 60;
            },
            // A dedicated public address so the process-static limiter counter is this test's alone.
            clientIp: IPAddress.Parse("8.8.4.20"));
        var user = SeedUser(harness);

        // The first call passes the limiter, spends the single-attempt budget, and completes the revoke (Ok).
        Assert.IsType<OkResult>(await harness.Controller.Unregister("alice", "Jellyfin"));

        // The second is over budget and throttled before any work: a 429 from LoginOutcome.Throttled via the
        // single mapper (#474), carrying the machine-readable Retry-After.
        var throttled = Assert.IsType<ContentResult>(await harness.Controller.Unregister("alice", "Jellyfin"));
        Assert.Equal(429, throttled.StatusCode);
        Assert.Equal("Too many attempts. Please wait a moment and try again.", throttled.Content);

        var retryAfter = harness.Controller.Response.Headers.RetryAfter.ToString();
        Assert.True(
            int.TryParse(retryAfter, out var seconds) && seconds >= 1 && seconds <= 60,
            $"Retry-After must be whole seconds within the 60s window; was '{retryAfter}'.");

        // The throttled call did no work: only the first revoke touched the session manager (#440 untouched by the 429).
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public async Task Unregister_AuthorizedUnderRateLimit_NotThrottled()
    {
        // With rate limiting enabled but the budget generous (the default 30/60s), a normal admin unregister is
        // unaffected: it revokes SSO and returns Ok, never a 429, and the #440 session revocation still fires.
        var harness = new SsoControllerHarness(
            c =>
            {
                c.EnableRateLimit = true;
                c.RateLimitMaxAttempts = 30;
                c.RateLimitWindowSeconds = 60;
            },
            clientIp: IPAddress.Parse("8.8.4.21"));
        SeedUser(harness);

        var result = await harness.Controller.Unregister("alice", "Jellyfin");

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserId, null);
    }

    [Fact]
    public void Unregister_IsGuardedByTheElevationPolicy_SoUnauthorizedNeverReachesTheLimiter()
    {
        // The in-process harness calls the action directly, bypassing MVC's authorization filters, so the
        // "unauthorized never 429" property is pinned structurally instead: the [Authorize(RequiresElevation)]
        // filter rejects a non-elevated caller (401/403) BEFORE the action body — and thus before the
        // RateLimitCheck the body fronts itself with — runs. So no 429 can ever precede the auth rejection: a
        // hammering unauthorized caller is refused, never throttled, and never consumes the "unregister" budget.
        var authorize = typeof(SSOController).GetMethod(nameof(SSOController.Unregister))!
            .GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(authorize);
        Assert.Equal(Policies.RequiresElevation, authorize!.Policy);
    }

    // Registers a user with the harness's mocked IUserManager so GetUserByName resolves it.
    private static User SeedUser(SsoControllerHarness harness)
    {
        var user = TestUsers.Named("alice", UserId);
        harness.UserManager.GetUserByName("alice").Returns(user);
        return user;
    }
}
