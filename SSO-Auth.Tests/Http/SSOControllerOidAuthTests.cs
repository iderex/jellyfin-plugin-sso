// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the OpenID auth callback (<c>OidAuth</c>) via <see cref="SsoControllerHarness"/>.
/// The callback consumes an already-validated authorize state (populated by the browser redirect leg in
/// the real flow), so these tests seed that state directly with the harness's test hook. They cover the
/// guard branches (missing data, disabled provider, unknown state) and the happy path, where a valid,
/// single-use state provisions the account and mints a session.
/// </summary>
[Collection("SSOController")]
public class SSOControllerOidAuthTests
{
    private static readonly Guid UserId = Guid.Parse("77777777-7777-7777-7777-777777777777");

    // The browser-binding id (#326) the challenge recorded on the state; the redeem leg must present the
    // same value (via the binding cookie) or the state is refused without being consumed.
    private const string Binding = "oidauth-browser-binding";

    [Fact]
    public async Task OidAuth_MissingData_ReturnsBadRequest()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = await harness.Controller.OidAuth("kc", new AuthResponse());

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task OidAuth_DisabledProvider_RejectsAsUnknownProvider()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = false });

        // A disabled provider is a client-caused rejection, not a server fault: a uniform 400 that is
        // byte-identical to the unknown-provider case, so the two cannot be told apart (#318).
        var result = await harness.Controller.OidAuth("kc", new AuthResponse { Data = "state-token" });

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("No matching provider found", content.Content);
    }

    [Fact]
    public async Task OidAuth_UnknownState_RejectsAsInvalidState()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        // No state was seeded, so the token does not resolve — a client-caused 400, not a 500, and the
        // same body an expired or replayed state gets, so a replay is indistinguishable from an expiry.
        var result = await harness.Controller.OidAuth("kc", new AuthResponse { Data = "no-such-state" });

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Invalid or expired state", content.Content);
    }

    [Fact]
    public async Task OidAuth_ValidState_ProvisionsAccountReturnsOk_AndIsSingleUse()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            EnableAuthorization = false, // skip the permission-application block; not under test here
            AllowExistingAccountLink = false,
        });
        SeedValidState(harness, "state-token");
        SetBindingCookie(harness, Binding);

        var result = await harness.Controller.OidAuth("kc", new AuthResponse
        {
            Data = "state-token",
            DeviceID = "device-1",
            DeviceName = "Test Device",
            AppName = "Jellyfin Web",
            AppVersion = "1.0",
        });

        Assert.IsType<OkObjectResult>(result);

        // The state is claimed atomically (TryRemove), so a replay of the same token no longer redeems —
        // it rejects as an invalid state (a client-caused 400), indistinguishable from an expiry.
        var replay = await harness.Controller.OidAuth("kc", new AuthResponse { Data = "state-token" });
        var content = Assert.IsType<ContentResult>(replay);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Invalid or expired state", content.Content);

        // The replay minted nothing: the account was provisioned exactly once, by the first redemption.
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task OidAuth_MissingBindingCookie_RejectsAsInvalidState_WithoutConsumingTheState()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
        });
        SeedValidState(harness, "state-token");
        // No binding cookie is set: the redeem arrives from a different browser than started the flow.

        var rejected = await harness.Controller.OidAuth("kc", new AuthResponse
        {
            Data = "state-token",
            DeviceID = "device-1",
            DeviceName = "Test Device",
            AppName = "Jellyfin Web",
            AppVersion = "1.0",
        });

        // #326: refused with the uniform invalid-state body, and — crucially — the state was NOT consumed
        // (the binding check precedes the atomic remove), so a wrong-browser attempt cannot burn a
        // legitimate user's in-flight state, and nothing was provisioned.
        var content = Assert.IsType<ContentResult>(rejected);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Invalid or expired state", content.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());

        // The state survived the wrong-browser hit: presenting the correct binding cookie still redeems it.
        SetBindingCookie(harness, Binding);
        var accepted = await harness.Controller.OidAuth("kc", new AuthResponse
        {
            Data = "state-token",
            DeviceID = "device-1",
            DeviceName = "Test Device",
            AppName = "Jellyfin Web",
            AppVersion = "1.0",
        });
        Assert.IsType<OkObjectResult>(accepted);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task OidAuth_RequireVerifiedEmailForLoginOff_Succeeds_RegardlessOfEmailVerified()
    {
        // The availability-critical property (#166): with the flag off (the default), the login succeeds
        // even when email_verified is absent (null) — behaviour is byte-identical to before the gate, so no
        // existing deployment or claim-omitting IdP is affected on upgrade.
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
            RequireVerifiedEmailForLogin = false,
        });
        SeedValidState(harness, "state-token", emailVerified: null);
        SetBindingCookie(harness, Binding);

        var result = await harness.Controller.OidAuth("kc", Redeem("state-token"));

        Assert.IsType<OkObjectResult>(result);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task OidAuth_RequireVerifiedEmailForLoginOn_EmailVerifiedTrue_Succeeds()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
            RequireVerifiedEmailForLogin = true,
        });
        SeedValidState(harness, "state-token", emailVerified: true);
        SetBindingCookie(harness, Binding);

        var result = await harness.Controller.OidAuth("kc", Redeem("state-token"));

        Assert.IsType<OkObjectResult>(result);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Theory]
    [InlineData(false)] // the IdP asserted the email is NOT verified
    [InlineData(null)]  // the claim was absent or unparseable
    public async Task OidAuth_RequireVerifiedEmailForLoginOn_EmailNotVerified_RejectsAndMintsNothing(bool? emailVerified)
    {
        // Fail closed (#166): with the flag on, anything other than email_verified == true rejects the whole
        // login with the 403 gate body, and — crucially — no account is provisioned and no session minted.
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
            RequireVerifiedEmailForLogin = true,
        });
        SeedValidState(harness, "state-token", emailVerified);
        SetBindingCookie(harness, Binding);

        var result = await harness.Controller.OidAuth("kc", Redeem("state-token"));

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(403, content.StatusCode);
        Assert.Equal("A verified email is required to log in.", content.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    // A fully-populated redeem request; the state token is the only field these gate tests vary.
    private static AuthResponse Redeem(string state) => new AuthResponse
    {
        Data = state,
        DeviceID = "device-1",
        DeviceName = "Test Device",
        AppName = "Jellyfin Web",
        AppVersion = "1.0",
    };

    // Seeds a valid, redeemable login state for provider "kc" bound to a new user "alice", and mocks the
    // user provisioning + session lookup the happy path drives. BindingId records the browser-binding id
    // the challenge would have set; the redeem leg must present the matching cookie (see SetBindingCookie).
    // emailVerified is the email_verified claim the login resolved (null = absent), so a test can exercise
    // the verified-email login gate (#166).
    private static void SeedValidState(SsoControllerHarness harness, string token, bool? emailVerified = null)
    {
        var pending = new AuthorizeSession.Pending(new AuthorizeState { State = token }, "kc", isLinking: false, DateTime.UtcNow, Binding, clientKey: null, providerInformation: null!, responseIssuerRequired: false);
        var ready = new AuthorizeSession.Ready(
            pending,
            new OidcAuthorizeStateBuilder.OidcAuthorizeState(
                Username: "alice", Subject: "sub-1", Issuer: null, EmailVerified: emailVerified, Valid: true, Admin: false,
                EnableLiveTv: false, EnableLiveTvManagement: false, Folders: new List<string>(), AvatarUrl: null));
        OidcLoginService.SeedOidStateForTests(token, ready);

        var user = TestUsers.Named("alice", UserId);
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(UserId).Returns(user);
    }

    // Presents the browser-binding cookie on the controller's request (#326). Populating the Cookie header
    // is how a DefaultHttpContext exposes Request.Cookies, which the callback reads.
    private static void SetBindingCookie(SsoControllerHarness harness, string value) =>
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={value}";
}
