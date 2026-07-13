using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
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

    [Fact]
    public async Task OidAuth_MissingData_ReturnsBadRequest()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = await harness.Controller.OidAuth("kc", new AuthResponse());

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task OidAuth_DisabledProvider_ReturnsProblem()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = false });

        // The provider exists but is disabled, so the redeem guard short-circuits to a problem, not a session.
        var result = await harness.Controller.OidAuth("kc", new AuthResponse { Data = "state-token" });

        Assert.Equal(500, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task OidAuth_UnknownState_ReturnsProblem()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        // No state was seeded, so the token does not resolve and no session is minted.
        var result = await harness.Controller.OidAuth("kc", new AuthResponse { Data = "no-such-state" });

        Assert.Equal(500, Assert.IsType<ObjectResult>(result).StatusCode);
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

        var result = await harness.Controller.OidAuth("kc", new AuthResponse
        {
            Data = "state-token",
            DeviceID = "device-1",
            DeviceName = "Test Device",
            AppName = "Jellyfin Web",
            AppVersion = "1.0",
        });

        Assert.IsType<OkObjectResult>(result);
        await harness.UserManager.Received(1).CreateUserAsync("alice");

        // The state is claimed atomically (TryRemove), so a replay of the same token no longer redeems.
        var replay = await harness.Controller.OidAuth("kc", new AuthResponse { Data = "state-token" });
        Assert.Equal(500, Assert.IsType<ObjectResult>(replay).StatusCode);
    }

    // Seeds a valid, redeemable login state for provider "kc" bound to a new user "alice", and mocks the
    // user provisioning + session lookup the happy path drives.
    private static void SeedValidState(SsoControllerHarness harness, string token)
    {
        var state = new TimedAuthorizeState(new AuthorizeState { State = token }, DateTime.Now)
        {
            Provider = "kc",
            Valid = true,
            Subject = "sub-1",
            Username = "alice",
            Folders = new List<string>(),
        };
        SSOController.SeedOidStateForTests(token, state);

        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(UserId).Returns(user);
    }
}
