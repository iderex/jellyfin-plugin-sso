using System;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Config;
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

    // Registers a user with the harness's mocked IUserManager so GetUserByName resolves it.
    private static User SeedUser(SsoControllerHarness harness)
    {
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        harness.UserManager.GetUserByName("alice").Returns(user);
        return user;
    }
}
