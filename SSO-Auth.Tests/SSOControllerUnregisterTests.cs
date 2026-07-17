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

    // Registers a user with the harness's mocked IUserManager so GetUserByName resolves it.
    private static User SeedUser(SsoControllerHarness harness)
    {
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        harness.UserManager.GetUserByName("alice").Returns(user);
        return user;
    }
}
