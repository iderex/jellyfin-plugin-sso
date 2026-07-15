using System;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Direct tests of <see cref="SessionMinter"/> — the session-minting flow extracted from the controller
/// (#318). They pin the fail-closed guard (a login whose resolved account no longer exists mints no
/// session) and that the controller-supplied remote endpoint reaches the authentication request (the one
/// behavior this extraction changes: the endpoint is passed in rather than read from HttpContext).
/// </summary>
public class SessionMinterTests
{
    private static readonly Guid UserId = Guid.Parse("77777777-7777-7777-7777-777777777777");

    private static (SessionMinter Minter, IUserManager Users, ISessionManager Sessions) Build()
    {
        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        // A real AvatarService (its deps stubbed): with a null AvatarUrl its fetch early-returns, so it is
        // never reached destructively here.
        var avatar = new AvatarService(users, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), new CapturingLogger(), "test-agent");
        var minter = new SessionMinter(users, avatar, sessions, new CapturingLogger());
        return (minter, users, sessions);
    }

    private static SessionParameters Params() => new SessionParameters
    {
        UserId = UserId,
        IsAdmin = false,
        EnableAuthorization = false,
        EnableAllFolders = false,
        EnabledFolders = Array.Empty<string>(),
        EnableLiveTv = false,
        EnableLiveTvManagement = false,
        AvatarUrl = null,
        DefaultProvider = null,
        AuthResponse = new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" },
    };

    [Fact]
    public async Task MintAsync_ResolvedAccountDeleted_ThrowsAndMintsNoSession()
    {
        // Fail closed (#318): the account resolved for this login no longer exists (deleted between
        // resolution and the mint), so no session may be minted — the throw precedes any AuthenticateDirect.
        var (minter, users, sessions) = Build();
        users.GetUserById(UserId).Returns((User?)null);

        await Assert.ThrowsAsync<AuthenticationException>(() => minter.MintAsync(Params(), "203.0.113.7"));

        await sessions.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>());
    }

    [Fact]
    public async Task MintAsync_ResolvedAccount_PassesTheSuppliedRemoteEndPointToTheAuthRequest()
    {
        // The extraction's one behavior change: the controller resolves the client IP from HttpContext and
        // passes it in, so it must land on the AuthenticationRequest unchanged (#177) alongside the user.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        users.GetUserById(UserId).Returns(user);
        AuthenticationRequest? captured = null;
        sessions.AuthenticateDirect(Arg.Do<AuthenticationRequest>(r => captured = r)).Returns(new AuthenticationResult());

        await minter.MintAsync(Params(), "203.0.113.7");

        Assert.NotNull(captured);
        Assert.Equal("203.0.113.7", captured!.RemoteEndPoint);
        Assert.Equal(UserId, captured.UserId);
        Assert.Equal("alice", captured.Username);
    }
}
