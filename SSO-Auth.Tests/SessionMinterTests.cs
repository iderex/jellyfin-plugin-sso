using System;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
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

    private static SessionParameters Params(
        bool enableAuthorization = false,
        bool isAdmin = false,
        bool enableAllFolders = false,
        string[]? enabledFolders = null,
        bool enableLiveTv = false,
        bool enableLiveTvManagement = false,
        string? avatarUrl = null,
        string? defaultProvider = null) => new SessionParameters
    {
        UserId = UserId,
        IsAdmin = isAdmin,
        EnableAuthorization = enableAuthorization,
        EnableAllFolders = enableAllFolders,
        EnabledFolders = enabledFolders ?? Array.Empty<string>(),
        EnableLiveTv = enableLiveTv,
        EnableLiveTvManagement = enableLiveTvManagement,
        AvatarUrl = avatarUrl,
        DefaultProvider = defaultProvider,
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

    [Fact]
    public async Task MintAsync_EnableAuthorizationWithRestrictedFolders_AppliesAllRoleGrants()
    {
        // #215: with the master switch on, all five role-derived grants are applied — including the two
        // Live TV grants — and folder access is restricted (!EnableAllFolders), which also writes the
        // enabled-folder list as a preference.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(
            Params(enableAuthorization: true, isAdmin: true, enableAllFolders: false, enabledFolders: new[] { "lib-1" }, enableLiveTv: true, enableLiveTvManagement: true),
            "203.0.113.7");

        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.IsAdministrator && perm.Value);
        Assert.DoesNotContain(user.Permissions, perm => perm.Kind == PermissionKind.EnableAllFolders && perm.Value);
        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.EnableLiveTvAccess && perm.Value);
        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.EnableLiveTvManagement && perm.Value);
    }

    [Fact]
    public async Task MintAsync_EnableAuthorizationWithAllFolders_GrantsAllFolders_SkippingTheFolderRestriction()
    {
        // The other side of the EnableAllFolders branch: all folders granted, so the enabled-folder
        // preference write is skipped (that path is only for the restricted case above).
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(Params(enableAuthorization: true, enableAllFolders: true), "203.0.113.7");

        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.EnableAllFolders && perm.Value);
    }

    [Fact]
    public async Task MintAsync_NoAuthorization_LeavesPermissionsUntouched()
    {
        // With the master switch off, no SSO-driven grant is applied — the account keeps whatever it had
        // (here, a fresh account with no admin grant). Pins that EnableAuthorization gates the whole block.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(Params(enableAuthorization: false, isAdmin: true), "203.0.113.7");

        Assert.DoesNotContain(user.Permissions, perm => perm.Kind == PermissionKind.IsAdministrator && perm.Value); // isAdmin ignored while off
    }

    [Fact]
    public async Task MintAsync_DefaultProviderSet_SetsItAndWritesTheUserTwice()
    {
        // When a default provider is configured the user's AuthenticationProviderId is set, which the
        // pre-extraction Authenticate persisted with a SECOND UpdateUserAsync (once after
        // permissions/avatar, once after the provider id). This pins that verbatim two-write behavior; a
        // single-write optimization would be an observable change, tracked separately, not folded into the
        // behavior-preserving extraction.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(Params(defaultProvider: "SSO-Auth"), "203.0.113.7");

        Assert.Equal("SSO-Auth", user.AuthenticationProviderId);
        await users.Received(2).UpdateUserAsync(user);
    }
}
