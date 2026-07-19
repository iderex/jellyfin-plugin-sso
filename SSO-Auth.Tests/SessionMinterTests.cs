using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Data;
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
        bool isBreakGlassAdmin = false,
        bool enableAllFolders = false,
        string[]? enabledFolders = null,
        bool enableLiveTv = false,
        bool enableLiveTvManagement = false,
        string? avatarUrl = null,
        string? defaultProvider = null,
        IReadOnlyList<PermissionGrant>? permissionGrants = null) => new SessionParameters
    {
        UserId = UserId,
        IsAdmin = isAdmin,
        IsBreakGlassAdmin = isBreakGlassAdmin,
        EnableAuthorization = enableAuthorization,
        EnableAllFolders = enableAllFolders,
        EnabledFolders = enabledFolders ?? Array.Empty<string>(),
        EnableLiveTv = enableLiveTv,
        EnableLiveTvManagement = enableLiveTvManagement,
        PermissionGrants = permissionGrants ?? Array.Empty<PermissionGrant>(),
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
        var resolverInvoked = false;

        await Assert.ThrowsAsync<AuthenticationException>(() => minter.MintAsync(
            Params(),
            () =>
            {
                resolverInvoked = true;
                return "203.0.113.7";
            },
            () => true));

        await sessions.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        // The deferred-evaluation contract of the resolver (the reason it is a Func): the fail-closed
        // path rejects before the controller-supplied HttpContext read would ever happen.
        Assert.False(resolverInvoked);
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

        await minter.MintAsync(Params(), () => "203.0.113.7", () => true);

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
        // Seed the OPPOSITE state so the assertions prove the grant flipped, not just that a fresh user
        // happens to match: start with all-folders granted and no admin.
        user.SetPermission(PermissionKind.EnableAllFolders, true);
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(
            Params(enableAuthorization: true, isAdmin: true, enableAllFolders: false, enabledFolders: new[] { "lib-1" }, enableLiveTv: true, enableLiveTvManagement: true),
            () => "203.0.113.7",
            () => true);

        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.IsAdministrator && perm.Value);
        Assert.DoesNotContain(user.Permissions, perm => perm.Kind == PermissionKind.EnableAllFolders && perm.Value); // flipped from the seeded true
        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.EnableLiveTvAccess && perm.Value);
        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.EnableLiveTvManagement && perm.Value);
        Assert.Contains(user.Preferences, pref => pref.Kind == PreferenceKind.EnabledFolders); // restricted-folder list written
    }

    [Fact]
    public async Task MintAsync_EnableAuthorizationWithAllFolders_GrantsAllFolders_SkippingTheFolderRestriction()
    {
        // The other side of the EnableAllFolders branch: all folders granted, so the enabled-folder
        // preference write is skipped (that path is only for the restricted case above).
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        user.SetPermission(PermissionKind.EnableAllFolders, false); // seed a restriction, so the grant must flip to true
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(Params(enableAuthorization: true, enableAllFolders: true), () => "203.0.113.7", () => true);

        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.EnableAllFolders && perm.Value); // flipped from the seeded restriction
    }

    [Fact]
    public async Task MintAsync_NoAuthorization_LeavesPermissionsUntouched()
    {
        // With the master switch off, the whole permission block is skipped, so an EXISTING grant is left
        // untouched. Seed admin=true and pass isAdmin=false: if the block wrongly ran it would set admin
        // to false; a correct skip leaves the seeded admin intact. This pins that EnableAuthorization
        // gates the block AND that it never touches pre-existing permissions when off.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        user.SetPermission(PermissionKind.IsAdministrator, true);
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(Params(enableAuthorization: false, isAdmin: false), () => "203.0.113.7", () => true);

        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.IsAdministrator && perm.Value); // seeded admin left untouched
    }

    [Fact]
    public async Task MintAsync_EnableAuthorization_AppliesGenericPermissionGrants_GrantAndRevoke()
    {
        // #164: with the master switch on, each generic role→permission grant is applied authoritatively —
        // a granted permission is set true and a revoked one set false. Seed the OPPOSITE of each so the
        // assertions prove the mint flipped them, not that a fresh user happened to match.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        user.SetPermission(PermissionKind.EnableContentDownloading, false); // grant must flip to true
        user.SetPermission(PermissionKind.EnableContentDeletion, true); // revoke must flip to false
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(
            Params(
                enableAuthorization: true,
                permissionGrants: new[]
                {
                    new PermissionGrant(PermissionKind.EnableContentDownloading, true),
                    new PermissionGrant(PermissionKind.EnableContentDeletion, false),
                }),
            () => "203.0.113.7",
            () => true);

        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.EnableContentDownloading && perm.Value);
        Assert.DoesNotContain(user.Permissions, perm => perm.Kind == PermissionKind.EnableContentDeletion && perm.Value);
    }

    [Fact]
    public async Task MintAsync_NoAuthorization_LeavesGenericPermissionGrantsUntouched()
    {
        // The generic grants respect the same EnableAuthorization master switch as the admin/Live TV grants
        // (#215): with it off, a mapped permission is NOT applied. Seed the opposite of the grant and pass
        // the master switch off — a correct skip leaves the seed intact.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        user.SetPermission(PermissionKind.EnableContentDownloading, false);
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(
            Params(
                enableAuthorization: false,
                permissionGrants: new[] { new PermissionGrant(PermissionKind.EnableContentDownloading, true) }),
            () => "203.0.113.7",
            () => true);

        Assert.DoesNotContain(user.Permissions, perm => perm.Kind == PermissionKind.EnableContentDownloading && perm.Value); // seed left untouched
    }

    [Fact]
    public async Task MintAsync_BreakGlassAdmin_UnderNonAdminLogin_KeepsAdministrator()
    {
        // #165 Finding H1: while SSO-only mode is on, the designated break-glass admin's OWN SSO login must
        // not be able to demote it. Even with EnableAuthorization on and a login whose claims do NOT grant
        // admin (isAdmin: false), the recovery account keeps IsAdministrator — otherwise the guaranteed
        // recovery admin becomes useless once the IdP is down. Seed admin=true so the assertion proves the
        // demotion was SUPPRESSED, not that a fresh user happened to be non-admin.
        var (minter, users, sessions) = Build();
        var user = new User("root", "SSO-Auth", "Default") { Id = UserId };
        user.SetPermission(PermissionKind.IsAdministrator, true);
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(
            Params(enableAuthorization: true, isAdmin: false, isBreakGlassAdmin: true),
            () => "203.0.113.7",
            () => true);

        Assert.Contains(user.Permissions, perm => perm.Kind == PermissionKind.IsAdministrator && perm.Value); // admin preserved
    }

    [Fact]
    public async Task MintAsync_NonBreakGlassAccount_UnderNonAdminLogin_IsDemotedAsUsual()
    {
        // The negative of the break-glass exemption: a NON-break-glass account is authoritatively demoted when
        // its login carries no admin claim (default-deny). The exemption is narrow — it must never leak to
        // ordinary accounts. Seed admin=true; a correct write flips it to false.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        user.SetPermission(PermissionKind.IsAdministrator, true);
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await minter.MintAsync(
            Params(enableAuthorization: true, isAdmin: false, isBreakGlassAdmin: false),
            () => "203.0.113.7",
            () => true);

        Assert.DoesNotContain(user.Permissions, perm => perm.Kind == PermissionKind.IsAdministrator && perm.Value); // demoted as usual
    }

    [Fact]
    public async Task MintAsync_DefaultProviderSet_SetsItInASingleWrite()
    {
        // When a default provider is configured the user's AuthenticationProviderId is set before the
        // one UpdateUserAsync, so it persists in a single write (#391) — the pre-extraction Authenticate
        // wrote the user a second time just for this field.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        users.GetUserById(UserId).Returns(user);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        // Capture the id at the write boundary, not off the shared user after MintAsync returns —
        // otherwise the assertion passes even if the id is set AFTER the write, defeating the point (#391).
        string? providerAtWrite = null;
        users.UpdateUserAsync(Arg.Do<User>(u => providerAtWrite = u.AuthenticationProviderId)).Returns(Task.CompletedTask);

        await minter.MintAsync(Params(defaultProvider: "SSO-Auth"), () => "203.0.113.7", () => true);

        Assert.Equal("SSO-Auth", providerAtWrite);
        await users.Received(1).UpdateUserAsync(user);
    }

    [Fact]
    public async Task MintAsync_IdentityRevokedInFlight_ThrowsWithoutWritingTheUserOrMintingASession()
    {
        // #232: the account resolved under the config lock, but an admin revocation (Unregister / link
        // delete / provider disable) committed before the mint, so the revocation re-check returns false.
        // The first gate refuses BEFORE any user side effect, so no grants are persisted and no session is
        // minted — fail closed exactly like the deleted-user guard.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        users.GetUserById(UserId).Returns(user);

        await Assert.ThrowsAsync<AuthenticationException>(() => minter.MintAsync(Params(), () => "203.0.113.7", () => false));

        await users.DidNotReceive().UpdateUserAsync(Arg.Any<User>()); // no grants/avatar/provider persisted
        await sessions.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>()); // no session
    }

    [Fact]
    public async Task MintAsync_RevocationRecheck_RunsBeforeTheUserWrite_AndAgainImmediatelyBeforeTheMint()
    {
        // Pins the two-gate placement (#232): the predicate is evaluated once BEFORE the user side
        // effects (so a revoked login persists no grants) and once as the LAST gate after the write and
        // immediately before AuthenticateDirect (so a revocation landing mid-mint still yields no session).
        // A recording predicate captures the state at each firing.
        var (minter, users, sessions) = Build();
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        users.GetUserById(UserId).Returns(user);

        var userWritten = false;
        var mintCalled = false;
        users.UpdateUserAsync(Arg.Any<User>()).Returns(_ => { userWritten = true; return Task.CompletedTask; });
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(_ => { mintCalled = true; return new AuthenticationResult(); });

        var states = new System.Collections.Generic.List<(bool Written, bool Minted)>();
        await minter.MintAsync(
            Params(),
            () => "203.0.113.7",
            () =>
            {
                states.Add((userWritten, mintCalled));
                return true;
            });

        Assert.Equal(2, states.Count); // both gates fired
        Assert.False(states[0].Written); // the first gate ran before the user write
        Assert.True(states[^1].Written); // the final gate ran after the user write
        Assert.False(states[^1].Minted); // and before the mint
        Assert.True(mintCalled); // with both gates true, the mint proceeded
    }
}
