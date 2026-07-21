// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Dto;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Direct tests of <see cref="LoginCompletionService"/> — the shared login-completion tail extracted from
/// the controller (#160, #318 step 11). They pin that both protocols funnel their <see cref="VerifiedIdentity"/>
/// into the identical mint (an OpenID and a SAML identity complete the same way, carrying the
/// controller-supplied remote endpoint through), and that a refusal from the account-linking workflow still
/// surfaces as a <c>Rejected</c> 403 with no session minted — the fail-closed behavior that must survive the
/// move verbatim. The controller suites keep proving the wire behavior end to end; these pin the tail in
/// isolation.
/// </summary>
public class LoginCompletionServiceTests
{
    private static readonly Guid Created = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid Existing = Guid.Parse("11111111-1111-1111-1111-111111111111");


    private static (LoginCompletionService Service, PluginConfiguration Config, IUserManager Users, ISessionManager Sessions) Build(Action<PluginConfiguration> seed)
    {
        var cfg = new PluginConfiguration();
        seed(cfg);
        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var canonicalLinks = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());
        // A real AvatarService (its deps stubbed): a null AvatarUrl early-returns, so no network is reached.
        var avatar = new AvatarService(users, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), new CapturingLogger(), "test-agent");
        var minter = new SessionMinter(users, avatar, sessions, new CapturingLogger());
        var ssoOnly = new SsoOnlyLoginService(users, store, new CapturingLogger());
        return (new LoginCompletionService(canonicalLinks, minter, ssoOnly, store, new CapturingLogger()), cfg, users, sessions);
    }

    private static AuthResponse Response() =>
        new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" };

    private static VerifiedIdentity OidcIdentity(string provider, string subject, string username, int? maxParentalRatingScore = null) =>
        TestIdentities.Oidc(provider, new OidcAuthorizeStateBuilder.OidcAuthorizeState(
            Username: username,
            Subject: subject,
            Issuer: null,
            EmailVerified: null,
            Valid: true,
            Admin: false,
            EnableLiveTv: false,
            EnableLiveTvManagement: false,
            Folders: new List<string>(),
            AvatarUrl: null,
            MaxParentalRatingScore: maxParentalRatingScore));

    private static VerifiedIdentity SamlIdentity(string provider, string nameId) =>
        TestIdentities.Saml(provider, nameId, new SamlAuthorizeStateBuilder.SamlAuthorizeState(
            Admin: false,
            EnableLiveTv: false,
            EnableLiveTvManagement: false,
            Folders: new List<string>()));

    [Fact]
    public async Task CompleteAsync_OidcIdentity_ResolvesTheAccountAndMintsWithTheSuppliedRemoteEndPoint()
    {
        var config = new OidConfig { Enabled = true };
        var (service, _, users, sessions) = Build(c => c.OidConfigs["kc"] = config);
        var created = TestUsers.Named("alice", Created);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Created).Returns(created);
        AuthenticationRequest? captured = null;
        sessions.AuthenticateDirect(Arg.Do<AuthenticationRequest>(r => captured = r)).Returns(new AuthenticationResult());

        var result = await service.CompleteAsync(
            OidcIdentity("kc", "sub-1", "alice"), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.IsType<OkObjectResult>(result);
        await sessions.Received(1).AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        Assert.NotNull(captured);
        Assert.Equal(Created, captured!.UserId);
        Assert.Equal("203.0.113.9", captured.RemoteEndPoint);
    }

    [Fact]
    public async Task CompleteAsync_SingleLogoutOff_DoesNotCaptureEvenWithALogoutContext()
    {
        // The capture is gated on EnableSingleLogout (#727): off (the default), a login stores nothing, even
        // when the OpenID path supplies the id_token/sid.
        var config = new OidConfig { Enabled = true };
        var (service, cfg, users, sessions) = Build(c => c.OidConfigs["kc"] = config); // EnableSingleLogout defaults off
        var created = TestUsers.Named("alice", Created);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Created).Returns(created);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await service.CompleteAsync(
            OidcIdentity("kc", "sub-1", "alice"), Response(), config, AdoptionGate.None, () => "203.0.113.9",
            new LogoutContext("sid-1", "raw.id.token"));

        Assert.Empty(cfg.LogoutSessions);
    }

    [Fact]
    public async Task CompleteAsync_SingleLogoutOn_NoSessionId_SkipsCaptureWithoutFailingTheLogin()
    {
        // Fail-safe: with the feature on but the mint returning no session id, the capture is skipped and the
        // login still succeeds — a capture problem must never turn a good login into a failure.
        var config = new OidConfig { Enabled = true };
        var (service, cfg, users, sessions) = Build(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = config;
        });
        var created = TestUsers.Named("alice", Created);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Created).Returns(created);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult()); // SessionInfo == null

        var result = await service.CompleteAsync(
            OidcIdentity("kc", "sub-1", "alice"), Response(), config, AdoptionGate.None, () => "203.0.113.9",
            new LogoutContext("sid-1", "raw.id.token"));

        Assert.IsType<OkObjectResult>(result);
        Assert.Empty(cfg.LogoutSessions);
    }

    [Fact]
    public async Task CompleteAsync_SingleLogoutOn_CapturesTheSessionStateKeyedByTheMintedSession()
    {
        // The end-to-end capture: with the feature on and a real minted session, the login persists the
        // logout state — the id_token, subject, session index, and user — keyed by the minted session id.
        var config = new OidConfig { Enabled = true };
        var (service, cfg, users, sessions) = Build(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = config;
        });
        var created = TestUsers.Named("alice", Created);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Created).Returns(created);
        var session = new SessionInfoDto { Id = "session-key-1" };
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>())
            .Returns(new AuthenticationResult { SessionInfo = session });

        await service.CompleteAsync(
            OidcIdentity("kc", "sub-1", "alice"), Response(), config, AdoptionGate.None, () => "203.0.113.9",
            new LogoutContext("sid-1", "raw.id.token", "https://idp.example/logout"));

        Assert.True(cfg.LogoutSessions.ContainsKey("session-key-1"));
        var entry = cfg.LogoutSessions["session-key-1"];
        Assert.Equal("raw.id.token", entry.IdToken);
        Assert.Equal("sub-1", entry.Subject);
        Assert.Equal("sid-1", entry.SessionIndex);
        Assert.Equal("kc", entry.Provider);
        Assert.Equal("https://idp.example/logout", entry.EndSessionEndpoint);
        Assert.Equal(Created, entry.UserId);
    }

    [Fact]
    public async Task CompleteAsync_ThreadsTheParentalRatingCeilingFromTheIdentityOntoTheMintedUser()
    {
        // #736 end-to-end through the whole keystone thread (VerifiedIdentity -> SessionParameters ->
        // SessionMinter): a resolved ceiling on the identity lands on the user's MaxParentalRatingScore. Guards
        // the middle of the threading — every hop is optional/defaulted, so a dropped copy line would compile
        // and pass the per-unit tests while silently failing to reach the mint; this fails if it does.
        var config = new OidConfig { Enabled = true, EnableAuthorization = true };
        var (service, _, users, sessions) = Build(c => c.OidConfigs["kc"] = config);
        var created = TestUsers.Named("alice", Created);
        created.MaxParentalRatingScore = 100; // a looser existing value the resolved ceiling must overwrite
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Created).Returns(created);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        var result = await service.CompleteAsync(
            OidcIdentity("kc", "sub-1", "alice", maxParentalRatingScore: 3), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(3, created.MaxParentalRatingScore);
    }

    [Fact]
    public async Task CompleteAsync_SamlIdentity_CompletesIdenticallyToTheOidcPath()
    {
        // The keystone's whole point (#473): a SAML VerifiedIdentity funnels into the same tail — resolve the
        // account, mint the session, carry the supplied remote endpoint — indistinguishable from OpenID.
        var config = new SamlConfig { Enabled = true };
        var (service, _, users, sessions) = Build(c => c.SamlConfigs["okta"] = config);
        var created = TestUsers.Named("bob", Created);
        users.GetUserByName("bob").Returns((User?)null);
        users.CreateUserAsync("bob").Returns(created);
        users.GetUserById(Created).Returns(created);
        AuthenticationRequest? captured = null;
        sessions.AuthenticateDirect(Arg.Do<AuthenticationRequest>(r => captured = r)).Returns(new AuthenticationResult());

        var result = await service.CompleteAsync(
            SamlIdentity("okta", "bob"), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.IsType<OkObjectResult>(result);
        await sessions.Received(1).AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        Assert.NotNull(captured);
        Assert.Equal(Created, captured!.UserId);
        Assert.Equal("203.0.113.9", captured.RemoteEndPoint);
    }

    [Fact]
    public async Task CompleteAsync_SsoOnly_BreakGlassAdmin_RenamedOnIdp_KeepsPasswordDoorAndAdmin()
    {
        // Findings A + H1 end to end: SSO-only mode is on and the login RESOLVES (by subject link) to the
        // break-glass admin "root", but the IdP now supplies a DIFFERENT username ("root-renamed"). The
        // break-glass decision must be judged on the RESOLVED account, so root's password door is NOT stripped
        // (its provider stays the password provider even though the config's DefaultProvider is the SSO
        // provider) and its own SSO login — carrying no admin claim — does NOT demote it. Either failure is a
        // whole-org lockout / recovery-defeat once the IdP is down.
        var config = new OidConfig
        {
            Enabled = true,
            EnableAuthorization = true, // so the mint would apply the (non-)admin grant if not exempt
            DefaultProvider = SsoAuthenticationProviders.SsoProviderId, // the common operator setup
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-root"] = Existing },
        };
        var (service, cfg, users, sessions) = Build(c =>
        {
            c.OidConfigs["kc"] = config;
            c.DisablePasswordLogin = true;
            c.BreakGlassAdminUsername = "root";
        });
        var root = TestUsers.Named("root", Existing);
        root.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        root.SetPermission(Jellyfin.Database.Implementations.Enums.PermissionKind.IsAdministrator, true);
        users.GetUserById(Existing).Returns(root);
        users.GetUserByName("root-renamed").Returns((User?)null);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        var result = await service.CompleteAsync(
            OidcIdentity("kc", "sub-root", "root-renamed"), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.IsType<OkObjectResult>(result);
        // The password door survives, and the recovery admin is not demoted.
        Assert.Equal(SsoAuthenticationProviders.DefaultPasswordProviderId, root.AuthenticationProviderId);
        Assert.True(root.HasPermission(Jellyfin.Database.Implementations.Enums.PermissionKind.IsAdministrator));
        // The break-glass admin is never tracked as a repointed account.
        Assert.DoesNotContain(Existing, cfg.SsoOnlyRepointedUserIds);
    }

    [Fact]
    public async Task CompleteAsync_SsoOnly_NonExemptAccount_IsRepointedAndTracked()
    {
        // Finding B end to end: an account onboarded after enable that logs in via SSO while the mode is on is
        // forced onto the SSO provider AND recorded in the tracking set, so the reversible off-switch can
        // restore it. Without the login-path tracking this account would escape the off-switch entirely.
        var config = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-alice"] = Existing },
        };
        var (service, cfg, users, sessions) = Build(c =>
        {
            c.OidConfigs["kc"] = config;
            c.DisablePasswordLogin = true;
            c.BreakGlassAdminUsername = "root";
        });
        var alice = TestUsers.Named("alice", Existing);
        alice.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId; // still had a password door
        users.GetUserById(Existing).Returns(alice);
        users.GetUserByName("alice").Returns(alice);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        var result = await service.CompleteAsync(
            OidcIdentity("kc", "sub-alice", "alice"), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(SsoAuthenticationProviders.SsoProviderId, alice.AuthenticationProviderId); // repointed off the password door
        Assert.Contains(Existing, cfg.SsoOnlyRepointedUserIds); // and tracked so DisableAsync can restore it
    }

    [Fact]
    public async Task CompleteAsync_AccountLinkRefused_ReturnsRejectedWithoutMinting()
    {
        // Fail closed, moved verbatim: a login whose name matches a pre-existing unlinked account with
        // adoption off is refused (#95). ResolveOrCreateAsync throws AccountLinkForbiddenException, which the
        // tail must catch and turn into a Rejected 403 — and crucially NO session may be minted. The catch is
        // moved as a whole unit, so a refusal cannot fall through to the mint.
        var config = new OidConfig { Enabled = true, AllowExistingAccountLink = false };
        var (service, _, users, sessions) = Build(c => c.OidConfigs["kc"] = config);
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));

        var result = await service.CompleteAsync(
            OidcIdentity("kc", "sub-1", "alice"), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(403, content.StatusCode);
        await sessions.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task CompleteAsync_ProvisionNewUsersDisabled_UnknownIdentity_RefusesAwaitingApprovalWithoutMinting()
    {
        // #737: with ProvisionNewUsersDisabled on, an unknown identity's first login creates the account
        // disabled (no permissions) and the login is refused with an awaiting-approval 403 — NO session is
        // minted. This is the core fail-closed onboarding control.
        var config = new OidConfig { Enabled = true, ProvisionNewUsersDisabled = true };
        var (service, _, users, sessions) = Build(c => c.OidConfigs["kc"] = config);
        var created = TestUsers.Named("alice", Created);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Created).Returns(created);

        var result = await service.CompleteAsync(
            OidcIdentity("kc", "sub-1", "alice"), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(403, content.StatusCode);
        Assert.Contains("awaiting administrator approval", content.Content, StringComparison.OrdinalIgnoreCase);
        Assert.True(created.HasPermission(Jellyfin.Database.Implementations.Enums.PermissionKind.IsDisabled)); // created inert
        await sessions.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>()); // and never a session
    }

    [Fact]
    public async Task CompleteAsync_ProvisionNewUsersDisabled_ExistingLinkedAdmin_IsNeverDisabledAndMints()
    {
        // The invariant #737 must not regress: the policy disables only a BRAND-NEW account. An existing,
        // enabled admin that resolves by its subject link logs in normally — it is never disabled, no new
        // account is created, and a session is minted (mirrors the break-glass "never demote an existing
        // admin" posture).
        var config = new OidConfig
        {
            Enabled = true,
            ProvisionNewUsersDisabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        };
        var (service, _, users, sessions) = Build(c => c.OidConfigs["kc"] = config);
        var existing = TestUsers.Named("alice", Existing);
        existing.SetPermission(Jellyfin.Database.Implementations.Enums.PermissionKind.IsAdministrator, true);
        users.GetUserById(Existing).Returns(existing);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        var result = await service.CompleteAsync(
            OidcIdentity("kc", "sub-1", "alice"), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.IsType<OkObjectResult>(result);
        Assert.False(existing.HasPermission(Jellyfin.Database.Implementations.Enums.PermissionKind.IsDisabled)); // never disabled
        await sessions.Received(1).AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task CompleteAsync_ProvisionNewUsersDisabled_SecondLoginOfPendingAccount_RefusesAgainWithoutMinting()
    {
        // A still-disabled linked account (provisioned pending on an earlier login) logs in again: the resolved
        // account is disabled, so the uniform gate refuses with awaiting-approval again — never a session, and
        // the account is never re-enabled by the login path.
        var config = new OidConfig
        {
            Enabled = true,
            ProvisionNewUsersDisabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        };
        var (service, _, users, sessions) = Build(c => c.OidConfigs["kc"] = config);
        var pending = TestUsers.Named("alice", Existing);
        pending.SetPermission(Jellyfin.Database.Implementations.Enums.PermissionKind.IsDisabled, true);
        users.GetUserById(Existing).Returns(pending);

        var result = await service.CompleteAsync(
            OidcIdentity("kc", "sub-1", "alice"), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(403, content.StatusCode);
        await sessions.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }
}
