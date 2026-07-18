using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
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

    private static User UserNamed(string name, Guid id) => new User(name, "SSO-Auth", "Default") { Id = id };

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
        return (new LoginCompletionService(canonicalLinks, minter, new CapturingLogger()), cfg, users, sessions);
    }

    private static AuthResponse Response() =>
        new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" };

    private static VerifiedIdentity OidcIdentity(string provider, string subject, string username) =>
        VerifiedIdentity.FromOidcRedemption(provider, new OidcAuthorizeStateBuilder.OidcAuthorizeState(
            Username: username,
            Subject: subject,
            Issuer: null,
            EmailVerified: null,
            Valid: true,
            Admin: false,
            EnableLiveTv: false,
            EnableLiveTvManagement: false,
            Folders: new List<string>(),
            AvatarUrl: null));

    private static VerifiedIdentity SamlIdentity(string provider, string nameId) =>
        VerifiedIdentity.FromValidatedSaml(provider, nameId, new SamlAuthorizeStateBuilder.SamlAuthorizeState(
            Admin: false,
            EnableLiveTv: false,
            EnableLiveTvManagement: false,
            Folders: new List<string>()));

    [Fact]
    public async Task CompleteAsync_OidcIdentity_ResolvesTheAccountAndMintsWithTheSuppliedRemoteEndPoint()
    {
        var config = new OidConfig { Enabled = true };
        var (service, _, users, sessions) = Build(c => c.OidConfigs["kc"] = config);
        var created = UserNamed("alice", Created);
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
    public async Task CompleteAsync_SamlIdentity_CompletesIdenticallyToTheOidcPath()
    {
        // The keystone's whole point (#473): a SAML VerifiedIdentity funnels into the same tail — resolve the
        // account, mint the session, carry the supplied remote endpoint — indistinguishable from OpenID.
        var config = new SamlConfig { Enabled = true };
        var (service, _, users, sessions) = Build(c => c.SamlConfigs["okta"] = config);
        var created = UserNamed("bob", Created);
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
    public async Task CompleteAsync_AccountLinkRefused_ReturnsRejectedWithoutMinting()
    {
        // Fail closed, moved verbatim: a login whose name matches a pre-existing unlinked account with
        // adoption off is refused (#95). ResolveOrCreateAsync throws AccountLinkForbiddenException, which the
        // tail must catch and turn into a Rejected 403 — and crucially NO session may be minted. The catch is
        // moved as a whole unit, so a refusal cannot fall through to the mint.
        var config = new OidConfig { Enabled = true, AllowExistingAccountLink = false };
        var (service, _, users, sessions) = Build(c => c.OidConfigs["kc"] = config);
        users.GetUserByName("alice").Returns(UserNamed("alice", Existing));

        var result = await service.CompleteAsync(
            OidcIdentity("kc", "sub-1", "alice"), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(403, content.StatusCode);
        await sessions.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }
}
