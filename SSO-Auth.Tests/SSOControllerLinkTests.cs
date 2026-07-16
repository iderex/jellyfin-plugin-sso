using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the canonical-link endpoints via <see cref="SsoControllerHarness"/>. They cover
/// the authorization guard (a non-admin editing another user's links is refused with 403) and, once the
/// guard passes, the mode dispatch and its outcomes: an invalid mode is rejected; the add path rejects
/// missing data and unknown providers fail-closed and, given a redeemable OID state or a validly signed
/// SAML response, creates the link (204); and the delete path removes a caller-owned link, refuses a UID
/// mismatch with 409, and returns 404 for an unknown canonical name. The per-user link queries return the
/// caller's links once authorized. The authorization decision runs through the mocked
/// <see cref="IAuthorizationContext"/>.
/// </summary>
[Collection("SSOController")]
public class SSOControllerLinkTests
{
    private static readonly Guid Target = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static readonly Guid Other = Guid.Parse("66666666-6666-6666-6666-666666666666");

    // The browser-binding id (#326) recorded on the seeded OID states; ForCaller presents the matching
    // binding cookie so the OID link redeems (the SAML paths ignore it). Without the match the redeem
    // would be refused as a wrong-browser callback.
    private const string Binding = "link-browser-binding";

    [Fact]
    public async Task AddCanonicalLink_NonAdminEditingAnotherUser_Returns403()
    {
        var harness = ForCaller(isAdmin: false, callerId: Other);

        var result = await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse());

        Assert.Equal(403, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task DeleteCanonicalLink_NonAdminEditingAnotherUser_Returns403()
    {
        var harness = ForCaller(isAdmin: false, callerId: Other);

        var result = await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "sub-1");

        Assert.Equal(403, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task GetOidLinksByUser_NonAdminQueryingAnotherUser_Returns403()
    {
        var harness = ForCaller(isAdmin: false, callerId: Other);

        var result = await harness.Controller.GetOidLinksByUser(Target);

        Assert.Equal(403, Assert.IsType<ObjectResult>(result.Result).StatusCode);
    }

    [Fact]
    public async Task AddCanonicalLink_AuthorizedButInvalidMode_Throws()
    {
        var harness = ForCaller(isAdmin: true, callerId: Target);

        // The guard passes (admin), so the mode dispatch runs and rejects an unknown mode fail-closed.
        await Assert.ThrowsAsync<ArgumentException>(() =>
            harness.Controller.AddCanonicalLink("ldap", "keycloak", Target, new AuthResponse()));
    }

    [Fact]
    public async Task DeleteCanonicalLink_AuthorizedButUnknownCanonicalName_ReturnsNotFound()
    {
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c =>
            c.OidConfigs["keycloak"] = new OidConfig());

        var result = await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "does-not-exist");

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task DeleteCanonicalLink_AuthorizedButUnknownProvider_ReturnsBadRequest()
    {
        // Delete does no provider pre-check (unlike the link endpoints' #343 disabled-provider guard),
        // so an unknown provider is the live path through the service's UnknownProvider result. It must
        // map to the same BadRequest(NoMatchingProviderMessage) the old KeyNotFoundException catch did.
        var harness = ForCaller(isAdmin: true, callerId: Target);

        var result = await harness.Controller.DeleteCanonicalLink("oid", "does-not-exist", Target, "sub-1");

        // Assert the body, not just the type: the UnknownProvider result must keep the exact message the
        // old KeyNotFoundException catch returned, so the mapping is not silently changed.
        Assert.Equal("No matching provider found", Assert.IsType<BadRequestObjectResult>(result).Value);
    }

    [Fact]
    public async Task GetSamlLinksByUser_NonAdminQueryingAnotherUser_Returns403()
    {
        var harness = ForCaller(isAdmin: false, callerId: Other);

        var result = await harness.Controller.GetSamlLinksByUser(Target);

        Assert.Equal(403, Assert.IsType<ObjectResult>(result.Result).StatusCode);
    }

    [Fact]
    public async Task AddCanonicalLink_OidMissingData_ReturnsBadRequest()
    {
        var harness = ForCaller(isAdmin: true, callerId: Target);

        // The OID link path needs the redeemable state token in the body; an empty body is a clean 400.
        var result = await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse());

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task AddCanonicalLink_OidUnknownProvider_ReturnsBadRequest()
    {
        var harness = ForCaller(isAdmin: true, callerId: Target);

        // Data is present, but no such provider is configured, so the lookup fails closed.
        var result = await harness.Controller.AddCanonicalLink("oid", "does-not-exist", Target, new AuthResponse { Data = "state-token" });

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task AddCanonicalLink_SamlUnknownProvider_ReturnsBadRequest()
    {
        var harness = ForCaller(isAdmin: true, callerId: Target);

        // SamlLink checks the provider before touching the response, so an unknown provider is a clean 400.
        var result = await harness.Controller.AddCanonicalLink("saml", "does-not-exist", Target, new AuthResponse { Data = "irrelevant" });

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task DeleteCanonicalLink_AuthorizedOwnLink_RemovesItAndReturnsOk()
    {
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c =>
            c.OidConfigs["keycloak"] = new OidConfig
            {
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Target },
            });

        var result = await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "sub-1");

        Assert.IsType<OkResult>(result);
        var links = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks);
        Assert.False(links.ContainsKey("sub-1"));
    }

    [Fact]
    public async Task DeleteCanonicalLink_AuthorizedButUidMismatch_Returns409()
    {
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c =>
            c.OidConfigs["keycloak"] = new OidConfig
            {
                // The link points at a different Jellyfin user, so the delete must refuse rather than remove.
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Other },
            });

        var result = await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "sub-1");

        Assert.Equal(409, Assert.IsType<ObjectResult>(result).StatusCode);
        // The mismatched link is left untouched.
        var links = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks);
        Assert.True(links.ContainsKey("sub-1"));
    }

    [Fact]
    public async Task AddCanonicalLink_AuthorizedOidWithRedeemableState_LinksAndReturnsNoContent()
    {
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c => c.OidConfigs["keycloak"] = new OidConfig { Enabled = true });
        // The OID link path redeems an authorize state the redirect leg validated; seed a redeemable one.
        SSOController.SeedOidStateForTests("state-1", new TimedAuthorizeState(new AuthorizeState { State = "state-1" }, DateTime.Now)
        {
            Provider = "keycloak",
            Valid = true,
            Subject = "sub-1",
            BindingId = Binding,
        });

        var result = await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse { Data = "state-1" });

        Assert.IsType<NoContentResult>(result);
        var links = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks);
        Assert.Equal(Target, links["sub-1"]);
    }

    [Fact]
    public async Task AddCanonicalLink_OidDisabledProvider_RejectsWithoutConsumingTheState()
    {
        // #343: a state validated shortly before an administrator disables the provider must not stay
        // usable to create a link, and the disabled provider must not burn the state either — the
        // rejection mirrors OidAuth's short-circuit order and shares the unknown-provider response, so
        // the two cases cannot be probed apart.
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c => c.OidConfigs["keycloak"] = new OidConfig { Enabled = false });
        SSOController.SeedOidStateForTests("state-1", new TimedAuthorizeState(new AuthorizeState { State = "state-1" }, DateTime.Now)
        {
            Provider = "keycloak",
            Valid = true,
            Subject = "sub-1",
            BindingId = Binding,
        });

        var rejected = await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse { Data = "state-1" });

        // Same body as the unknown-provider rejection, so the two cases cannot be probed apart.
        Assert.Equal("No matching provider found", Assert.IsType<BadRequestObjectResult>(rejected).Value);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks.ContainsKey("sub-1")));

        // The state survived the rejection: re-enabling the provider lets the same token link.
        SSOPlugin.Instance.MutateConfiguration(c => c.OidConfigs["keycloak"].Enabled = true);
        var accepted = await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse { Data = "state-1" });
        Assert.IsType<NoContentResult>(accepted);
    }

    [Fact]
    public async Task AddCanonicalLink_OidMismatchedBindingCookie_RejectsWithoutConsumingTheState()
    {
        // #326: the OID link redeem is browser-bound like the login path. A callback presenting a
        // different browser's binding cookie is refused, and — the binding check preceding the atomic
        // remove — the state is NOT consumed, so the browser that started the flow can still link.
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c => c.OidConfigs["keycloak"] = new OidConfig { Enabled = true });
        SSOController.SeedOidStateForTests("state-1", new TimedAuthorizeState(new AuthorizeState { State = "state-1" }, DateTime.Now)
        {
            Provider = "keycloak",
            Valid = true,
            Subject = "sub-1",
            BindingId = Binding,
        });
        // A wrong-browser callback: overwrite the matching cookie ForCaller set with a different id.
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}=other-browser";

        var rejected = await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse { Data = "state-1" });

        Assert.Equal("Invalid or expired state", Assert.IsType<ContentResult>(rejected).Content);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks.ContainsKey("sub-1")));

        // The state was not burned: the originating browser (matching cookie) still completes the link.
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={Binding}";
        var accepted = await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse { Data = "state-1" });
        Assert.IsType<NoContentResult>(accepted);
    }

    [Fact]
    public async Task AddCanonicalLink_SamlDisabledProvider_RejectsWithoutConsumingTheAssertion()
    {
        // #343, SAML twin: the disabled check runs before the replay cache, so the assertion's
        // one-time-use ID is not burned by a rejected attempt against a disabled provider.
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = false,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
        });

        var rejected = await harness.Controller.AddCanonicalLink("saml", "adfs", Target, new AuthResponse { Data = fixture.EncodeResponse() });

        // Same body as the unknown-provider rejection, so the two cases cannot be probed apart.
        Assert.Equal("No matching provider found", Assert.IsType<BadRequestObjectResult>(rejected).Value);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].CanonicalLinks.ContainsKey("alice")));

        // The assertion survived the rejection: re-enabling the provider lets the same response link.
        SSOPlugin.Instance.MutateConfiguration(c => c.SamlConfigs["adfs"].Enabled = true);
        var accepted = await harness.Controller.AddCanonicalLink("saml", "adfs", Target, new AuthResponse { Data = fixture.EncodeResponse() });
        Assert.IsType<NoContentResult>(accepted);
    }

    [Fact]
    public async Task AddCanonicalLink_AuthorizedSamlWithSignedResponse_LinksAndReturnsNoContent()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true, // audience validation is covered separately
        });

        var result = await harness.Controller.AddCanonicalLink("saml", "adfs", Target, new AuthResponse { Data = fixture.EncodeResponse() });

        Assert.IsType<NoContentResult>(result);
        var links = SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].CanonicalLinks);
        Assert.Equal(Target, links["alice"]);
    }

    [Fact]
    public async Task GetOidLinksByUser_AuthorizedAdmin_ReturnsTheUsersLinks()
    {
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c =>
            c.OidConfigs["keycloak"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Target } });

        var result = await harness.Controller.GetOidLinksByUser(Target);

        var map = Assert.IsType<SerializableDictionary<string, IEnumerable<string>>>(result.Value);
        Assert.Contains("sub-1", map["keycloak"]);
    }

    [Fact]
    public async Task GetSamlLinksByUser_AuthorizedAdmin_ReturnsTheUsersLinks()
    {
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c =>
            c.SamlConfigs["adfs"] = new SamlConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-1"] = Target } });

        var result = await harness.Controller.GetSamlLinksByUser(Target);

        var map = Assert.IsType<SerializableDictionary<string, IEnumerable<string>>>(result.Value);
        Assert.Contains("nameid-1", map["adfs"]);
    }

    // Builds a harness whose mocked IAuthorizationContext resolves the request to the given caller. An
    // admin (or the target user themselves) passes AssertCanUpdateUser; a non-admin editing another user
    // is refused.
    private static SsoControllerHarness ForCaller(bool isAdmin, Guid callerId, Action<PluginConfiguration>? configure = null)
    {
        var harness = new SsoControllerHarness(configure);

        var user = new User("caller", "SSO-Auth", "Default") { Id = callerId, EnableUserPreferenceAccess = true };
        user.SetPermission(PermissionKind.IsAdministrator, isAdmin);

        // AuthorizationInfo.UserId is derived from User.Id, so setting the user fixes the caller identity.
        var authInfo = new AuthorizationInfo { User = user };
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>()).Returns(Task.FromResult(authInfo));

        // Present the browser-binding cookie (#326) so the OID link redeem sees the id the seeded state
        // records; the Cookie header is how a DefaultHttpContext exposes Request.Cookies. Harmless for the
        // SAML and non-redeem paths, which never read it.
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={Binding}";
        return harness;
    }
}
