using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
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
/// missing data and unknown providers fail-closed; and the delete path removes a caller-owned link,
/// refuses a UID mismatch with 409, and returns 404 for an unknown canonical name. The authorization
/// decision runs through the mocked <see cref="IAuthorizationContext"/>.
/// </summary>
[Collection("SSOController")]
public class SSOControllerLinkTests
{
    private static readonly Guid Target = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static readonly Guid Other = Guid.Parse("66666666-6666-6666-6666-666666666666");

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
        return harness;
    }
}
