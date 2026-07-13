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
/// guard passes, the mode dispatch: an invalid mode is rejected and a delete of an unknown canonical
/// name is a 404. The authorization decision runs through the mocked <see cref="IAuthorizationContext"/>.
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
