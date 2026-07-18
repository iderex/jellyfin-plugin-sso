using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
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
    public async Task AddCanonicalLink_AdminWithoutPreferenceAccess_Returns403()
    {
        // Pins the EnableUserPreferenceAccess term of AssertCanUpdateUser (#397 folded it from an
        // always-true parameter into the helper): even an administrator is refused without it, so a
        // future edit dropping the term cannot pass silently.
        var harness = ForCaller(isAdmin: true, callerId: Target, enableUserPreferenceAccess: false);

        var result = await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse());

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
    public async Task DeleteCanonicalLink_AuthorizedButInvalidMode_Throws()
    {
        // #369: the DELETE route parses {mode} at the same boundary as the add route, so an unknown mode is
        // rejected there once — fail closed, exactly like AddCanonicalLink — rather than being forwarded raw
        // to the service to throw deep inside TryGetLinks. Pins the previously-untested DELETE invalid-mode path.
        var harness = ForCaller(isAdmin: true, callerId: Target);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            harness.Controller.DeleteCanonicalLink("ldap", "keycloak", Target, "sub-1"));
    }

    [Fact]
    public async Task AddCanonicalLink_MixedCaseMode_RoutesToTheRightFlow()
    {
        // #369: the single boundary parse is case-insensitive and culture-independent, so a mixed-case token
        // routes to the same protocol the lowercase one does — the two former divergent dispatches (one
        // culture-sensitive) can no longer disagree. "SAML" routes to the SAML link path, proven by its
        // clean unknown-provider 400 (SamlLink checks the provider before touching the response).
        var harness = ForCaller(isAdmin: true, callerId: Target);

        var result = await harness.Controller.AddCanonicalLink("SAML", "does-not-exist", Target, new AuthResponse { Data = "irrelevant" });

        Assert.IsType<BadRequestObjectResult>(result);
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
    public async Task DeleteCanonicalLink_RemovingTheUsersLastLink_RevokesTheirActiveTokens()
    {
        // #468: unlinking the user's ONLY canonical link severs their SSO identity entirely (they can no
        // longer SSO in at all), so — matching Unregister's hard-lockdown posture (#440) — their already
        // issued tokens are revoked, scoped strictly to this one user id (null revokes all of theirs).
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c =>
            c.OidConfigs["keycloak"] = new OidConfig
            {
                Enabled = true,
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Target },
            });

        var result = await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "sub-1");

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(Target, null);
    }

    [Fact]
    public async Task DeleteCanonicalLink_LastLinkRevoke_ScopedToTarget_LeavesOtherUsersTokensAlone()
    {
        // The revoke is scoped strictly to the resolved target — no other user's tokens may be swept even
        // when their link lives on the same provider.
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c =>
            c.OidConfigs["keycloak"] = new OidConfig
            {
                Enabled = true,
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Target, ["sub-other"] = Other },
            });

        await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "sub-1");

        await harness.SessionManager.Received(1).RevokeUserTokens(Target, null);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Other, Arg.Any<string?>());
    }

    [Fact]
    public async Task DeleteCanonicalLink_UserKeepsAnotherLink_DoesNotRevokeTokens()
    {
        // #468 availability guard: a user who still holds a link on ANOTHER provider can still SSO in, so
        // unlinking a secondary provider must NOT revoke — that would be a self-inflicted mass-logout of a
        // healthy multi-link user for no security gain.
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c =>
        {
            c.OidConfigs["keycloak"] = new OidConfig
            {
                Enabled = true,
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Target },
            };
            c.SamlConfigs["adfs"] = new SamlConfig
            {
                Enabled = true,
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-1"] = Target },
            };
        });

        var result = await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "sub-1");

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
    }

    [Fact]
    public async Task DeleteCanonicalLink_NoOpOutcomes_DoNotRevokeTokens()
    {
        // Only a real removal (Removed) can trigger a last-link revoke; a NotFound canonical name changes no
        // state, so no tokens are revoked — the revoke is gated on the durable state change, never a miss.
        var harness = ForCaller(isAdmin: true, callerId: Target, configure: c =>
            c.OidConfigs["keycloak"] = new OidConfig { Enabled = true });

        var result = await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "does-not-exist");

        Assert.IsType<NotFoundObjectResult>(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
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
        OidcLoginService.SeedOidStateForTests("state-1", new AuthorizeSession.Ready(
            new AuthorizeSession.Pending(new AuthorizeState { State = "state-1" }, "keycloak", isLinking: false, DateTime.Now, Binding, clientKey: null, providerInformation: null, responseIssuerRequired: false),
            new OidcAuthorizeStateBuilder.OidcAuthorizeState("alice", "sub-1", null, true, false, false, false, new List<string>(), null)));

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
        OidcLoginService.SeedOidStateForTests("state-1", new AuthorizeSession.Ready(
            new AuthorizeSession.Pending(new AuthorizeState { State = "state-1" }, "keycloak", isLinking: false, DateTime.Now, Binding, clientKey: null, providerInformation: null, responseIssuerRequired: false),
            new OidcAuthorizeStateBuilder.OidcAuthorizeState("alice", "sub-1", null, true, false, false, false, new List<string>(), null)));

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
        OidcLoginService.SeedOidStateForTests("state-1", new AuthorizeSession.Ready(
            new AuthorizeSession.Pending(new AuthorizeState { State = "state-1" }, "keycloak", isLinking: false, DateTime.Now, Binding, clientKey: null, providerInformation: null, responseIssuerRequired: false),
            new OidcAuthorizeStateBuilder.OidcAuthorizeState("alice", "sub-1", null, true, false, false, false, new List<string>(), null)));
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

    [Fact]
    public async Task AddCanonicalLink_AuthorizedOverRateLimit_Returns429()
    {
        // #382: the authenticated link write surface is now throttled by the shared gate under its own "link"
        // class. A burst past the configured budget is refused with the same 429 the login path renders.
        var harness = ForCaller(isAdmin: true, callerId: Target, clientIp: IPAddress.Parse("8.8.4.10"), configure: c =>
        {
            c.EnableRateLimit = true;
            c.RateLimitMaxAttempts = 1;
            c.RateLimitWindowSeconds = 60;
        });

        // The first authorized call passes the limiter and spends the single-attempt budget; the unknown
        // provider then rejects with the uniform 400 — but the budget is already spent.
        Assert.IsType<BadRequestObjectResult>(
            await harness.Controller.AddCanonicalLink("oid", "does-not-exist", Target, new AuthResponse { Data = "state-token" }));

        // The second authorized call is over budget and is throttled before the provider is looked up: a 429
        // from LoginOutcome.Throttled via the single mapper (#474), with the machine-readable Retry-After.
        var throttled = Assert.IsType<ContentResult>(
            await harness.Controller.AddCanonicalLink("oid", "does-not-exist", Target, new AuthResponse { Data = "state-token" }));
        Assert.Equal(429, throttled.StatusCode);
        Assert.Equal("Too many login attempts. Please wait a moment and try again.", throttled.Content);

        var retryAfter = harness.Controller.Response.Headers.RetryAfter.ToString();
        Assert.True(
            int.TryParse(retryAfter, out var seconds) && seconds >= 1 && seconds <= 60,
            $"Retry-After must be whole seconds within the 60s window; was '{retryAfter}'.");
    }

    [Fact]
    public async Task DeleteCanonicalLink_AuthorizedOverRateLimit_Returns429()
    {
        // #382: the DELETE arm is throttled too — a name-miss DELETE still runs a full persist under the
        // config lock, so it shares the "link" budget with the add arm.
        var harness = ForCaller(isAdmin: true, callerId: Target, clientIp: IPAddress.Parse("8.8.4.11"), configure: c =>
        {
            c.EnableRateLimit = true;
            c.RateLimitMaxAttempts = 1;
            c.RateLimitWindowSeconds = 60;
        });

        // First call spends the single-attempt budget (unknown provider → 400).
        Assert.IsType<BadRequestObjectResult>(
            await harness.Controller.DeleteCanonicalLink("oid", "does-not-exist", Target, "sub-1"));

        // Second call is over budget and throttled.
        var throttled = Assert.IsType<ContentResult>(
            await harness.Controller.DeleteCanonicalLink("oid", "does-not-exist", Target, "sub-1"));
        Assert.Equal(429, throttled.StatusCode);
    }

    [Fact]
    public async Task AddCanonicalLink_UnauthorizedOverRateLimit_Returns403NotThrottled()
    {
        // The caller-authz guard runs before the limiter (#382 keeps the 403 first), so an unauthorized caller
        // is refused with 403 and never consumes or is judged by the rate-limit budget — even hammering past
        // the configured max of one. This pins the ordering: no 429 can precede the 403 (no rate-limit oracle).
        var harness = ForCaller(isAdmin: false, callerId: Other, clientIp: IPAddress.Parse("8.8.4.12"), configure: c =>
        {
            c.EnableRateLimit = true;
            c.RateLimitMaxAttempts = 1;
            c.RateLimitWindowSeconds = 60;
        });

        for (var i = 0; i < 3; i++)
        {
            var result = await harness.Controller.AddCanonicalLink("oid", "keycloak", Target, new AuthResponse());
            Assert.Equal(403, Assert.IsType<ObjectResult>(result).StatusCode);
        }
    }

    [Fact]
    public async Task DeleteCanonicalLink_AuthorizedUnderRateLimit_NotThrottled()
    {
        // With rate limiting enabled but the budget generous (the default 30/60s), a normal admin unlink is
        // unaffected: it removes the caller's own link and returns Ok, never a 429.
        var harness = ForCaller(isAdmin: true, callerId: Target, clientIp: IPAddress.Parse("8.8.4.13"), configure: c =>
        {
            c.EnableRateLimit = true;
            c.RateLimitMaxAttempts = 30;
            c.RateLimitWindowSeconds = 60;
            c.OidConfigs["keycloak"] = new OidConfig
            {
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Target },
            };
        });

        var result = await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "sub-1");

        Assert.IsType<OkResult>(result);
    }

    // Builds a harness whose mocked IAuthorizationContext resolves the request to the given caller. An
    // admin (or the target user themselves) with preference access passes AssertCanUpdateUser; a
    // non-admin editing another user, or any caller without EnableUserPreferenceAccess, is refused. A
    // dedicated clientIp lets a throttling test isolate its process-static limiter counter (#382).
    private static SsoControllerHarness ForCaller(bool isAdmin, Guid callerId, Action<PluginConfiguration>? configure = null, bool enableUserPreferenceAccess = true, IPAddress? clientIp = null)
    {
        var harness = new SsoControllerHarness(configure, clientIp);

        var user = new User("caller", "SSO-Auth", "Default") { Id = callerId, EnableUserPreferenceAccess = enableUserPreferenceAccess };
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
