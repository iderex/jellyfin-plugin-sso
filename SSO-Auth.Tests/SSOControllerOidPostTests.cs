using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the OpenID redirect callback's token-exchange path (<c>OidPost</c>) via
/// <see cref="SsoControllerHarness"/> and <see cref="OidcTokenFixture"/>, which serves discovery, a JWKS,
/// and a token endpoint returning a real signed id_token, so the actual code exchange and id_token
/// validation run. A valid callback renders the auth page; an authorization-response issuer that does not
/// match the id_token issuer is refused (RFC 9207 mix-up check, #125). The guard branches (unknown
/// provider, missing/invalid/expired state, disabled, rate-limit) are covered in
/// <see cref="SSOControllerEndpointTests"/> / <see cref="SSOControllerAdminTests"/>.
///
/// Two of the tests characterize the callback end-to-end against the OAuth 2.0 Security BCP update
/// (draft-ietf-oauth-security-topics-update, rev -03 dated 2026-07-06) threat classes that apply to
/// this RP (#176):
/// Cross-toolkit OAuth Account Takeover (COAT) — a state minted in one named provider's context cannot
/// complete against another configured provider's callback — and cross-user session fixation — a state
/// token observed by a party in a different browser cannot complete the flow. The store-level mechanisms
/// these rely on are pinned in <see cref="OidcStateStoreTests"/> (provider-scoped peek/redeem, the
/// browser-binding gate, and the one-time atomic claim); the mint-path one-time-consume is pinned in
/// <see cref="SSOControllerOidAuthTests"/>.
/// </summary>
[Collection("SSOController")]
public class SSOControllerOidPostTests
{
    private const string Authority = "https://idp-oidpost.example.com";

    // The browser-binding id (#326) the challenge would have recorded on the state and handed to the
    // browser as a cookie; the callback must present the same value or the state is refused.
    private const string Binding = "oidpost-browser-binding";

    [Fact]
    public async Task OidPost_ValidCallback_RendersTheAuthPage()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1");

        var result = await harness.Controller.OidPost("kc", "state-1");

        // Reaching the intermediate HTML auth page (text/html) rather than a plain-text error proves the
        // token exchange, id_token signature validation, and sub resolution all succeeded.
        var page = Assert.IsType<ContentResult>(result);
        Assert.Equal("text/html", page.ContentType);
        Assert.False(string.IsNullOrEmpty(page.Content));
    }

    [Fact]
    public async Task OidPost_MissingBindingCookie_RejectsAsInvalidState()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // #326: the state was started in another browser (no matching binding cookie is presented), so the
        // callback is refused before any token exchange — the forced-login / session-fixation defense. The
        // body is the uniform invalid-state message, so a wrong-browser hit is indistinguishable from an
        // expiry.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", bindingCookie: null);

        var result = await harness.Controller.OidPost("kc", "state-1");

        Assert.Equal("Invalid or expired state", Assert.IsType<BadRequestObjectResult>(result).Value);
    }

    [Fact]
    public async Task OidPost_StateMintedForAnotherProvider_RejectedOnThisProvidersCallback()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // COAT (OAuth 2.0 Security BCP update, draft-ietf-oauth-security-topics-update, #176): this
        // plugin is a multi-provider OAuth client (OidConfigs is a dict of named providers), so a response minted in
        // one provider's context must not complete against another's callback. The state is keyed by its
        // token, so the lookup FINDS it under "kc2" — but PeekCurrent rejects it because the route
        // provider does not match the provider recorded on the state, before any token exchange. Both
        // providers are enabled, so this isolates the provider-context binding from the unknown/disabled
        // guard.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", secondProvider: "kc2");

        var crossContext = await harness.Controller.OidPost("kc2", "state-1");
        Assert.Equal("Invalid or expired state", Assert.IsType<BadRequestObjectResult>(crossContext).Value);

        // Positive control: PeekCurrent does not consume, so the same state still completes on the
        // provider it WAS minted for — proving the rejection above is the provider-context binding, not an
        // unrelated failure of the shared fixture.
        var sameContext = await harness.Controller.OidPost("kc", "state-1");
        Assert.Equal("text/html", Assert.IsType<ContentResult>(sameContext).ContentType);
    }

    [Fact]
    public async Task OidPost_StateTokenPresentedFromADifferentBrowser_RejectedAsInvalidState()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // Cross-user session fixation (same BCP update, #176): an attacker who observes/fixates the state
        // token still cannot complete the flow from their own browser. The callback requires the
        // browser-binding cookie the challenge recorded (#326); the attacker's browser carries a DIFFERENT
        // value, not the victim's. A present-but-mismatched cookie (not merely an absent one, covered by
        // OidPost_MissingBindingCookie) is refused, proving the binding check requires equality, not mere
        // presence. Once the victim completes, the one-time atomic claim prevents replay/handoff (pinned
        // end-to-end by OidAuth_ValidState_ProvisionsAccountReturnsOk_AndIsSingleUse).
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", bindingCookie: "attacker-other-browser-binding");

        var result = await harness.Controller.OidPost("kc", "state-1");

        Assert.Equal("Invalid or expired state", Assert.IsType<BadRequestObjectResult>(result).Value);
    }

    [Fact]
    public async Task OidPost_ResponseIssuerMismatch_Returns400()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // RFC 9207 (#125): the authorization-response `iss` names a different issuer than the id_token's,
        // which is an authorization-server mix-up and must be rejected even though the token itself is valid.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1&iss=https://attacker.example.com");

        var result = await harness.Controller.OidPost("kc", "state-1");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task OidPost_TokenExchangeFails_Returns400()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // The authorization-code exchange fails at the token endpoint, so ProcessResponseAsync errors and
        // the callback is refused rather than minting a login.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", tokenEndpointFails: true);

        var result = await harness.Controller.OidPost("kc", "state-1");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task OidPost_IdTokenWithoutSub_Returns401()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // Fail closed (#155): a validated id_token carrying no `sub` claim resolves no stable subject to
        // key the account link on, so the login is refused.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", idToken: fixture.IdToken(subject: null, username: "alice"));

        var result = await harness.Controller.OidPost("kc", "state-1");

        Assert.Equal(401, Assert.IsType<ContentResult>(result).StatusCode);
    }

    // Builds a harness whose HTTP responder serves the fixture's discovery/JWKS/token endpoints, seeds the
    // matching authorize state, and sets the callback request path and query. The token endpoint returns
    // <paramref name="idToken"/> (a valid signed token by default), or a 400 when
    // <paramref name="tokenEndpointFails"/> is set.
    private static SsoControllerHarness ArrangeCallback(
        OidcTokenFixture fixture,
        string query,
        string? idToken = null,
        bool tokenEndpointFails = false,
        string? bindingCookie = Binding,
        string? secondProvider = null)
    {
        idToken ??= fixture.IdToken(subject: "sub-1", username: "alice");

        OidConfig NewProvider() => new()
        {
            Enabled = true,
            OidEndpoint = Authority,
            OidClientId = "jf",
            OidScopes = Array.Empty<string>(),
            DisablePushedAuthorization = true,
            DoNotLoadProfile = true, // the id_token carries sub + preferred_username; skip the userinfo fetch
        };

        var harness = new SsoControllerHarness(
            c =>
            {
                c.OidConfigs["kc"] = NewProvider();

                // A second enabled provider so a COAT test can hit its callback with a state minted for
                // "kc" and isolate the provider-context binding from the unknown/disabled-provider guard.
                if (secondProvider is not null)
                {
                    c.OidConfigs[secondProvider] = NewProvider();
                }
            },
            httpResponder: request =>
            {
                var url = request.RequestUri!.AbsoluteUri;
                if (url == fixture.DiscoveryUrl)
                {
                    return Json(fixture.Discovery());
                }

                if (url == fixture.JwksUrl)
                {
                    return Json(fixture.Jwks());
                }

                if (url == fixture.TokenUrl)
                {
                    return tokenEndpointFails
                        ? new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("{\"error\":\"invalid_grant\"}", Encoding.UTF8, "application/json") }
                        : Json(fixture.TokenEndpointJson(idToken));
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        harness.Controller.HttpContext.Request.Path = "/sso/OID/redirect/kc";
        harness.Controller.HttpContext.Request.QueryString = new QueryString(query);

        // The browser-binding cookie the challenge leg set (#326). Populating the Cookie header is how a
        // DefaultHttpContext exposes Request.Cookies; a null bindingCookie models a callback arriving in a
        // different browser (no cookie), which the binding gate must refuse.
        if (bindingCookie is not null)
        {
            harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={bindingCookie}";
        }

        // The authorize state the redirect leg would have created. The code flow is protected by the PKCE
        // code_verifier here; OidcClient 7.x carries no nonce on the AuthorizeState. BindingId is the id the
        // challenge recorded and the cookie above presents.
        var authState = new AuthorizeState
        {
            State = "state-1",
            CodeVerifier = "test-code-verifier",
            RedirectUri = "https://jf.example.com/sso/OID/redirect/kc",
        };
        SSOController.SeedOidStateForTests("state-1", new TimedAuthorizeState(authState, DateTime.Now) { Provider = "kc", BindingId = Binding });

        return harness;
    }

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
