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
        string? bindingCookie = Binding)
    {
        idToken ??= fixture.IdToken(subject: "sub-1", username: "alice");

        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = Authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
                DoNotLoadProfile = true, // the id_token carries sub + preferred_username; skip the userinfo fetch
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
            harness.Controller.HttpContext.Request.Headers["Cookie"] = $"{AuthorizeStateBinding.CookieName}={bindingCookie}";
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
