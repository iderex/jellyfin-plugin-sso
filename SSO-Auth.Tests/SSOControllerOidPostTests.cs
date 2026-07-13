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
    public async Task OidPost_ResponseIssuerMismatch_Returns400()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // RFC 9207 (#125): the authorization-response `iss` names a different issuer than the id_token's,
        // which is an authorization-server mix-up and must be rejected even though the token itself is valid.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1&iss=https://attacker.example.com");

        var result = await harness.Controller.OidPost("kc", "state-1");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    // Builds a harness whose HTTP responder serves the fixture's discovery/JWKS/token endpoints, seeds the
    // matching authorize state, and sets the callback request path and query.
    private static SsoControllerHarness ArrangeCallback(OidcTokenFixture fixture, string query)
    {
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice");

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
                    return Json(fixture.TokenEndpointJson(idToken));
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        harness.Controller.HttpContext.Request.Path = "/sso/OID/redirect/kc";
        harness.Controller.HttpContext.Request.QueryString = new QueryString(query);

        // The authorize state the redirect leg would have created. The code flow is protected by the PKCE
        // code_verifier here; OidcClient 7.x carries no nonce on the AuthorizeState.
        var authState = new AuthorizeState
        {
            State = "state-1",
            CodeVerifier = "test-code-verifier",
            RedirectUri = "https://jf.example.com/sso/OID/redirect/kc",
        };
        SSOController.SeedOidStateForTests("state-1", new TimedAuthorizeState(authState, DateTime.Now) { Provider = "kc" });

        return harness;
    }

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
