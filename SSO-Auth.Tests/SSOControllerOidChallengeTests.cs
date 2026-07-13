using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the OpenID challenge via <see cref="SsoControllerHarness"/>. They cover the
/// PKCE-discovery gate (#141, RFC 9700 §2.1.1) — when a provider is marked <c>RequirePkce</c>, the
/// challenge must fail closed unless the authorization server's discovery document advertises PKCE
/// (S256), so a document without S256 or one that cannot be read is refused with a 400 — and the
/// enabled-provider happy path, where a served discovery document yields a redirect to the authorization
/// endpoint. The discovery document is served in-process through the harness's stub HTTP responder; the
/// harness resets the shared authorize-state store between tests (#289).
/// </summary>
[Collection("SSOController")]
public class SSOControllerOidChallengeTests
{
    [Fact]
    public async Task OidChallenge_DisabledProvider_Throws()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = false });

        await Assert.ThrowsAsync<ArgumentException>(() => harness.Controller.OidChallenge("kc"));
    }

    [Fact]
    public async Task OidChallenge_RequirePkceButProviderDoesNotAdvertiseS256_Returns400()
    {
        var requested = new List<string>();
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = "https://idp-no-s256.example.com",
                OidClientId = "jf",
                RequirePkce = true,
            },
            // Discovery is served but omits code_challenge_methods_supported, so S256 is not advertised.
            httpResponder: request =>
            {
                requested.Add(request.RequestUri!.AbsoluteUri);
                return Json("{\"issuer\":\"https://idp-no-s256.example.com\"}");
            });

        var result = await harness.Controller.OidChallenge("kc");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
        // The 400 must come from the PKCE gate, which only fires after the discovery document is fetched
        // and found to lack S256 — so the discovery endpoint must actually have been contacted.
        Assert.Contains("https://idp-no-s256.example.com/.well-known/openid-configuration", requested);
    }

    [Fact]
    public async Task OidChallenge_RequirePkceButDiscoveryUnreadable_Returns400()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            OidEndpoint = "https://idp-unreachable.example.com",
            OidClientId = "jf",
            RequirePkce = true,
        });
        // No httpResponder: the discovery fetch fails, so PKCE (S256) support cannot be confirmed.

        var result = await harness.Controller.OidChallenge("kc");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task OidChallenge_EnabledProviderWithDiscovery_RedirectsToAuthorizeEndpoint()
    {
        const string authority = "https://idp-full.example.com";
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
            },
            httpResponder: request =>
            {
                var url = request.RequestUri!.AbsoluteUri;
                if (url == authority + "/.well-known/openid-configuration")
                {
                    return Json(Discovery(authority));
                }

                if (url == authority + "/jwks")
                {
                    return Json("{\"keys\":[]}");
                }

                // A challenge should only fetch discovery and its JWKS; any other URL is unexpected and
                // fails the request so a regression that reaches, e.g., the token endpoint is caught.
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        var result = await harness.Controller.OidChallenge("kc");

        // A served discovery document lets OidcClient build the authorization redirect; the harness's
        // per-test reset of the static state store (#289) keeps the added authorize state from leaking.
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.StartsWith(authority + "/authorize", redirect.Url);
    }

    private static string Discovery(string authority) =>
        $"{{\"issuer\":\"{authority}\","
        + $"\"authorization_endpoint\":\"{authority}/authorize\","
        + $"\"token_endpoint\":\"{authority}/token\","
        + $"\"jwks_uri\":\"{authority}/jwks\","
        + $"\"userinfo_endpoint\":\"{authority}/userinfo\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
        + "\"grant_types_supported\":[\"authorization_code\"],"
        + "\"code_challenge_methods_supported\":[\"S256\"]}";

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
