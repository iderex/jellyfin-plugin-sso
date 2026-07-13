using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the OpenID challenge's PKCE-discovery gate (#141, RFC 9700 §2.1.1) via
/// <see cref="SsoControllerHarness"/>. When a provider is marked <c>RequirePkce</c>, the challenge must
/// fail closed unless the authorization server's discovery document advertises PKCE (S256): a document
/// without S256, or one that cannot be read at all, is refused with a 400. The discovery document is
/// served in-process through the harness's stub HTTP responder.
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
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = "https://idp-no-s256.example.com",
                OidClientId = "jf",
                RequirePkce = true,
            },
            // Discovery is served but omits code_challenge_methods_supported, so S256 is not advertised.
            httpResponder: _ => Json("{\"issuer\":\"https://idp-no-s256.example.com\"}"));

        var result = await harness.Controller.OidChallenge("kc");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
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

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
