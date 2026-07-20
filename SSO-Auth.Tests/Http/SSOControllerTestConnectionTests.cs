using System;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the admin Test-connection endpoints (#163) via <see cref="SsoControllerHarness"/>.
/// They pin: both endpoints are elevation-gated (so an unauthenticated/non-admin caller cannot drive the
/// server-side fetch as an SSRF probe); an unknown provider is a 404; the OpenID probe reports the issuer,
/// endpoints and JWKS through the hardened reader; the SAML probe parses the configured certificate; and the
/// serialized response never carries the stored client secret / signing key.
/// </summary>
[Collection("SSOController")]
public class SSOControllerTestConnectionTests
{
    private const string Authority = "https://idp-endpoint-test.example.com";
    private const string OidSecretSentinel = "endpoint-test-oid-secret";
    private const string SamlKeySentinel = "endpoint-test-saml-key";

    [Fact]
    public void OidTest_IsGuardedByTheElevationPolicy()
    {
        // The harness calls the action directly, bypassing MVC's authorization filter, so the "not an
        // anonymous SSRF probe" property is pinned structurally: the [Authorize(RequiresElevation)] filter
        // rejects a non-elevated caller (401/403) before the body — and thus before any outbound fetch —
        // runs. This is the deliberate difference from the anonymous OID/SAML GetNames (#540).
        var authorize = typeof(SSOController).GetMethod(nameof(SSOController.OidTest))!
            .GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(authorize);
        Assert.Equal(Policies.RequiresElevation, authorize!.Policy);
    }

    [Fact]
    public void SamlTest_IsGuardedByTheElevationPolicy()
    {
        var authorize = typeof(SSOController).GetMethod(nameof(SSOController.SamlTest))!
            .GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(authorize);
        Assert.Equal(Policies.RequiresElevation, authorize!.Policy);
    }

    [Fact]
    public async Task OidTest_UnknownProvider_ReturnsNotFound()
    {
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.OidTest("does-not-exist");

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public void SamlTest_UnknownProvider_ReturnsNotFound()
    {
        var harness = new SsoControllerHarness();

        var result = harness.Controller.SamlTest("does-not-exist");

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task OidTest_ServedDiscovery_ReportsIssuerEndpointsAndJwks()
    {
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig { Enabled = true, OidEndpoint = Authority, OidClientId = "jf", OidSecret = OidSecretSentinel },
            httpResponder: Responder);

        var ok = Assert.IsType<OkObjectResult>(await harness.Controller.OidTest("kc"));
        var result = Assert.IsType<ProviderTestResult>(ok.Value);

        Assert.True(result.Ok);
        Assert.Contains(result.Details, d => d.StartsWith("Issuer:", StringComparison.Ordinal) && d.Contains(Authority, StringComparison.Ordinal));
        Assert.Contains(result.Details, d => d.StartsWith("JWKS: reachable", StringComparison.Ordinal));
    }

    [Fact]
    public async Task OidTest_ResponseNeverCarriesTheStoredClientSecret()
    {
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig { Enabled = true, OidEndpoint = Authority, OidClientId = "jf", OidSecret = OidSecretSentinel },
            httpResponder: Responder);

        var ok = Assert.IsType<OkObjectResult>(await harness.Controller.OidTest("kc"));

        // Serialize exactly as the MVC JSON formatter would; the secret must appear nowhere in the payload.
        var json = JsonSerializer.Serialize(ok.Value);
        Assert.DoesNotContain(OidSecretSentinel, json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OidTest_UnreadableDiscovery_ReturnsOkResultThatFailedClosed()
    {
        // No httpResponder: the discovery fetch fails. The endpoint still returns 200 with a well-formed
        // result whose Ok is false and whose message is actionable — the probe reports failure, it does not
        // throw an unhandled 500.
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig { Enabled = true, OidEndpoint = "https://idp-down.example.com", OidClientId = "jf" });

        var ok = Assert.IsType<OkObjectResult>(await harness.Controller.OidTest("kc"));
        var result = Assert.IsType<ProviderTestResult>(ok.Value);

        Assert.False(result.Ok);
    }

    [Fact]
    public void SamlTest_ValidCertificate_ReportsParseSuccess()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["idp"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = SamlTestFactory.Create().CertificateBase64,
            SamlSigningKeyPfx = SamlKeySentinel,
        });

        var ok = Assert.IsType<OkObjectResult>(harness.Controller.SamlTest("idp"));
        var result = Assert.IsType<ProviderTestResult>(ok.Value);

        Assert.True(result.Ok);
        var json = JsonSerializer.Serialize(ok.Value);
        Assert.DoesNotContain(SamlKeySentinel, json, StringComparison.Ordinal);
    }

    // Serves the discovery document and a one-key JWKS; any other URL 404s so an unexpected call is visible.
    private static HttpResponseMessage Responder(HttpRequestMessage request)
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url == Authority + "/.well-known/openid-configuration")
        {
            return Json(Discovery(Authority));
        }

        if (url == Authority + "/jwks")
        {
            return Json("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"abc\",\"e\":\"AQAB\"}]}");
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
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
        + "\"code_challenge_methods_supported\":[\"S256\"]}";

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
