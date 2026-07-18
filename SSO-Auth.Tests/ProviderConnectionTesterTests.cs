using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="ProviderConnectionTester"/> — the admin Test-connection probe (#163). They pin:
/// the OpenID probe reads discovery through the hardened reader and reports the issuer, endpoints and JWKS
/// reachability; an unreadable document / invalid endpoint / missing endpoint returns a fail-closed,
/// actionable, secret-free result rather than throwing; the SAML probe reports a parsing certificate's
/// public facts and rejects a non-parsing one; and NEITHER path ever leaks a stored secret into the result.
/// </summary>
public class ProviderConnectionTesterTests
{
    private const string Authority = "https://idp-test.example.com";
    private const string OidSecretSentinel = "super-secret-oid-client-secret-value";
    private const string SamlKeySentinel = "super-secret-saml-signing-key-pfx-value";

    private static string FullDiscovery(string authority) =>
        "{"
        + $"\"issuer\":\"{authority}\","
        + $"\"authorization_endpoint\":\"{authority}/authorize\","
        + $"\"token_endpoint\":\"{authority}/token\","
        + $"\"userinfo_endpoint\":\"{authority}/userinfo\","
        + $"\"jwks_uri\":\"{authority}/jwks\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
        + "\"code_challenge_methods_supported\":[\"S256\"],"
        + "\"authorization_response_iss_parameter_supported\":true}";

    private static ILogger Logger() => Substitute.For<ILogger>();

    [Fact]
    public async Task TestOidcAsync_ServedDiscovery_ReportsIssuerEndpointsAndJwks()
    {
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf", OidSecret = OidSecretSentinel };
        var factory = FactoryFor(Serve(FullDiscovery(Authority)));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.True(result.Ok);
        Assert.Contains(result.Details, d => d.Contains(Authority, StringComparison.Ordinal) && d.StartsWith("Issuer:", StringComparison.Ordinal));
        Assert.Contains(result.Details, d => d.Contains(Authority + "/authorize", StringComparison.Ordinal));
        Assert.Contains(result.Details, d => d.Contains(Authority + "/token", StringComparison.Ordinal));
        // The JWKS was reachable (the reader fetches it as part of discovery) — one key served below.
        Assert.Contains(result.Details, d => d.StartsWith("JWKS: reachable", StringComparison.Ordinal));
        Assert.Contains(result.Details, d => d.StartsWith("PKCE (S256) advertised: yes", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TestOidcAsync_UnreadableDiscovery_FailsClosedWithActionableMessage()
    {
        var config = new OidConfig { OidEndpoint = "https://idp-unreachable.example.com", OidClientId = "jf" };
        var factory = FactoryFor(_ => throw new HttpRequestException("unreachable"));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.False(result.Ok);
        Assert.Contains("discovery document", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.Details);
    }

    [Theory]
    [InlineData("not-a-url")]
    [InlineData("ftp:///")]
    public async Task TestOidcAsync_InvalidEndpoint_FailsClosed(string endpoint)
    {
        var config = new OidConfig { OidEndpoint = endpoint, OidClientId = "jf" };
        var factory = FactoryFor(Serve(FullDiscovery(Authority)));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.False(result.Ok);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task TestOidcAsync_NoEndpoint_FailsClosed_WithoutFetching(string? endpoint)
    {
        var config = new OidConfig { OidEndpoint = endpoint };
        var contacted = false;
        var factory = FactoryFor(request =>
        {
            contacted = true;
            return Json(FullDiscovery(Authority));
        });

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.False(result.Ok);
        Assert.False(contacted); // no endpoint -> no outbound fetch
    }

    [Fact]
    public async Task TestOidcAsync_NonHttpsUnderRequireHttps_FailsClosed()
    {
        // DisableHttps is off (default), so the discovery policy is RequireHttps; a plaintext endpoint is
        // refused by the reader before any fetch — the probe inherits the login's SSRF/TLS posture (#163).
        const string httpAuthority = "http://idp-plaintext.example.com";
        var config = new OidConfig { OidEndpoint = httpAuthority, OidClientId = "jf" };
        var fetched = false;
        var factory = FactoryFor(request =>
        {
            fetched = true;
            return Json(FullDiscovery(httpAuthority));
        });

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.False(result.Ok);
        Assert.False(fetched);
    }

    [Fact]
    public async Task TestOidcAsync_NeverLeaksTheStoredClientSecret()
    {
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf", OidSecret = OidSecretSentinel };
        var factory = FactoryFor(Serve(FullDiscovery(Authority)));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        AssertNoSecret(result, OidSecretSentinel);
    }

    [Fact]
    public void TestSaml_ValidCertificate_ReportsPublicFacts()
    {
        var config = new SamlConfig
        {
            SamlCertificate = SamlTestFactory.Create().CertificateBase64,
            SamlSigningKeyPfx = SamlKeySentinel,
        };

        var result = ProviderConnectionTester.TestSaml(config);

        Assert.True(result.Ok);
        Assert.Contains(result.Details, d => d.StartsWith("Subject:", StringComparison.Ordinal));
        Assert.Contains(result.Details, d => d.StartsWith("SHA-256 thumbprint:", StringComparison.Ordinal));
        // The service-provider signing key (a secret) must never appear in the public-cert report.
        AssertNoSecret(result, SamlKeySentinel);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TestSaml_BlankCertificate_FailsClosed(string? certificate)
    {
        var result = ProviderConnectionTester.TestSaml(new SamlConfig { SamlCertificate = certificate });

        Assert.False(result.Ok);
        Assert.Empty(result.Details);
    }

    [Theory]
    [InlineData("@@ not base64 @@")]
    [InlineData("QUJD")] // valid base64 ("ABC") but not a certificate
    public void TestSaml_UnparsableCertificate_FailsClosed(string certificate)
    {
        var result = ProviderConnectionTester.TestSaml(new SamlConfig { SamlCertificate = certificate });

        Assert.False(result.Ok);
        Assert.Contains("could not be parsed", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    // Asserts the sentinel secret appears in NO admin-facing field of the result.
    private static void AssertNoSecret(ProviderTestResult result, string secret)
    {
        Assert.DoesNotContain(secret, result.Message, StringComparison.Ordinal);
        Assert.All(result.Details, d => Assert.DoesNotContain(secret, d, StringComparison.Ordinal));
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> Serve(string discoveryJson) => request =>
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
        {
            return Json(discoveryJson);
        }

        // One RSA key so the JWKS reachability line reports a positive count.
        if (url.EndsWith("/jwks", StringComparison.Ordinal))
        {
            return Json("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"abc\",\"e\":\"AQAB\"}]}");
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    };

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static IHttpClientFactory FactoryFor(Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new StubHttpMessageHandler(responder)));
        return factory;
    }
}
