// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcDiscoveryReader"/> — the single, policy-validated discovery read the OpenID
/// challenge performs, sourcing BOTH the two security facts (PKCE-S256 #141, RFC 9207 response-<c>iss</c>
/// #210) AND the <see cref="ProviderInformation"/> the login is fed from ONE response (#450). They pin:
/// a served document yields the facts plus the metadata OidcClient would build; a document that omits a
/// fact reports a definite <c>false</c> (not a silent downgrade); an unreadable document returns
/// <see cref="OidcDiscoveryResult.Unavailable"/> so the caller fails the login closed; and the read honours
/// the <c>DiscoveryPolicy</c> — a non-HTTPS authority under <c>RequireHttps</c> is refused before any fetch,
/// closing the pre-#450 probe's weak-channel gap.
/// </summary>
public class OidcDiscoveryReaderTests
{
    private const string Authority = "https://idp-reader.example.com";
    private const string DiscoveryUrl = Authority + "/.well-known/openid-configuration";
    private const string JwksUrl = Authority + "/jwks";

    // A discovery document that advertises PKCE S256 and the RFC 9207 response-iss parameter and names the
    // endpoints OidcClient maps onto ProviderInformation.
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

    private static OidcClientOptions OptionsFor(string authority, bool requireHttps = true)
    {
        var options = new OidcClientOptions { Authority = authority };
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(new Uri(authority).GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.RequireHttps = requireHttps;
        options.Policy.Discovery.ValidateIssuerName = true;
        options.Policy.Discovery.ValidateEndpoints = true;
        return options;
    }

    private static ILogger Logger() => Substitute.For<ILogger>();

    [Fact]
    public async Task ReadAsync_ServedDiscovery_ReturnsFactsAndMetadataFromTheOneResponse()
    {
        var http = new CountingFactory(Serve(FullDiscovery(Authority)));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        // Facts read from the SAME discovery response the metadata is built from (#450).
        Assert.True(result.Facts.PkceS256);
        Assert.True(result.Facts.ResponseIssuerAdvertised);
        // The metadata OidcClient's own discovery would produce, so PrepareLoginAsync can reuse it.
        Assert.Equal(Authority, result.ProviderInformation.IssuerName);
        Assert.Equal(Authority + "/authorize", result.ProviderInformation.AuthorizeEndpoint);
        Assert.Equal(Authority + "/token", result.ProviderInformation.TokenEndpoint);
        Assert.NotNull(result.ProviderInformation.KeySet);
        // Exactly one discovery document was fetched (plus its JWKS) — no second probe (#450).
        Assert.Equal(1, http.DiscoveryRequests);
    }

    [Fact]
    public async Task ReadAsync_DiscoveryWithoutS256_ReportsDefiniteFalse_StillAvailable()
    {
        // A readable document that does not advertise S256: PkceS256 is a definite false, not a null/absent
        // that the caller could misread — the caller then rejects only under RequirePkce.
        var discovery = "{"
            + $"\"issuer\":\"{Authority}\","
            + $"\"authorization_endpoint\":\"{Authority}/authorize\","
            + $"\"token_endpoint\":\"{Authority}/token\","
            + $"\"jwks_uri\":\"{Authority}/jwks\","
            + "\"authorization_response_iss_parameter_supported\":true}";
        var http = new CountingFactory(Serve(discovery));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        Assert.False(result.Facts.PkceS256);
        Assert.True(result.Facts.ResponseIssuerAdvertised);
    }

    [Fact]
    public async Task ReadAsync_DiscoveryWithoutResponseIssuerParam_ReportsTolerantFalse()
    {
        // The RFC 9207 parameter is absent: ResponseIssuerAdvertised is false (tolerant), so the callback
        // does not require `iss` — an IdP that never emits it keeps working (#210). This false comes from a
        // document that WAS read, so it is authoritative, not a failed-probe downgrade.
        var discovery = "{"
            + $"\"issuer\":\"{Authority}\","
            + $"\"authorization_endpoint\":\"{Authority}/authorize\","
            + $"\"token_endpoint\":\"{Authority}/token\","
            + $"\"jwks_uri\":\"{Authority}/jwks\","
            + "\"code_challenge_methods_supported\":[\"S256\"]}";
        var http = new CountingFactory(Serve(discovery));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        Assert.True(result.Facts.PkceS256);
        Assert.False(result.Facts.ResponseIssuerAdvertised);
    }

    [Fact]
    public async Task ReadAsync_FetchFailure_ReturnsUnavailable()
    {
        // The document could not be read at all: Unavailable, so the caller fails the login closed rather
        // than proceeding on unverified facts (#450). Never a tolerant default that silently weakens iss.
        var http = new CountingFactory(_ => throw new HttpRequestException("unreachable"));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.False(result.Available);
        Assert.Null(result.ProviderInformation);
    }

    [Fact]
    public async Task ReadAsync_NonHttpsAuthorityUnderRequireHttps_ReturnsUnavailable_WithoutFetching()
    {
        // The DiscoveryPolicy is honoured: a non-HTTPS authority under RequireHttps is refused by
        // IdentityModel before any request leaves the process, so a network attacker on a plaintext
        // discovery channel cannot strip the advertised facts (the pre-#450 probe issued a raw GET with no
        // such policy). The caller then fails closed.
        const string httpAuthority = "http://idp-plaintext.example.com";
        var http = new CountingFactory(Serve(FullDiscovery(httpAuthority)));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(httpAuthority, requireHttps: true), "kc", http.Factory, Logger());

        Assert.False(result.Available);
        Assert.Equal(0, http.DiscoveryRequests); // policy rejected the address before any fetch
    }

    // Serves the given discovery JSON for the well-known document and an empty JWKS for the keyset fetch;
    // any other URL 404s so an unexpected request is visible.
    private static Func<HttpRequestMessage, HttpResponseMessage> Serve(string discoveryJson) => request =>
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
        {
            return Json(discoveryJson);
        }

        if (url.EndsWith("/jwks", StringComparison.Ordinal))
        {
            return Json("{\"keys\":[]}");
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    };

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    // A factory whose every client is backed by the responder and that counts the outbound discovery-document
    // requests (the well-known URL) it serves, so a test can assert a single discovery read.
    private sealed class CountingFactory
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        internal CountingFactory(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
            var factory = Substitute.For<IHttpClientFactory>();
            factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new StubHttpMessageHandler(Handle)));
            Factory = factory;
        }

        internal IHttpClientFactory Factory { get; }

        internal int DiscoveryRequests { get; private set; }

        private HttpResponseMessage Handle(HttpRequestMessage request)
        {
            if (request.RequestUri!.AbsoluteUri.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
            {
                DiscoveryRequests++;
            }

            return _responder(request);
        }
    }
}
