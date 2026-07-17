using System;
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
/// Tests for <see cref="OidcDiscoveryCache"/> — the per-discovery-URL cache of the two facts the OpenID
/// challenge reads in one fetch (PKCE-S256 support #141 and the RFC 9207 response-<c>iss</c> advertisement
/// #210), extracted off the controller in #449. They pin the behaviour the controller relied on: a fresh
/// fetch is parsed and cached, a second read within the TTL is served without a re-fetch, a stale entry is
/// re-fetched, a "read but not advertised" fact is a definite false, an unusable authority never fetches,
/// and a fetch failure returns the tolerant default WITHOUT caching it so the next login retries.
/// </summary>
public class OidcDiscoveryCacheTests
{
    private const string Authority = "https://idp-cache.example.com";
    private const string DiscoveryUrl = Authority + "/.well-known/openid-configuration";

    // Discovery that advertises PKCE S256 and the RFC 9207 response-iss parameter.
    private static string FullDiscovery() =>
        "{\"issuer\":\"" + Authority + "\","
        + "\"code_challenge_methods_supported\":[\"S256\"],"
        + "\"authorization_response_iss_parameter_supported\":true}";

    private static OidConfig Config() => new OidConfig { Enabled = true, OidEndpoint = Authority };

    private static ILogger Logger() => Substitute.For<ILogger>();

    [Fact]
    public async Task ReadFacts_ParsesAdvertisedFacts()
    {
        var http = new CountingFactory(_ => Json(FullDiscovery()));
        var cache = new OidcDiscoveryCache();

        var facts = await cache.ReadFactsAsync(Config(), "kc", http.Factory, Logger());

        Assert.True(facts.PkceS256); // S256 advertised -> true
        Assert.True(facts.ResponseIssuerAdvertised); // RFC 9207 iss advertised -> true
    }

    [Fact]
    public async Task ReadFacts_SecondReadWithinTtl_IsServedFromCache()
    {
        var http = new CountingFactory(_ => Json(FullDiscovery()));
        var cache = new OidcDiscoveryCache();

        var first = await cache.ReadFactsAsync(Config(), "kc", http.Factory, Logger());
        var second = await cache.ReadFactsAsync(Config(), "kc", http.Factory, Logger());

        Assert.Equal(first, second); // identical facts round-trip out of the cache
        Assert.Equal(1, http.DiscoveryRequests); // fetched once; the second read did not touch the network
    }

    [Fact]
    public async Task ReadFacts_AfterTtlElapsed_ReFetches()
    {
        var http = new CountingFactory(_ => Json(FullDiscovery()));
        var cache = new OidcDiscoveryCache(TimeSpan.Zero); // every entry is immediately stale

        await cache.ReadFactsAsync(Config(), "kc", http.Factory, Logger());
        await cache.ReadFactsAsync(Config(), "kc", http.Factory, Logger());

        Assert.Equal(2, http.DiscoveryRequests); // a stale entry is re-fetched, not served
    }

    [Fact]
    public async Task ReadFacts_DiscoveryWithoutS256_ReportsDefiniteFalse()
    {
        var http = new CountingFactory(_ => Json("{\"issuer\":\"" + Authority + "\"}"));
        var cache = new OidcDiscoveryCache();

        var facts = await cache.ReadFactsAsync(Config(), "kc", http.Factory, Logger());

        Assert.False(facts.PkceS256); // read but not advertised -> a definite false, not null
        Assert.False(facts.ResponseIssuerAdvertised);
    }

    [Fact]
    public async Task ReadFacts_MissingOrInvalidEndpoint_ReturnsDefault_WithoutFetching()
    {
        var http = new CountingFactory(_ => Json(FullDiscovery()));
        var cache = new OidcDiscoveryCache();

        var facts = await cache.ReadFactsAsync(new OidConfig { Enabled = true, OidEndpoint = "not-a-url" }, "kc", http.Factory, Logger());

        Assert.Null(facts.PkceS256); // unusable authority -> unreadable (null), caller fails closed under RequirePkce
        Assert.False(facts.ResponseIssuerAdvertised);
        Assert.Equal(0, http.DiscoveryRequests); // never attempted a fetch
    }

    [Fact]
    public async Task ReadFacts_EndpointAlreadyWellKnown_DoesNotDoubleAppendThePath()
    {
        string? requested = null;
        var http = new CountingFactory(req =>
        {
            requested = req.RequestUri!.AbsoluteUri;
            return Json(FullDiscovery());
        });
        var cache = new OidcDiscoveryCache();

        await cache.ReadFactsAsync(new OidConfig { Enabled = true, OidEndpoint = DiscoveryUrl }, "kc", http.Factory, Logger());

        Assert.Equal(DiscoveryUrl, requested); // the well-known path is appended only when absent
    }

    [Fact]
    public async Task ReadFacts_FetchFailure_ReturnsTolerantDefault_AndIsNotCached()
    {
        var http = new CountingFactory(Throw);
        var cache = new OidcDiscoveryCache();

        var failed = await cache.ReadFactsAsync(Config(), "kc", http.Factory, Logger());
        Assert.Null(failed.PkceS256); // unreadable -> null (tolerant; caller fails closed only under RequirePkce)
        Assert.False(failed.ResponseIssuerAdvertised);

        // The failure was not cached, so a subsequent successful fetch yields the real facts — a transient
        // outage retries on the next login rather than pinning the tolerant default for the whole TTL.
        http.SetResponder(_ => Json(FullDiscovery()));
        var recovered = await cache.ReadFactsAsync(Config(), "kc", http.Factory, Logger());
        Assert.True(recovered.PkceS256);
        Assert.True(recovered.ResponseIssuerAdvertised);
        Assert.Equal(2, http.DiscoveryRequests); // both the failing and the succeeding fetch actually ran
    }

    [Fact]
    public async Task ReadFacts_Clear_DropsTheCachedEntry()
    {
        var http = new CountingFactory(_ => Json(FullDiscovery()));
        var cache = new OidcDiscoveryCache();

        await cache.ReadFactsAsync(Config(), "kc", http.Factory, Logger());
        cache.Clear();
        await cache.ReadFactsAsync(Config(), "kc", http.Factory, Logger());

        Assert.Equal(2, http.DiscoveryRequests); // a cleared cache re-fetches (test-isolation reset works)
    }

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    // A fetch failure: SendAsync throws, which the cache's fetch surfaces as the tolerant default.
    private static HttpResponseMessage Throw(HttpRequestMessage request) => throw new HttpRequestException("unreachable");

    // A factory whose every client is backed by the current responder — swappable so a test can start with
    // a failing fetch and then a succeeding one — that counts the outbound discovery requests it serves.
    private sealed class CountingFactory
    {
        private Func<HttpRequestMessage, HttpResponseMessage> _responder;

        internal CountingFactory(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
            var factory = Substitute.For<IHttpClientFactory>();
            factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new StubHttpMessageHandler(Handle)));
            Factory = factory;
        }

        internal IHttpClientFactory Factory { get; }

        internal int DiscoveryRequests { get; private set; }

        internal void SetResponder(Func<HttpRequestMessage, HttpResponseMessage> responder) => _responder = responder;

        private HttpResponseMessage Handle(HttpRequestMessage request)
        {
            DiscoveryRequests++;
            return _responder(request);
        }
    }
}
