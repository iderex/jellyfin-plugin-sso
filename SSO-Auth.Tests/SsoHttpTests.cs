using System.Net.Http;
using Jellyfin.Plugin.SSO_Auth.Api;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SsoHttp"/> — the single factory for the plugin's outbound HTTP clients (#318).
/// It must return a factory-pooled client with the plugin User-Agent applied, so every server-to-provider
/// call is identifiable in one place.
/// </summary>
public class SsoHttpTests
{
    [Fact]
    public void CreateClient_AppliesTheUserAgentToTheFactoryClient()
    {
        using var pooled = new HttpClient();
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient().Returns(pooled);
        const string userAgent = "Jellyfin-Plugin-SSO-Auth +1.2.3 (https://example.test)";

        var client = SsoHttp.CreateClient(factory, userAgent);

        Assert.Same(pooled, client); // the factory's client is used, not a fresh one
        // The whole User-Agent must round-trip, not just the product token — a wrong version or URL
        // would slip past a substring check.
        Assert.Equal(userAgent, client.DefaultRequestHeaders.UserAgent.ToString());
    }
}
