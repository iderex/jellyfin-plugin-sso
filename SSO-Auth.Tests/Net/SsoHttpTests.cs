using System.Net.Http;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SsoHttp"/> — the single home for the plugin's outbound HTTP policy (#318, #378).
/// <see cref="SsoHttp.CreateClient"/> must return the factory's client (over the factory's pooled handler
/// stack, not a fresh standalone client) with the plugin User-Agent applied, so every server-to-provider
/// call is identifiable from one definition.
/// </summary>
public class SsoHttpTests
{
    [Fact]
    public void CreateClient_AppliesThePluginUserAgentToTheFactoryClient()
    {
        using var factoryClient = new HttpClient();
        var factory = Substitute.For<IHttpClientFactory>();
        // factory.CreateClient() is the HttpClientFactoryExtensions extension method, which forwards to
        // the interface's CreateClient(Options.DefaultName) — NSubstitute latches onto that forwarded
        // interface call, so this Returns covers the parameterless extension too.
        factory.CreateClient().Returns(factoryClient);

        var client = SsoHttp.CreateClient(factory);

        Assert.Same(factoryClient, client); // the factory's client is used, not a fresh one
        // The whole User-Agent must round-trip against the single-sourced constant — a wrong version or
        // URL would slip past a substring check.
        Assert.Equal(SsoHttp.UserAgent, client.DefaultRequestHeaders.UserAgent.ToString());
    }
}
