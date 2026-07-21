// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Net.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SsoHttp"/> — the single home for the plugin's outbound HTTP policy (#318, #378).
/// <see cref="SsoHttp.CreateClient"/> must resolve the SSRF-hardened <see cref="SsoHttp.OutboundClientName"/>
/// named client from the factory (whose primary handler is the hardened transport in production, #755) with
/// the plugin User-Agent applied, so every server-to-provider call is identifiable and transport-guarded from
/// one definition.
/// </summary>
public class SsoHttpTests
{
    [Fact]
    public void CreateClient_ResolvesTheNamedHardenedClient_AndAppliesTheUserAgent()
    {
        using var factoryClient = new HttpClient();
        var factory = Substitute.For<IHttpClientFactory>();
        // CreateClient must ask for the SSRF-hardened OUTBOUND client by name (#755): in production that name
        // is registered with the hardened SocketsHttpHandler, so requesting the default client instead would
        // silently bypass the connect-time guard. A test's stub/loopback factory returns its own client for
        // this name, keeping an in-process IdP reachable.
        factory.CreateClient(SsoHttp.OutboundClientName).Returns(factoryClient);

        var client = SsoHttp.CreateClient(factory);

        Assert.Same(factoryClient, client); // the named client is used, not the default and not a fresh one
        factory.Received(1).CreateClient(SsoHttp.OutboundClientName);
        // The whole User-Agent must round-trip against the single-sourced constant — a wrong version or URL
        // would slip past a substring check.
        Assert.Equal(SsoHttp.UserAgent, client.DefaultRequestHeaders.UserAgent.ToString());
    }

    [Fact]
    public void CreateHardenedHandler_IsConfiguredWithTheSsrfConnectGuardAndNoProxy()
    {
        // The transport guard cannot be exercised at unit level (it fires only on a real socket connect, and
        // the higher-level tests stub the message handler, #385) — so pin its CONFIGURATION here, so a
        // regression that drops the ConnectCallback, re-enables the system proxy (which would make the guard
        // validate the proxy instead of the host), or unbounds redirects fails this test rather than silently
        // reopening the SSRF / DNS-rebinding vector (#755, #370).
        using var handler = SsoHttp.CreateHardenedHandler();

        Assert.NotNull(handler.ConnectCallback);
        Assert.False(handler.UseProxy);
        Assert.True(handler.AllowAutoRedirect);
        Assert.Equal(5, handler.MaxAutomaticRedirections);
    }
}
