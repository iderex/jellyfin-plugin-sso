// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
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

    [Theory]
    [InlineData("http://127.0.0.1")] // IPv4 loopback literal
    [InlineData("http://[::1]")] // IPv6 loopback literal
    [InlineData("http://10.0.0.1")] // RFC1918 private literal
    [InlineData("http://169.254.169.254")] // link-local cloud metadata endpoint
    [InlineData("http://localhost")] // a NAME that resolves to loopback
    public async Task HardenedHandler_RefusesAConnectionToABlockedAddress_AtTheSocketLayer(string baseUrl)
    {
        // #928 U7 — the real socket-level integration test the configuration pin above explicitly could not
        // provide. This drives the ACTUAL hardened handler (its ConnectCallback resolves the host and refuses
        // any blocked address before connecting), so a regression that lets the guard connect to a
        // loopback / RFC1918 / link-local address is a red build — not merely a changed handler property.
        // A live listener on the loopback port proves the point: the guard must refuse BEFORE any socket
        // reaches it.
        using var listener = new BlockedListener();
        using var handler = SsoHttp.CreateHardenedHandler();
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

        var target = $"{baseUrl}:{listener.Port}/";
        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetAsync(target, TestContext.Current.CancellationToken));

        // The guard's own diagnostics — proves the refusal came from ConnectToAllowedAddressAsync, not an
        // unrelated transport error.
        Assert.Contains("blocked address", ex.Message, StringComparison.OrdinalIgnoreCase);
        // And nothing reached the socket: the listener never accepted a connection.
        Assert.False(listener.Accepted, "the SSRF guard let a socket reach the blocked loopback listener");
    }

    // A loopback TCP listener that would accept any connection reaching it — so a passing test proves the
    // guard refused BEFORE the socket layer, not that the port simply happened to be closed.
    private sealed class BlockedListener : IDisposable
    {
        private readonly Socket _socket;
        private readonly CancellationTokenSource _cts = new();

        internal BlockedListener()
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _socket.Listen(16);
            Port = ((IPEndPoint)_socket.LocalEndPoint!).Port;
            _ = AcceptLoopAsync(_cts.Token);
        }

        internal int Port { get; }

        internal bool Accepted { get; private set; }

        private async Task AcceptLoopAsync(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    using var conn = await _socket.AcceptAsync(token).ConfigureAwait(false);
                    Accepted = true;
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // Listener torn down — expected on dispose.
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _socket.Dispose();
            _cts.Dispose();
        }
    }
}
