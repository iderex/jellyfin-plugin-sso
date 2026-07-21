using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Jellyfin.Plugin.SSO_Auth.Api.Net;

/// <summary>
/// The one home for the plugin's outbound HTTP policy: the User-Agent, and the single SSRF-hardened
/// transport every server-to-provider call is built on. Both the OpenID discovery / token / JWKS backchannel
/// (through <see cref="CreateClient"/>, which resolves the named <see cref="OutboundClientName"/> client) and
/// the avatar fetch (which builds its own long-lived client on <see cref="CreateHardenedHandler"/>) share the
/// same connect-time guard, so a provider or avatar URL resolving to a private/loopback address is rejected
/// at the transport layer in one place (#370, #755). The named client's hardened handler is registered in the
/// composition root; a test's stub/loopback factory supplies its own handler for that name, so integration
/// tests reach their in-process IdP while production stays fail-closed.
/// </summary>
internal static class SsoHttp
{
    /// <summary>
    /// The <see cref="IHttpClientFactory"/> name of the plugin's SSRF-hardened outbound client. The
    /// composition root registers this name with <see cref="CreateHardenedHandler"/>; production
    /// server-to-provider calls resolve it through <see cref="CreateClient"/>.
    /// </summary>
    internal const string OutboundClientName = "sso-outbound";

    /// <summary>
    /// The plugin's outbound User-Agent: product token, assembly file version, and project URL.
    /// </summary>
    internal static readonly string UserAgent =
        $"Jellyfin-Plugin-SSO-Auth +{FileVersionInfo.GetVersionInfo(typeof(SsoHttp).Assembly.Location).FileVersion} (https://github.com/iderex/jellyfin-plugin-sso)";

    /// <summary>
    /// Returns the SSRF-hardened outbound client (the named <see cref="OutboundClientName"/> client from the
    /// factory, whose primary handler is <see cref="CreateHardenedHandler"/> in production) with
    /// <see cref="UserAgent"/> applied. Used for the OpenID discovery / token / JWKS fetches, so a provider
    /// endpoint that resolves to a private/loopback address cannot be reached (#755).
    /// </summary>
    /// <param name="factory">The shared HTTP client factory.</param>
    /// <returns>A client with the plugin User-Agent applied over the hardened transport.</returns>
    internal static HttpClient CreateClient(IHttpClientFactory factory)
    {
        var client = factory.CreateClient(OutboundClientName);
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return client;
    }

    /// <summary>
    /// The SSRF-hardened transport handler: routes every connection (including redirect targets) through a
    /// callback that resolves the host and connects only to a non-blocked (public) address, closing the SSRF
    /// and DNS-rebinding vectors. Redirects stay enabled but bounded; the system proxy is disabled so the
    /// guard validates the real host, not a proxy; and a pooled connection is recycled periodically so DNS
    /// changes are honoured despite reuse. The one implementation shared by the OpenID backchannel (via the
    /// named outbound client) and the avatar fetch.
    /// </summary>
    /// <returns>A hardened <see cref="SocketsHttpHandler"/>.</returns>
    internal static SocketsHttpHandler CreateHardenedHandler() => new()
    {
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 5,
        ConnectCallback = ConnectToAllowedAddressAsync,

        // A system proxy would be the connection target, so the connect callback would validate the proxy's
        // address rather than the real host's — bypassing the guard.
        UseProxy = false,

        // The handler is reused, so bound how long a pooled connection lives — after this the connection is
        // recycled and the host re-resolved, so DNS changes are honored despite reuse.
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
    };

    // Resolves the target host and connects only to a non-blocked (public) address, so a hostname that
    // resolves to an internal address — including via DNS rebinding on a redirect hop — cannot be reached.
    private static async ValueTask<Stream> ConnectToAllowedAddressAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await System.Net.Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);

        // Try every non-blocked address in turn (a per-address connect fallback for dual-stack / multi-record
        // hosts, since supplying a ConnectCallback replaces the handler's built-in one), connecting to the
        // validated IP rather than the hostname so a DNS rebind cannot redirect the connection internally.
        Exception? lastError = null;
        var attempted = false;
        foreach (var address in addresses)
        {
            if (IpAddressClassifier.IsBlockedAddress(address))
            {
                continue;
            }

            attempted = true;
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            var connected = false;
            try
            {
                await socket.ConnectAsync(address, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);
                connected = true;
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = ex;
            }
            finally
            {
                // Dispose unless ownership passed to the returned NetworkStream. Runs on the cancellation path
                // too, where the catch filter is skipped and the socket would otherwise leak.
                if (!connected)
                {
                    socket.Dispose();
                }
            }
        }

        if (attempted)
        {
            throw new HttpRequestException("Could not connect to any allowed address for the outbound host.", lastError);
        }

        throw new HttpRequestException("The outbound host resolves only to blocked addresses.");
    }
}
