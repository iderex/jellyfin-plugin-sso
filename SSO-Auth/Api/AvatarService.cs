using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Fetches an SSO provider's avatar over an SSRF-safe transport and stores it as the user's profile
/// image. Best-effort by design: any fetch or save failure is logged and the login proceeds without the
/// avatar. The security-relevant parts — the URL allow-list, the per-connection IP validation (closing
/// SSRF and DNS-rebinding on every hop, including redirects), the content-type allow-list, and the size
/// cap — all fail closed (no fetch, no store).
/// </summary>
internal sealed class AvatarService
{
    private readonly IUserManager _userManager;
    private readonly IProviderManager _providerManager;
    private readonly IServerConfigurationManager _serverConfigurationManager;
    private readonly ILogger _logger;
    private readonly string _userAgent;

    internal AvatarService(
        IUserManager userManager,
        IProviderManager providerManager,
        IServerConfigurationManager serverConfigurationManager,
        ILogger logger,
        string userAgent)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _providerManager = providerManager ?? throw new ArgumentNullException(nameof(providerManager));
        _serverConfigurationManager = serverConfigurationManager ?? throw new ArgumentNullException(nameof(serverConfigurationManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _userAgent = userAgent ?? throw new ArgumentNullException(nameof(userAgent));
    }

    /// <summary>
    /// Fetches the avatar and sets it as the user's profile image. Best-effort: any fetch or save failure
    /// is logged and the caller proceeds without the avatar; only the URL guard and the SSRF-safe
    /// transport are security-relevant, and they fail closed (no fetch).
    /// </summary>
    /// <param name="user">The user whose profile image is set.</param>
    /// <param name="avatarUrl">The provider-supplied avatar URL, or null to skip.</param>
    /// <returns>A <see cref="Task"/> that completes when the avatar has been set or skipped.</returns>
    internal async Task TrySetAsync(User user, string avatarUrl)
    {
        if (avatarUrl is null)
        {
            return;
        }

        if (!AvatarUrlValidator.IsAllowedUrl(avatarUrl, out var avatarUri))
        {
            _logger.LogWarning("Refusing to fetch avatar from disallowed URL: {AvatarUrl}", avatarUrl.ReplaceLineEndings(string.Empty));
            return;
        }

        try
        {
            // Route every connection (including redirect targets) through a callback that rejects
            // private/loopback addresses, closing the SSRF and DNS-rebinding vectors. Redirects stay
            // enabled (many avatar URLs redirect) but are bounded, each hop is IP-validated, and both
            // the request and the download are bounded.
            using var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 5,
                ConnectCallback = ConnectCallback,

                // A system proxy would be the connection target, so the ConnectCallback would
                // validate the proxy's address rather than the avatar host's - bypassing the guard.
                UseProxy = false,
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            client.DefaultRequestHeaders.UserAgent.ParseAdd(_userAgent);

            // One deadline for the whole fetch: with ResponseHeadersRead the client Timeout stops
            // applying once the headers arrive, so a malicious endpoint could send headers immediately
            // then trickle the body forever. A single 10s token passed into GetAsync AND every body
            // ReadAsync bounds the header wait and the streamed read together, while keeping the
            // streaming size cap (#220).
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            // ResponseHeadersRead so the body is streamed, not fully buffered, before ReadCappedAsync
            // enforces the size limit; otherwise the cap runs only after the whole download is in memory.
            using var avatarResponse = await client.GetAsync(avatarUri, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            avatarResponse.EnsureSuccessStatusCode();

            // Media types are case-insensitive (RFC 7231); use the parsed type with parameters stripped.
            var mediaType = avatarResponse.Content.Headers.ContentType?.MediaType;

            // Allow only raster image types and derive the stored extension from that allow-list, never
            // from the raw subtype — image/svg+xml is rejected because a stored SVG can carry script (#217).
            if (!AvatarContentType.TryResolveExtension(mediaType, out var extension))
            {
                // Log the rejected type sanitized inline at the log call (mediaType is server-controlled),
                // and keep the thrown/caught exception message generic so no untrusted text reaches the
                // logged exception — mirrors the disallowed-URL warning above.
                _logger.LogWarning("Refusing avatar with disallowed content type: {MediaType}", (mediaType ?? "(none)").ReplaceLineEndings(string.Empty));
                throw new InvalidOperationException("Avatar content type is not an allowed raster image.");
            }

            const long MaxAvatarBytes = 10 * 1024 * 1024;
            if (avatarResponse.Content.Headers.ContentLength > MaxAvatarBytes)
            {
                throw new InvalidOperationException("Avatar exceeds the maximum allowed size.");
            }

            using var stream = await ReadCappedAsync(avatarResponse, MaxAvatarBytes, timeout.Token).ConfigureAwait(false);

            var userDataPath =
                Path.Combine(
                    _serverConfigurationManager.ApplicationPaths.UserConfigurationDirectoryPath,
                    user.Username);
            if (user.ProfileImage is not null)
            {
                await _userManager.ClearProfileImageAsync(user).ConfigureAwait(false);
            }

            user.ProfileImage = new ImageInfo(Path.Combine(userDataPath, "profile" + extension));

            await _providerManager.SaveImage(stream, mediaType, user.ProfileImage.Path)
                .ConfigureAwait(false);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to fetch or save the SSO avatar.");
        }
    }

    // Resolves the target host and connects only to a non-blocked (public) address, so a hostname that
    // resolves to an internal address - including via DNS rebinding on a redirect hop - cannot be reached.
    private static async ValueTask<Stream> ConnectCallback(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);

        // Try every non-blocked address in turn (a per-address connect fallback for dual-stack /
        // multi-record hosts, since supplying a ConnectCallback replaces the handler's built-in one),
        // connecting to the validated IP rather than the hostname so a DNS rebind cannot redirect the
        // connection to an internal address.
        Exception lastError = null;
        var attempted = false;
        foreach (var address in addresses)
        {
            if (AvatarUrlValidator.IsBlockedAddress(address))
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
                // Dispose unless ownership passed to the returned NetworkStream. Runs on the
                // cancellation path too, where the catch filter is skipped and the socket would leak.
                if (!connected)
                {
                    socket.Dispose();
                }
            }
        }

        if (attempted)
        {
            throw new HttpRequestException("Could not connect to any allowed address for the avatar host.", lastError);
        }

        throw new HttpRequestException("Avatar host resolves only to blocked addresses.");
    }

    // Copies the response body into memory, aborting if it exceeds the cap, so a hostile endpoint cannot
    // exhaust resources with an unbounded (or Content-Length-lying) download.
    private static async ValueTask<MemoryStream> ReadCappedAsync(HttpResponseMessage response, long maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new MemoryStream();
        var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (source.ConfigureAwait(false))
        {
            var chunk = new byte[81920];
            long total = 0;
            int read;
            while ((read = await source.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
            {
                total += read;
                if (total > maxBytes)
                {
                    await buffer.DisposeAsync().ConfigureAwait(false);
                    throw new InvalidOperationException("Avatar exceeds the maximum allowed size.");
                }

                await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }

        buffer.Position = 0;
        return buffer;
    }
}
