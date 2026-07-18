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
    /// <summary>The maximum avatar size accepted, enforced both against Content-Length and while streaming (#220).</summary>
    internal const long MaxAvatarBytes = 10 * 1024 * 1024;

    // Serializes the store step per user across ALL logins (#400). Static because the controller builds a
    // fresh AvatarService per request, so two concurrent same-user logins hold different instances — an
    // instance lock would not serialize them. Keyed by user, so unrelated users never block each other,
    // and collectible, so the map cannot leak a semaphore per username ever seen. Ordinal because the key
    // is exactly the profile-path determinant (Path.Combine on user.Username below).
    private static readonly KeyedLockStore SharedUserStoreLocks = new KeyedLockStore(StringComparer.Ordinal);

    // One process-wide HTTP stack reused across every login (#248). Static for the same reason the store
    // lock is: the controller builds a fresh AvatarService per request, so a per-instance client would
    // open a new connection pool — a full TCP+TLS handshake — on every login. The single shared client
    // keeps its pool warm across logins while the hardened handler's guards (SSRF ConnectCallback, redirect
    // bound, proxy-off) are unchanged; PooledConnectionLifetime bounds how long a pooled connection lives
    // so DNS changes are still eventually honored despite the reuse. Thread-safe: concurrent logins call
    // SendAsync with their own HttpRequestMessage (User-Agent and If-Modified-Since live on the request,
    // not on the shared client's mutable DefaultRequestHeaders).
    private static readonly HttpClient SharedClient = CreateHardenedClient();

    private readonly IUserManager _userManager;
    private readonly IProviderManager _providerManager;
    private readonly IServerConfigurationManager _serverConfigurationManager;
    private readonly ILogger _logger;
    private readonly string _userAgent;
    private readonly HttpClient _httpClient;
    private readonly KeyedLockStore _userStoreLocks;

    internal AvatarService(
        IUserManager userManager,
        IProviderManager providerManager,
        IServerConfigurationManager serverConfigurationManager,
        ILogger logger,
        string userAgent)
        : this(userManager, providerManager, serverConfigurationManager, logger, userAgent, SharedClient)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AvatarService"/> class with an injected
    /// <see cref="HttpClient"/>. This is the test seam (#385): a client wrapping a stub handler makes the
    /// content-type gate, the size cap, the happy path, the conditional 304, and the timeout reachable
    /// without live HTTP. Production uses the five-argument constructor, which supplies the process-wide
    /// shared client built on the hardened SSRF-safe <see cref="SocketsHttpHandler"/>.
    /// </summary>
    /// <param name="userManager">The Jellyfin user manager.</param>
    /// <param name="providerManager">The Jellyfin provider manager (image saving).</param>
    /// <param name="serverConfigurationManager">The server configuration manager (user data paths).</param>
    /// <param name="logger">The logger.</param>
    /// <param name="userAgent">The outbound User-Agent.</param>
    /// <param name="httpClient">The client used for every fetch; reused across calls (never disposed here).</param>
    /// <param name="userStoreLocks">The per-user store lock (#400); null uses the process-wide shared one. A test injects its own so it can drive the serialization deterministically.</param>
    internal AvatarService(
        IUserManager userManager,
        IProviderManager providerManager,
        IServerConfigurationManager serverConfigurationManager,
        ILogger logger,
        string userAgent,
        HttpClient httpClient,
        KeyedLockStore userStoreLocks = null)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _providerManager = providerManager ?? throw new ArgumentNullException(nameof(providerManager));
        _serverConfigurationManager = serverConfigurationManager ?? throw new ArgumentNullException(nameof(serverConfigurationManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _userAgent = userAgent ?? throw new ArgumentNullException(nameof(userAgent));
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _userStoreLocks = userStoreLocks ?? SharedUserStoreLocks;
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
            // One deadline for the whole fetch: with ResponseHeadersRead the client Timeout stops
            // applying once the headers arrive, so a malicious endpoint could send headers immediately
            // then trickle the body forever. A single 10s token passed into SendAsync AND every body
            // ReadAsync bounds the header wait and the streamed read together, while keeping the
            // streaming size cap (#220).
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            using var request = new HttpRequestMessage(HttpMethod.Get, avatarUri);
            request.Headers.UserAgent.ParseAdd(_userAgent);

            // Conditional refresh (#248): when we already hold this user's avatar, ask the origin to send
            // fresh bytes only if the image changed since we last stored it. If-Modified-Since carries the
            // timestamp of our last store (ProfileImage.LastModified) — exactly "when we last fetched this
            // representation" — so an unchanged avatar answers 304 and we skip the re-download AND the
            // re-store entirely; only a changed image (200) is fetched and re-stored. An origin that ignores
            // the header just answers 200 as before, so this degrades safely to the old always-download.
            // SpecifyKind(Utc) makes the DateTimeOffset construction total regardless of the stored Kind;
            // ProfileImage.LastModified is already written as DateTime.UtcNow, so no time is shifted.
            if (user.ProfileImage?.LastModified is { } lastStored && lastStored > DateTime.MinValue)
            {
                request.Headers.IfModifiedSince = new DateTimeOffset(DateTime.SpecifyKind(lastStored, DateTimeKind.Utc));
            }

            // ResponseHeadersRead so the body is streamed, not fully buffered, before ReadCappedAsync
            // enforces the size limit; otherwise the cap runs only after the whole download is in memory.
            using var avatarResponse = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);

            // 304: the image is unchanged since our last store — keep the existing profile image, fetch and
            // store nothing, and deliberately do NOT advance ProfileImage.LastModified (it stays the anchor
            // for the next login's If-Modified-Since; refreshing it here would defeat the conditional). Checked
            // before EnsureSuccessStatusCode, which treats 304 as a non-success throw.
            if (avatarResponse.StatusCode == HttpStatusCode.NotModified)
            {
                return;
            }

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

            if (avatarResponse.Content.Headers.ContentLength > MaxAvatarBytes)
            {
                throw new InvalidOperationException("Avatar exceeds the maximum allowed size.");
            }

            using var stream = await ReadCappedAsync(avatarResponse, MaxAvatarBytes, timeout.Token).ConfigureAwait(false);

            await StoreAsync(user, stream, mediaType, extension).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to fetch or save the SSO avatar.");
        }
    }

    /// <summary>
    /// Writes the fetched avatar to disk and only then updates the user's profile-image reference, so a
    /// failed save leaves the previous profile-image record intact instead of a cleared record pointing
    /// at a never-written path (#377). (When the target path is unchanged the host writes the file in
    /// place, so a mid-write failure can still truncate the bytes — that is ImageSaver's contract, not
    /// ours to fix.) Throws on save failure; <see cref="TrySetAsync"/>'s best-effort catch owns the logging.
    /// </summary>
    /// <param name="user">The user whose profile image is set.</param>
    /// <param name="image">The fetched avatar bytes.</param>
    /// <param name="mediaType">The validated image media type.</param>
    /// <param name="extension">The stored extension resolved from the content-type allow-list.</param>
    /// <returns>A <see cref="Task"/> that completes when the avatar is stored and the user updated.</returns>
    internal async Task StoreAsync(User user, Stream image, string mediaType, string extension)
    {
        // Serialize the whole write-and-transition against other logins for THIS user (#400): two
        // concurrent stores must not interleave the SaveImage + profile-image check/clear/assign, or one
        // can clear or overwrite the other's record. The lock spans only the store; the HTTP fetch runs
        // before this call (in TrySetAsync), so a slow endpoint never holds the per-user gate. Keyed by
        // user, so unrelated users never wait on each other.
        using (await _userStoreLocks.AcquireAsync(user.Username, CancellationToken.None).ConfigureAwait(false))
        {
            await StoreLockedAsync(user, image, mediaType, extension).ConfigureAwait(false);
        }
    }

    // The store sequence proper, run under the per-user lock (#400). Extracted so the lock acquisition
    // reads as one guarded block and the write -> transition ordering (#377) stays a single unit.
    private async Task StoreLockedAsync(User user, Stream image, string mediaType, string extension)
    {
        var root = _serverConfigurationManager.ApplicationPaths.UserConfigurationDirectoryPath;

        // The profile path's middle component is user.Username, which for an SSO login is IdP-controlled
        // (OIDC preferred_username / SAML NameID). The only host-side check is CreateUserAsync's username
        // regex ^(?!\s)[\w \-'._@+]+(?<!\s)$ — which the plugin cannot even reference (it lives in the
        // server, off the Controller/Model surface) and which ADMITS '.' and '..' (#447). A username of
        // ".." makes Path.Combine write the fetched image into the PARENT of the user-config directory.
        // Treat the username as untrusted and fail closed: an unsafe component skips the avatar entirely.
        // The store is best-effort, so login still succeeds with no avatar — we never throw from here.
        if (!IsUsernameSafeForProfilePath(root, user.Username))
        {
            _logger.LogWarning(
                "Refusing to store the SSO avatar: username is not a safe path component: {Username}",
                user.Username?.ReplaceLineEndings(string.Empty));
            return;
        }

        var newPath = Path.Combine(root, user.Username, "profile" + extension);

        // The write comes FIRST: if it throws, nothing below runs, so the user keeps the previous
        // profile-image record instead of a cleared record plus a dangling path to a file that was
        // never written.
        await _providerManager.SaveImage(image, mediaType, newPath).ConfigureAwait(false);

        if (user.ProfileImage is null)
        {
            user.ProfileImage = new ImageInfo(newPath);
        }
        else if (string.Equals(user.ProfileImage.Path, newPath, StringComparison.Ordinal))
        {
            // Same target file (the common same-extension re-login), just overwritten in place: the
            // record is already correct, so clearing it (which removes only the DB row — the host's
            // ClearProfileImageAsync does not touch the file) would drop and re-insert it for nothing.
            // Keep the record and refresh the timestamp so clients re-fetch the changed image.
            user.ProfileImage.LastModified = DateTime.UtcNow;
        }
        else
        {
            // The content type (and so the stored path) changed: drop the old RECORD only now that the
            // new bytes are safely on disk, then point the user at them. The old file stays on disk —
            // ClearProfileImageAsync removes just the DB row, the same residue Jellyfin's own image
            // replace leaves behind.
            await _userManager.ClearProfileImageAsync(user).ConfigureAwait(false);
            user.ProfileImage = new ImageInfo(newPath);
        }
    }

    // Fail-closed guard for the IdP-controlled profile-path component (#447). The username must be a single
    // safe path component that resolves to exactly the intended per-user directory. Two independent layers:
    // (1) a character check that rejects '.'/'..', either separator, and any invalid file-name char on every
    // platform (GetInvalidFileNameChars excludes '\' on Linux, so both separators are rejected explicitly);
    // (2) belt-and-suspenders, an exact round-trip check — Path.GetFullPath(root/username) must equal
    // root/username with nothing normalized away. That keeps the write under the root AND rejects platform
    // tricks the character check can't see: Windows silently strips trailing dots/spaces, so "victim." would
    // otherwise fold onto another user's "victim" directory (an in-root cross-user overwrite), and an
    // absolute/drive-relative/device form would resolve elsewhere. Returns false (skip the avatar) rather
    // than throwing, so the best-effort store never affects login.
    private static bool IsUsernameSafeForProfilePath(string root, string username)
    {
        if (string.IsNullOrEmpty(username)
            || string.Equals(username, ".", StringComparison.Ordinal)
            || string.Equals(username, "..", StringComparison.Ordinal)
            || username.Contains('/')
            || username.Contains('\\')
            || username.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            return false;
        }

        string fullRoot;
        string fullCandidate;
        try
        {
            fullRoot = Path.GetFullPath(root);
            fullCandidate = Path.GetFullPath(Path.Combine(root, username));
        }
        catch (Exception e) when (e is ArgumentException or IOException or NotSupportedException)
        {
            // The path could not be resolved (e.g. an over-long component) — not provably the intended
            // directory, so fail closed rather than trust it. Never let this bubble into the login path.
            return false;
        }

        // Require the resolved path to be EXACTLY <root>/<username> (case-insensitively on Windows, where
        // the filesystem is): any normalization the OS applied means the on-disk target is not the literal
        // per-user directory we intended, so reject it.
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return string.Equals(fullCandidate, Path.Combine(fullRoot, username), comparison);
    }

    // The process-wide shared client (#248): one hardened handler + one connection pool for the whole
    // process, reused across every login instead of rebuilt per fetch. Timeout stays 10s; because the
    // fetch uses ResponseHeadersRead the per-request CancellationTokenSource is the real end-to-end
    // deadline (see TrySetAsync), so this Timeout bounds only connect + header wait. Never disposed —
    // it lives for the process, the intended lifetime of a shared HttpClient.
    private static HttpClient CreateHardenedClient() =>
        new HttpClient(CreateHardenedHandler(), disposeHandler: true) { Timeout = TimeSpan.FromSeconds(10) };

    // The production handler: routes every connection (including redirect targets) through a callback
    // that rejects private/loopback addresses, closing the SSRF and DNS-rebinding vectors. Redirects
    // stay enabled (many avatar URLs redirect) but are bounded, each hop is IP-validated, and both the
    // request and the download are bounded. Built once for the shared client above.
    private static SocketsHttpHandler CreateHardenedHandler() => new SocketsHttpHandler
    {
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 5,
        ConnectCallback = ConnectToAllowedAddressAsync,

        // A system proxy would be the connection target, so the connect callback would validate the
        // proxy's address rather than the avatar host's - bypassing the guard.
        UseProxy = false,

        // The handler is reused across logins, so bound how long a pooled connection lives — after this
        // the connection is recycled and the host re-resolved, so DNS changes are honored despite reuse.
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
    };

    // Resolves the target host and connects only to a non-blocked (public) address, so a hostname that
    // resolves to an internal address - including via DNS rebinding on a redirect hop - cannot be reached.
    private static async ValueTask<Stream> ConnectToAllowedAddressAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
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
    // exhaust resources with an unbounded (or Content-Length-lying) download. Internal so the streamed
    // size cap (#220) — the most security-relevant branch — is unit-testable over a StreamContent body
    // without live HTTP (#385).
    internal static async ValueTask<MemoryStream> ReadCappedAsync(HttpResponseMessage response, long maxBytes, CancellationToken cancellationToken)
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
