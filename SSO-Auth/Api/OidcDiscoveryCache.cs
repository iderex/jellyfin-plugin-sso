using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Owns the per-discovery-URL cache of the two OpenID facts the challenge reads from a provider's
/// discovery document in a single fetch — whether the authorization server advertises PKCE (S256)
/// (#141, RFC 9700 §2.1.1) and whether it advertises the RFC 9207 response-<c>iss</c> parameter (#210) —
/// together with the fetch/parse that populates it. Extracted off <see cref="SSOController"/> so the
/// discovery-fetch/parse/cache logic lives in one testable place (#318, #449).
///
/// Bounding: the cache key is the admin-configured provider authority's resolved discovery URL, so the
/// number of distinct keys equals the number of configured OpenID providers — a small, operator-set
/// bound, never attacker-supplied. Unlike the anonymous-flood-facing login caches
/// (<see cref="OidcStateStore"/>, <see cref="SamlRequestCache"/>, which key on CSPRNG tokens), it needs
/// no hard cap or throttled expired-entry sweep: a stale entry is simply re-fetched and overwritten in
/// place once its short TTL elapses, so the map never holds more than one entry per provider. Only a
/// successful fetch is cached, so a transient failure retries on the next login rather than pinning a
/// tolerant default.
/// </summary>
internal sealed class OidcDiscoveryCache
{
    // How long a cached entry is served before it is re-fetched. The discovery document changes rarely,
    // so a login does not re-fetch it every time; the short window bounds how long a provider's changed
    // metadata stays stale.
    internal static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(15);

    // Concurrent logins read and refresh this map, so a plain Dictionary would corrupt under the
    // interleaving. Keyed by the resolved discovery URL with the default (ordinal) comparer — stated
    // explicitly so the ordinal URL matching is visible. The stored FetchedAt drives the TTL check.
    private readonly ConcurrentDictionary<string, Entry> _facts = new(StringComparer.Ordinal);

    private readonly TimeSpan _ttl;

    internal OidcDiscoveryCache()
        : this(DefaultTtl)
    {
    }

    // Test constructor: a short TTL makes the staleness/re-fetch path reachable without real time passing.
    internal OidcDiscoveryCache(TimeSpan ttl)
    {
        _ttl = ttl;
    }

    /// <summary>
    /// Returns the discovery facts for a provider, serving a still-fresh cached entry when one exists and
    /// otherwise fetching + parsing the discovery document (the admin-configured authority + the
    /// well-known path, the same document OidcClient uses). The fetch is bounded by a timeout and never
    /// throws — a transient failure returns the tolerant default <c>(null, false)</c> WITHOUT caching it,
    /// so the caller decides (PKCE fails closed only under <c>RequirePkce</c>; response-<c>iss</c> stays
    /// optional) and the next login retries. Best-effort: it does not replace OidcClient's own discovery,
    /// which fails the login if the provider is truly down.
    /// </summary>
    /// <param name="config">The provider config whose <c>OidEndpoint</c> resolves to the discovery URL.</param>
    /// <param name="provider">The provider name, for the fetch-failure warning only.</param>
    /// <param name="httpClientFactory">The shared HTTP client factory the outbound fetch is built over.</param>
    /// <param name="logger">The logger for the tolerant fetch-failure warning.</param>
    /// <returns>The discovery facts (a cache hit, a fresh fetch, or the tolerant default on failure).</returns>
    internal async Task<DiscoveryFacts> ReadFactsAsync(OidConfig config, string provider, IHttpClientFactory httpClientFactory, ILogger logger)
    {
        var authority = config.OidEndpoint?.Trim();
        if (string.IsNullOrEmpty(authority) || !Uri.TryCreate(authority, UriKind.Absolute, out _))
        {
            return new DiscoveryFacts(null, false);
        }

        // OidEndpoint is usually the issuer/authority, but some providers (e.g. PocketID) configure the
        // full .well-known URL; append the discovery path only when it is not already present, matching
        // how OidcClient resolves the same document.
        var trimmed = authority.TrimEnd('/');
        var discoveryUrl = trimmed.EndsWith("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase)
            ? trimmed
            : trimmed + "/.well-known/openid-configuration";

        if (_facts.TryGetValue(discoveryUrl, out var cached) && DateTime.UtcNow - cached.FetchedAt < _ttl)
        {
            return new DiscoveryFacts(cached.PkceS256, cached.ResponseIssuerAdvertised);
        }

        try
        {
            using var client = SsoHttp.CreateClient(httpClientFactory);
            client.Timeout = TimeSpan.FromSeconds(10);
            var json = await client.GetStringAsync(discoveryUrl).ConfigureAwait(false);
            var pkceS256 = PkceDiscovery.SupportsS256(json);
            var responseIssuerAdvertised = OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(json);
            _facts[discoveryUrl] = new Entry(pkceS256, responseIssuerAdvertised, DateTime.UtcNow);
            return new DiscoveryFacts(pkceS256, responseIssuerAdvertised);
        }
        catch (Exception e)
        {
            // The provider name is stripped of line endings inline at the log call so an admin-supplied
            // value cannot forge or split the entry (the log-forging sanitizer never crosses a helper
            // boundary).
            logger.LogWarning(
                e,
                "Could not fetch the OpenID discovery document for provider {Provider} to verify PKCE support; proceeding unless RequirePkce is set.",
                provider?.ReplaceLineEndings(string.Empty));
            return new DiscoveryFacts(null, false);
        }
    }

    /// <summary>Test-only: drops every cached entry so process-wide state cannot leak between tests.</summary>
    internal void Clear() => _facts.Clear();

    // One cached provider's discovery facts and when they were fetched. PkceS256 is stored non-nullable
    // because only a definitive fetch result is ever cached — a failure returns the tolerant default and
    // is not stored, so a cache hit always carries a real answer.
    private readonly record struct Entry(bool PkceS256, bool ResponseIssuerAdvertised, DateTime FetchedAt);
}
