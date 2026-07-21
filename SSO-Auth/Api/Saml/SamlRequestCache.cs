#nullable enable

using System;
using System.Collections.Concurrent;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Tracks the IDs of SAML AuthnRequests this service provider has issued but not yet seen answered,
/// so a response's <c>InResponseTo</c> can be correlated to a request we actually sent (#156). A
/// response whose <c>InResponseTo</c> is unknown — unsolicited (IdP-initiated), replayed, or minted
/// for a different flow — is refused. Entries are time-pruned and hard-capped so an abandoned-login
/// flood cannot grow the cache without bound.
/// </summary>
internal sealed class SamlRequestCache
{
    // An approximate ceiling on outstanding entries. Registration is driven by the anonymous
    // challenge endpoint, so this bounds memory under an abandoned-login flood. The check-then-insert
    // is not serialized (that would put a lock on the anonymous hot path), so concurrent registers can
    // transiently overshoot by at most the number of in-flight threads — immaterial against a
    // best-effort DoS backstop. Given the short request lifetime, real load never approaches it;
    // rate-limiting at the edge (#128) is the primary defense.

    /// <summary>The production ceiling on outstanding AuthnRequest entries; at the cap a fresh challenge is refused, never an in-flight entry evicted.</summary>
    internal const int DefaultMaxEntries = 100_000;

    // Expired-entry sweeping is throttled to at most once per this interval. The sweep is an O(n)
    // scan; running it on every anonymous challenge would amplify a flood into CPU load. Throttling
    // is safe because it is only memory reclamation — TryConsume independently rejects an expired
    // entry via its own expiry check, so a not-yet-swept entry never grants a login.
    private static readonly TimeSpan DefaultPruneInterval = TimeSpan.FromMinutes(1);

    private readonly int _maxEntries;

    private readonly ConcurrentDictionary<string, Entry> _outstanding = new(StringComparer.Ordinal);

    // Throttles the sweep to one run per prune interval; the gate owns the atomic cursor and self-heals
    // a backward wall-clock step of at least the interval (re-anchors), while a sub-interval backward step
    // is a stale sample suppressed with the cursor untouched (#334) — either way it never stalls until the
    // clock re-passes its cursor the way the hand-rolled predecessor did. See PruneExpired.
    private readonly IntervalGate _pruneGate;

    // Throttles the capacity-full warning to one signal per interval (CWE-400): under a flood every
    // refused registration would otherwise emit a warning, amplifying the flood into unbounded log
    // volume. Mirrors OidcStateStore so the SAML refusal has the same observability (#327 review).
    private readonly IntervalGate _capWarnGate;

    // Per-client occupancy sub-cap (#327): bounds how much of the global budget one client key can hold,
    // so a single anonymous source cannot fill the cache and deny every other login's callback.
    private readonly PerClientBudgetLimiter _perClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlRequestCache"/> class with the production cap and
    /// prune interval.
    /// </summary>
    internal SamlRequestCache()
        : this(DefaultMaxEntries, DefaultPruneInterval)
    {
    }

    // Test constructor: a small cap makes the global-cap and per-client sub-cap paths reachable in unit
    // tests (the production values are unreachable there).

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlRequestCache"/> class with explicit bounds, so a
    /// unit test can reach the global-cap and per-client sub-cap paths the production values make unreachable.
    /// </summary>
    /// <param name="maxEntries">The global ceiling on outstanding entries.</param>
    /// <param name="pruneInterval">The minimum interval between expired-entry sweeps.</param>
    internal SamlRequestCache(int maxEntries, TimeSpan pruneInterval)
    {
        _maxEntries = maxEntries;
        _pruneGate = new IntervalGate(pruneInterval);
        _capWarnGate = new IntervalGate(pruneInterval);
        _perClient = PerClientBudgetLimiter.FromGlobalCap(maxEntries);
    }

    /// <summary>Gets the live entry count. Test-only, like Clear.</summary>
    internal int Count => _outstanding.Count;

    /// <summary>
    /// Records an issued request ID as outstanding until <paramref name="expiryUtc"/>, together with the
    /// browser-binding id minted for it at the challenge (#415). A blank ID is ignored (the correlation
    /// at consume time then fails closed).
    /// </summary>
    /// <param name="requestId">The request ID (scoped by the caller, e.g. by provider).</param>
    /// <param name="bindingId">The browser-binding id set as a cookie at the challenge (may be empty).</param>
    /// <param name="expiryUtc">When the entry may be evicted (the request's validity horizon).</param>
    /// <param name="nowUtc">The current time.</param>
    /// <param name="clientKey">The normalized client key for the per-client sub-cap (#327), or null to exempt.</param>
    /// <param name="shouldWarnCapacity">True when the caller should emit the throttled capacity warning (a cap refusal, at most once per interval).</param>
    /// <returns>True if the entry was registered; false if refused (blank ID, per-client sub-cap, or global cap).</returns>
    internal bool Register(string? requestId, string bindingId, DateTime expiryUtc, DateTime nowUtc, string? clientKey, out bool shouldWarnCapacity)
    {
        PruneExpired(nowUtc);
        shouldWarnCapacity = false;
        if (string.IsNullOrEmpty(requestId))
        {
            return false;
        }

        // Per-client sub-cap (#327): reserve before the global insert so one source cannot fill the
        // cache and lock out everyone. A null key is exempt (the shared proxy/private-source bucket).
        if (!_perClient.TryReserve(clientKey))
        {
            shouldWarnCapacity = _capWarnGate.TryEnter(nowUtc);
            return false;
        }

        // At the cap, refuse the NEW registration rather than evicting an existing one: a flood of
        // fresh challenges must not displace a user already mid-login (whose entry we would otherwise
        // drop, failing their callback). A refused challenge simply won't correlate — that one login
        // fails closed. TryAdd (not the indexer) also refuses a DUPLICATE id, so this rollback stays
        // leak-free even if two registrations of the same CSPRNG id ever raced (the loser's TryAdd
        // fails and releases its reservation); request ids are fresh, so a real duplicate never occurs.
        if ((_outstanding.Count >= _maxEntries && !_outstanding.ContainsKey(requestId))
            || !_outstanding.TryAdd(requestId, new Entry(expiryUtc, bindingId ?? string.Empty, clientKey)))
        {
            _perClient.Release(clientKey);
            shouldWarnCapacity = _capWarnGate.TryEnter(nowUtc);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Atomically claims an outstanding request ID: succeeds once for a known, unexpired ID, then the
    /// entry is gone so a second response carrying the same <c>InResponseTo</c> is refused. Fails for a
    /// blank, unknown, expired, or already-consumed ID (fail closed). On success, yields the
    /// browser-binding id registered with it so the caller can enforce the binding (#415).
    /// </summary>
    /// <param name="requestId">The response's <c>InResponseTo</c>, scoped the same way as at registration.</param>
    /// <param name="nowUtc">The current time.</param>
    /// <param name="bindingId">The binding id recorded at registration (empty if none), when this returns true.</param>
    /// <returns>True if the ID was outstanding and is now consumed; false otherwise.</returns>
    internal bool TryConsume(string? requestId, DateTime nowUtc, out string bindingId)
    {
        PruneExpired(nowUtc);
        bindingId = string.Empty;
        if (string.IsNullOrEmpty(requestId))
        {
            return false;
        }

        if (_outstanding.TryRemove(requestId, out var entry))
        {
            // The slot is freed whether or not the entry was still valid — release on any successful
            // removal (the single winner of TryRemove), so the client's sub-cap slot never leaks (#327).
            _perClient.Release(entry.ClientKey);
            if (entry.ExpiryUtc > nowUtc)
            {
                bindingId = entry.BindingId;
                return true;
            }
        }

        return false;
    }

    /// <summary>Test-only: drops all outstanding entries so process-wide state cannot leak between tests.</summary>
    internal void Clear()
    {
        _outstanding.Clear();
        _perClient.Clear();
    }

    // Drops expired entries, at most once per PruneInterval. Enumerating a ConcurrentDictionary yields
    // a safe moving snapshot and TryRemove is atomic, so this is correct under concurrent
    // Register/TryConsume — unlike a buffering LINQ operator (OrderBy/ToArray built via
    // ICollection.CopyTo), which can throw when the dictionary grows mid-copy. Size is bounded by the
    // registration cap, not by eviction here.
    private void PruneExpired(DateTime nowUtc)
    {
        if (!_pruneGate.TryEnter(nowUtc))
        {
            return;
        }

        foreach (var kvp in _outstanding)
        {
            // Release only on the winning removal (out overload) so a concurrent consume does not
            // double-release the client's slot (#327).
            if (kvp.Value.ExpiryUtc <= nowUtc && _outstanding.TryRemove(kvp.Key, out var removed))
            {
                _perClient.Release(removed.ClientKey);
            }
        }
    }

    // One outstanding AuthnRequest: when it expires, the browser-binding id minted alongside it at the
    // challenge (#415), and the client key that reserved its per-client budget slot (#327, null for an
    // exempt source). The binding id ties the eventual response to the browser that started the flow; it
    // is returned on consume so the session-mint endpoint can require the request's cookie to match.
    // Empty binding for entries registered before browser binding existed (treated as unbound).
    private readonly record struct Entry(DateTime ExpiryUtc, string BindingId, string? ClientKey);
}
