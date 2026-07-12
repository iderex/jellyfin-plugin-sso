using System;
using System.Collections.Concurrent;
using System.Threading;

namespace Jellyfin.Plugin.SSO_Auth.Api;

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
    private const int MaxEntries = 100_000;

    // Expired-entry sweeping is throttled to at most once per this interval. The sweep is an O(n)
    // scan; running it on every anonymous challenge would amplify a flood into CPU load. Throttling
    // is safe because it is only memory reclamation — TryConsume independently rejects an expired
    // entry via its own expiry check, so a not-yet-swept entry never grants a login.
    private static readonly TimeSpan PruneInterval = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, DateTime> _outstanding = new(StringComparer.Ordinal);

    // Last sweep time as ticks, read/written atomically (DateTime is not torn-read-safe).
    private long _lastPruneTicks = DateTime.MinValue.Ticks;

    /// <summary>
    /// Records an issued request ID as outstanding until <paramref name="expiryUtc"/>. A blank ID is
    /// ignored (the correlation at consume time then fails closed).
    /// </summary>
    /// <param name="requestId">The request ID (scoped by the caller, e.g. by provider).</param>
    /// <param name="expiryUtc">When the entry may be evicted (the request's validity horizon).</param>
    /// <param name="nowUtc">The current time.</param>
    internal void Register(string requestId, DateTime expiryUtc, DateTime nowUtc)
    {
        PruneExpired(nowUtc);
        if (string.IsNullOrEmpty(requestId))
        {
            return;
        }

        // At the cap, refuse the NEW registration rather than evicting an existing one: a flood of
        // fresh challenges must not displace a user already mid-login (whose entry we would otherwise
        // drop, failing their callback). A refused challenge simply won't correlate — that one login
        // fails closed, which under a flood is overwhelmingly attacker traffic. Overwriting an
        // already-present key (a re-registered id) stays allowed.
        if (_outstanding.Count >= MaxEntries && !_outstanding.ContainsKey(requestId))
        {
            return;
        }

        _outstanding[requestId] = expiryUtc;
    }

    /// <summary>
    /// Atomically claims an outstanding request ID: succeeds once for a known, unexpired ID, then the
    /// entry is gone so a second response carrying the same <c>InResponseTo</c> is refused. Fails for a
    /// blank, unknown, expired, or already-consumed ID (fail closed).
    /// </summary>
    /// <param name="requestId">The response's <c>InResponseTo</c>, scoped the same way as at registration.</param>
    /// <param name="nowUtc">The current time.</param>
    /// <returns>True if the ID was outstanding and is now consumed; false otherwise.</returns>
    internal bool TryConsume(string requestId, DateTime nowUtc)
    {
        PruneExpired(nowUtc);
        if (string.IsNullOrEmpty(requestId))
        {
            return false;
        }

        return _outstanding.TryRemove(requestId, out var expiry) && expiry > nowUtc;
    }

    // Drops expired entries, at most once per PruneInterval. Enumerating a ConcurrentDictionary yields
    // a safe moving snapshot and TryRemove is atomic, so this is correct under concurrent
    // Register/TryConsume — unlike a buffering LINQ operator (OrderBy/ToArray built via
    // ICollection.CopyTo), which can throw when the dictionary grows mid-copy. Size is bounded by the
    // registration cap, not by eviction here.
    private void PruneExpired(DateTime nowUtc)
    {
        var last = Interlocked.Read(ref _lastPruneTicks);
        if (nowUtc.Ticks - last < PruneInterval.Ticks)
        {
            return;
        }

        // Only one thread should run the sweep per interval; the winner of the CAS does it.
        if (Interlocked.CompareExchange(ref _lastPruneTicks, nowUtc.Ticks, last) != last)
        {
            return;
        }

        foreach (var kvp in _outstanding)
        {
            if (kvp.Value <= nowUtc)
            {
                _outstanding.TryRemove(kvp.Key, out _);
            }
        }
    }
}
