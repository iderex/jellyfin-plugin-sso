using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Api.RateLimit;

/// <summary>
/// A per-client occupancy sub-cap shared by the in-flight state stores (#327). Each store owns one
/// instance, calls <see cref="TryReserve"/> before it inserts an entry and <see cref="Release"/> on
/// every removal, so one client key can hold at most its per-key share of the store's global cap.
/// This is the availability defense: without it a single anonymous source could fill the whole global
/// budget with unredeemed in-flight state and, because the stores refuse-at-cap rather than evict,
/// lock out every other login. Distinct from <see cref="SsoRateLimiter"/>: that bounds request RATE
/// over a time window; this bounds concurrent OCCUPANCY of a store and is not time-aware. The
/// check-and-increment is a single CAS, so a per-key count can never race past the cap (tighter than
/// the stores' own accepted check-then-insert overshoot), with no lock on the anonymous hot path.
/// </summary>
internal sealed class PerClientBudgetLimiter
{
    // One source may hold at most this fraction of the store's global cap: 1/100, so it takes >=100
    // distinct attributable public sources to exhaust the budget and no single one can lock out logins,
    // while >=99% stays free for everyone else. A constant, not config — a login-path safety limit whose
    // mis-set value would itself be a lockout (too low) or a no-op (too high).

    /// <summary>The reciprocal of one client's share of the global cap (1/100): it takes at least this many distinct sources to exhaust the budget, and no single one can lock out logins.</summary>
    internal const int ShareDivisor = 100;

    // clientKey -> live reservations; a key is present only while it holds >=1 (dropped at zero), so
    // |_counts| <= live entries <= the store's global cap even under an IPv6 key-rotation flood. Ordinal:
    // the key is an opaque normalized token from SsoRateLimiter.NormalizeClientKey.
    private readonly ConcurrentDictionary<string, int> _counts = new(StringComparer.Ordinal);
    private readonly int _perKeyCap;

    /// <summary>
    /// Initializes a new instance of the <see cref="PerClientBudgetLimiter"/> class with an explicit
    /// per-key cap. Most callers use <see cref="FromGlobalCap"/> so the 1/100 policy lives in one place.
    /// </summary>
    /// <param name="perKeyCap">The maximum concurrent reservations a single client key may hold.</param>
    internal PerClientBudgetLimiter(int perKeyCap) => _perKeyCap = perKeyCap;

    /// <summary>Gets the derived per-key cap. Test-only.</summary>
    internal int PerKeyCap => _perKeyCap;

    /// <summary>Gets the number of tracked (live) client keys. Test-only.</summary>
    internal int TrackedKeys => _counts.Count;

    /// <summary>
    /// Derives a limiter whose per-key share is <see cref="ShareDivisor"/>-th of a store's global cap,
    /// so the 1/100 policy lives in one place and a small test cap still yields a reachable sub-cap.
    /// </summary>
    /// <param name="globalCap">The owning store's global entry cap.</param>
    /// <returns>A limiter capped at <c>max(1, globalCap / 100)</c> per client key.</returns>
    internal static PerClientBudgetLimiter FromGlobalCap(int globalCap) =>
        new(Math.Max(1, globalCap / ShareDivisor));

    /// <summary>
    /// Reserves one slot for <paramref name="clientKey"/>, or false when it already holds its full share
    /// (fail closed for that one login). A null key is unattributable — loopback/RFC1918/CGNAT/link-local,
    /// or a reverse proxy whose forwarded headers Jellyfin was not told to resolve (the socket peer is the
    /// proxy's private IP) — i.e. the whole userbase behind one bucket, so it is EXEMPT (always reserves,
    /// never counted); per-client-capping it would re-introduce the mass lockout #327 forbids. The exempt
    /// bucket is still bounded by the store's global cap.
    /// </summary>
    /// <param name="clientKey">The normalized client key, or null for an unattributable/exempt source.</param>
    /// <returns>True if a slot was reserved (or the key is exempt); false when the key is at its share.</returns>
    internal bool TryReserve(string? clientKey)
    {
        if (clientKey is null)
        {
            return true;
        }

        while (true)
        {
            if (_counts.TryGetValue(clientKey, out var n))
            {
                if (n >= _perKeyCap)
                {
                    return false;
                }

                // Cap-check and increment as one atom: a concurrent increment changes n, the CAS fails,
                // we re-read — so two threads at cap-1 can never both cross the cap (zero overshoot).
                if (_counts.TryUpdate(clientKey, n + 1, n))
                {
                    return true;
                }
            }
            else if (_counts.TryAdd(clientKey, 1))
            {
                return true;
            }

            // Lost a race for this key — re-read and retry. Lock-free, O(1) amortized, never scans a store.
        }
    }

    /// <summary>
    /// Releases one slot previously reserved for <paramref name="clientKey"/>. Idempotent and never
    /// negative: an unknown key is a no-op, and the bucket is dropped at zero so the map stays bounded.
    /// A null key reserved nothing, so it releases nothing. MUST be called exactly once per successful
    /// reservation, on the single winner of the store's atomic removal — a double release would
    /// under-count and let the bucket admit past its cap.
    /// </summary>
    /// <param name="clientKey">The client key whose slot is freed, or null (a no-op).</param>
    internal void Release(string? clientKey)
    {
        if (clientKey is null)
        {
            return;
        }

        while (true)
        {
            if (!_counts.TryGetValue(clientKey, out var n))
            {
                return;
            }

            if (n <= 1)
            {
                // Drop the empty bucket. The KVP-conditional remove aborts if a concurrent reserve just
                // bumped n, so a live bucket is never deleted; we loop and decrement instead.
                if (_counts.TryRemove(new KeyValuePair<string, int>(clientKey, n)))
                {
                    return;
                }
            }
            else if (_counts.TryUpdate(clientKey, n - 1, n))
            {
                return;
            }
        }
    }

    /// <summary>Test-only: drops all counts, mirroring the owning store's Clear.</summary>
    internal void Clear() => _counts.Clear();
}
