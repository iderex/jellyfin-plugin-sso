using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Opt-in fixed-window rate limiter for the anonymous SSO flow endpoints (#128), keyed on the
/// attributed client address. Availability-first: an unattributable client, a full table, or a
/// disabled limiter never throttles (fail open) — throttling is a best-effort defense in depth on
/// top of the CSPRNG state, one-time replay caches and signature/time/audience validation, and must
/// never become a mass-lockout hazard itself.
/// </summary>
internal sealed class SsoRateLimiter
{
    // Ceiling on tracked client keys, bounding memory under a key-rotation flood. At the cap a NEW
    // key is allowed rather than throttled or evicted: refusing unknown clients would mass-lock-out
    // legitimate users during the very flood the limiter exists for, and evicting would reset an
    // abuser's window. Fail open — the cap bounds memory, not the attacker.
    private readonly int _maxEntries;

    // Stale-entry sweeping is throttled to at most once per this interval (an O(n) scan on the
    // anonymous hot path would amplify a flood into CPU load). Safe to defer: a stale window is
    // reset inline by the next hit on its key, so sweeping is only memory reclamation.
    private static readonly TimeSpan PruneInterval = TimeSpan.FromMinutes(1);

    // The throttle-engaged observability signal (#195) fires at most once per this interval. A
    // per-refusal log would amplify the very flood the limiter blunts into unbounded log/CPU volume
    // (a self-inflicted DoS on an anonymous endpoint), so the signal is bounded the same way the
    // prune sweep and the #246 capacity warning are: one CAS winner per interval drains a tally.
    private static readonly TimeSpan SignalInterval = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, Counter> _counters = new(StringComparer.Ordinal);

    // Serializes only the rare "new key" cap-check-and-insert so it is atomic; the hot "existing
    // key" path never touches it.
    private readonly System.Threading.Lock _capLock = new();

    // Throttles the #195 observability signal to one drain per SignalInterval; the gate owns the atomic
    // cursor. The tally (_throttledHits) it drains stays a mutable field below — see RecordThrottledHit.
    private readonly IntervalGate _signalGate = new(SignalInterval);

    // Throttles the stale-counter sweep to one run per PruneInterval; the gate owns the atomic cursor
    // and self-heals a backward wall-clock step of at least the interval (re-anchors), while a sub-interval
    // backward step is a stale sample suppressed with the cursor untouched (#334) — either way it never
    // stalls until the clock re-passes its cursor the way the hand-rolled predecessor did. See PruneStale.
    private readonly IntervalGate _pruneGate = new(PruneInterval);

    // Bounded observability signal (#195). Every refusal increments the tally; RecordThrottledHit drains it
    // into a single log line at most once per SignalInterval via _signalGate. A racing increment is never
    // lost — it lands in that drain or a later one (see RecordThrottledHit) — which is harmless timing slack
    // for a best-effort operator signal (never a security decision).
    private long _throttledHits;

    /// <summary>
    /// Initializes a new instance of the <see cref="SsoRateLimiter"/> class.
    /// </summary>
    /// <param name="maxEntries">Ceiling on tracked client keys (overridable for tests).</param>
    internal SsoRateLimiter(int maxEntries = 100_000)
    {
        _maxEntries = maxEntries;
    }

    /// <summary>
    /// Normalizes the client's connection address into a rate-limit key. Returns null (= do not
    /// throttle, fail open) when no address can be attributed. IPv6 is keyed on its /64 prefix —
    /// a single residential allocation — since per-/128 keying is evadable by address rotation;
    /// IPv4-mapped IPv6 is keyed as the underlying IPv4. IPv4-in-IPv6 transition sources (6to4,
    /// the NAT64 well-known prefix, IPv4-compatible) are keyed on their embedded IPv4, not the
    /// shared transition /64, so distinct NATed clients behind one prefix are not collapsed into
    /// one bucket where a single abuser would throttle them all (#194).
    /// </summary>
    /// <param name="remoteIp">The connection's remote address. Deliberately the ONLY input: the
    /// plugin never parses X-Forwarded-For itself. Jellyfin's own forwarded-headers middleware
    /// (enabled by the server's "Known proxies" networking setting) already resolves the real
    /// client into this address and strips the consumed header entries, so any X-Forwarded-For
    /// value visible here is client-supplied and spoofable — keying on it would let an attacker
    /// rotate keys to evade or pin a victim's address to lock them out.</param>
    /// <returns>The rate-limit key, or null when the client cannot be attributed.</returns>
    internal static string NormalizeClientKey(IPAddress remoteIp)
    {
        var ip = remoteIp;
        if (ip == null)
        {
            return null;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        // Non-public sources (loopback, RFC1918, CGNAT, link-local, unique/site-local) are never
        // rate-limited. This is THE structural mass-lockout defense: behind a reverse proxy whose
        // forwarded headers Jellyfin has not been told to resolve ("Known proxies" unset), the
        // socket peer is the proxy's private/loopback address — one shared bucket for the entire
        // userbase — so no bucket is created at all. LAN/insider traffic is out of scope for a
        // brute-force limiter aimed at the public edge. Shares its predicate with the avatar SSRF
        // guard (IpAddressClassifier, #370): "not a public address" is the same classification in
        // both places.
        if (IpAddressClassifier.IsBlockedAddress(ip))
        {
            return null;
        }

        if (ip.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return ip.ToString();
        }

        var bytes = ip.GetAddressBytes();

        // IPv4-in-IPv6 transition sources carry the client-identifying IPv4 in bits that /64 keying
        // treats coarsely. For the well-known NAT64 prefix (64:ff9b::/96) and the IPv4-compatible
        // form (::/96) the IPv4 sits in the low 64 bits that /64 ZEROS, so every distinct client
        // behind the prefix collapses into one shared bucket and one abuser would throttle them all
        // — this fix's target. Key on the embedded IPv4 instead: it is the true client identity, so a
        // NAT64/IPv4-compatible source now buckets exactly like the same native IPv4. (For 6to4,
        // 2002::/16, the IPv4 is in bytes 2-5, so this instead COLLAPSES a multi-/64 6to4 site onto
        // its one gateway IPv4 — the same egress-identity keying a native NAT already gets, and it
        // closes a rotate-within-your-own-/48 evasion hole; a bounded, deliberate trade for a
        // deprecated form.) The extraction is the same one IsBlockedAddress applied above, so the two
        // never disagree, and any source reaching here has a PUBLIC embedded IPv4 (a blocked/internal
        // one already returned null) — this only re-buckets, never returns null, so throttling is
        // preserved (fail closed). A network-specific NAT64 prefix (RFC 6052 NSP) is not recognized
        // and falls through to /64 below, as does any non-transition IPv6.
        if (IpAddressClassifier.TryExtractEmbeddedIPv4(bytes, out var embedded))
        {
            return embedded.ToString();
        }

        Array.Clear(bytes, 8, 8);
        return string.Create(CultureInfo.InvariantCulture, $"{new IPAddress(bytes)}/64");
    }

    /// <summary>
    /// Counts a hit for <paramref name="key"/> and reports whether it is within the limit. A fixed
    /// window per key: the first hit opens the window, hits beyond <paramref name="maxAttempts"/>
    /// inside it are refused, and the next hit after it expires resets it. Boundary bursts can reach
    /// 2x the limit across two adjacent windows — accepted; this throttles sustained abuse.
    /// </summary>
    /// <param name="key">The client key from <see cref="NormalizeClientKey"/>; null/empty is always allowed.</param>
    /// <param name="maxAttempts">Allowed hits per window. A value below 1 disables the limiter (always allowed), never "block everything".</param>
    /// <param name="window">The window length.</param>
    /// <param name="nowUtc">The current time.</param>
    /// <param name="retryAfterSeconds">Whole seconds until the window expires, when refused.</param>
    /// <returns>True when the hit is allowed; false when the client is over the limit.</returns>
    internal bool IsAllowed(string key, int maxAttempts, TimeSpan window, DateTime nowUtc, out int retryAfterSeconds)
    {
        retryAfterSeconds = 0;
        if (string.IsNullOrEmpty(key) || maxAttempts < 1)
        {
            return true;
        }

        PruneStale(window, nowUtc);
        if (!_counters.TryGetValue(key, out var counter))
        {
            // Serialize the cap check and the insert so they are atomic: a lock-free check-then-act
            // lets concurrent distinct new keys all pass the count check before any inserts, so the
            // tracked-key table overshoots the cap under a key-rotation flood (the login-path
            // invariant is to keep check-then-act on shared state atomic). Only new keys pay this;
            // the common already-tracked path above is lock-free.
            lock (_capLock)
            {
                if (!_counters.TryGetValue(key, out counter))
                {
                    if (_counters.Count >= _maxEntries)
                    {
                        return true;
                    }

                    counter = _counters.GetOrAdd(key, _ => new Counter());
                }
            }
        }

        lock (counter)
        {
            if (nowUtc.Ticks - counter.WindowStartTicks >= window.Ticks)
            {
                counter.WindowStartTicks = nowUtc.Ticks;
                counter.Count = 0;
            }

            // Count is clamped at the refusal threshold rather than incremented unboundedly, so a
            // pathologically long window cannot overflow it into a negative value that re-admits
            // (once over the limit the exact count is irrelevant — the client is refused).
            if (counter.Count <= maxAttempts)
            {
                counter.Count++;
            }

            if (counter.Count <= maxAttempts)
            {
                return true;
            }

            var remaining = TimeSpan.FromTicks(counter.WindowStartTicks + window.Ticks - nowUtc.Ticks);
            retryAfterSeconds = Math.Max(1, (int)Math.Ceiling(remaining.TotalSeconds));
            return false;
        }
    }

    /// <summary>
    /// Records one throttled (refused) hit and reports whether an observability signal is due. Every
    /// refusal increments a bounded tally; a signal fires at most once per <see cref="SignalInterval"/>,
    /// returning (and resetting) the count accumulated since the last one so the caller emits a single
    /// "N throttled" log line. Returns 0 while suppressed inside the current interval. This never scales
    /// with attack volume — one line per interval, not per request — and carries only a count, no client
    /// key, so it cannot amplify a flood into log/CPU volume nor forge log lines. It does NOT change the
    /// throttling decision (that is <see cref="IsAllowed"/>'s alone); it only observes it.
    /// </summary>
    /// <param name="nowUtc">The current time.</param>
    /// <returns>The throttled-hit count to log when a signal is due this interval; otherwise 0.</returns>
    internal long RecordThrottledHit(DateTime nowUtc)
    {
        Interlocked.Increment(ref _throttledHits);

        // Only the gate's single winner per interval drains the tally; everyone else returns 0 (suppressed).
        // An increment racing with the winner's drain lands either in that drain's returned count or in the
        // tally for a later drain — never erased, since increment and exchange on one location are serialized
        // atomic operations (pinned by the conservation test). The gate self-heals a backward clock step of
        // at least the interval and suppresses a sub-interval stale sample (#334), so neither a correction nor
        // a stale blip can stall the signal; the first refusal (cursor at MinValue) signals the onset at once.
        return _signalGate.TryEnter(nowUtc) ? Interlocked.Exchange(ref _throttledHits, 0) : 0;
    }

    // Drops counters whose window has long passed, at most once per PruneInterval. Enumerating a
    // ConcurrentDictionary is a safe moving snapshot and TryRemove is atomic (the same pattern as
    // SamlRequestCache.PruneExpired). A counter removed while another thread holds its lock only
    // loses that thread's tally to a fresh window — harmless for a best-effort limiter.
    private void PruneStale(TimeSpan window, DateTime nowUtc)
    {
        if (!_pruneGate.TryEnter(nowUtc))
        {
            return;
        }

        foreach (var kvp in _counters)
        {
            var counter = kvp.Value;
            long start;
            lock (counter)
            {
                start = counter.WindowStartTicks;
            }

            // Two windows of quiet before reclaiming, so an entry mid-refusal is never removed.
            if (nowUtc.Ticks - start >= 2 * window.Ticks)
            {
                _counters.TryRemove(kvp.Key, out _);
            }
        }
    }

    // Per-key tally, accessed only under its own lock (brief, per-client — no global contention).
    private sealed class Counter
    {
        internal long WindowStartTicks { get; set; }

        internal int Count { get; set; }
    }
}
