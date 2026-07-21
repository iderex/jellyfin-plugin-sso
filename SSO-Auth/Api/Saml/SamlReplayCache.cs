using System;
using System.Collections.Concurrent;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Tracks SAML assertion IDs that have already been used to mint a session, so a captured assertion
/// cannot be replayed within its validity window. Entries are retained until the supplied expiry and
/// reclaimed by a throttled expired-entry sweep, and the set is hard-capped so it cannot grow without
/// bound (#452). It mirrors the sibling login-path caches (<see cref="SamlRequestCache"/>,
/// <see cref="Jellyfin.Plugin.SSO_Auth.Api.Oidc.OidcStateStore"/>): an <see cref="IntervalGate"/>-throttled sweep plus a global cap, and a
/// second <see cref="IntervalGate"/>-throttled signal that surfaces a cap refusal to the caller so a full
/// replay cache is observable rather than silent (#470).
///
/// The cap is applied differently from the siblings, on purpose. Recording a consumed assertion is what
/// makes a replay detectable, so this cache must never drop a still-valid entry to free a slot — that
/// would reopen the replay window for exactly that assertion (#32). Eviction is therefore tied strictly
/// to expiry: an entry is removed only once the assertion it guards can no longer be validly presented.
/// At the cap, a NEW distinct login is refused (returns false, so the login fails closed) rather than
/// evicting a live entry — a bounded DoS backstop that never trades away replay protection. This path is
/// reached only after full XML-DSig signature validation, so it is not anonymously floodable; filling the
/// cap requires a large volume of legitimately signed, rate-limited assertions.
/// </summary>
internal sealed class SamlReplayCache
{
    // An approximate ceiling on retained consumed-assertion IDs, bounding memory (CWE-400 parity with the
    // siblings). Unlike the siblings this is not an anti-flood cap on an anonymous endpoint — TryConsume
    // runs only after signature validation — but a defense-in-depth memory bound. The check-then-insert is
    // not serialized, so concurrent consumes can transiently overshoot by at most the number of in-flight
    // threads; immaterial against a best-effort backstop.

    /// <summary>The production ceiling on retained consumed-assertion IDs; at the cap a new login is refused fail-closed, never a still-valid entry evicted.</summary>
    internal const int DefaultMaxEntries = 100_000;

    // The expired-entry sweep is an O(n) scan; throttling it to at most once per this interval matches the
    // siblings and keeps the sweep off every consume. Throttling is safe because it is only memory
    // reclamation — TryConsume rejects a live entry independently (see the replay check), and at the cap it
    // forces an unthrottled reclaim before refusing, so a not-yet-swept expired entry neither grants a
    // replay nor false-rejects a fresh login.
    private static readonly TimeSpan DefaultPruneInterval = TimeSpan.FromMinutes(1);

    private readonly int _maxEntries;

    private readonly ConcurrentDictionary<string, DateTime> _consumed = new(StringComparer.Ordinal);

    // Throttles the sweep to one run per interval; the gate owns the atomic cursor and self-heals a
    // backward wall-clock step of at least the interval (#334). See PruneExpired.
    private readonly IntervalGate _pruneGate;

    // Throttles the cap-refusal capacity warning to one signal per interval (CWE-400): its OWN gate,
    // distinct from the prune gate, so a full cache signals at most once per interval rather than once per
    // refused assertion — a compromised identity provider replaying signed assertions at the cap cannot
    // amplify the refusal into unbounded log volume. Mirrors the sibling caches (OidcStateStore,
    // SamlRequestCache) so the SAML replay refusal has the same operator visibility (#470). The warning
    // LINE itself stays at the caller, which owns the logger, so the log-forging inline sanitizer never
    // crosses a helper boundary; this cache only decides WHETHER to warn.
    private readonly IntervalGate _capWarnGate;

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlReplayCache"/> class with the production cap and
    /// prune interval.
    /// </summary>
    internal SamlReplayCache()
        : this(DefaultMaxEntries, DefaultPruneInterval)
    {
    }

    // Test constructor: a small cap and short interval make the cap and prune-throttle paths reachable in
    // unit tests (the production values are unreachable there). IntervalGate rejects a non-positive interval.

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlReplayCache"/> class with explicit bounds, so a unit
    /// test can reach the cap and prune-throttle paths the production values make unreachable.
    /// </summary>
    /// <param name="maxEntries">The global ceiling on retained consumed-assertion IDs.</param>
    /// <param name="pruneInterval">The minimum interval between expired-entry sweeps.</param>
    internal SamlReplayCache(int maxEntries, TimeSpan pruneInterval)
    {
        _maxEntries = maxEntries;
        _pruneGate = new IntervalGate(pruneInterval);
        _capWarnGate = new IntervalGate(pruneInterval);
    }

    /// <summary>Gets the live entry count. Test-only, so the cap and sweep paths can be asserted.</summary>
    internal int Count => _consumed.Count;

    /// <summary>Test-only: drops all consumed-assertion entries so process-wide state cannot leak between tests.</summary>
    internal void Clear() => _consumed.Clear();

    /// <summary>
    /// Computes how long a just-consumed assertion must be retained for replay protection: the whole
    /// window it would still be accepted - its NotOnOrAfter plus the validation clock skew - with a
    /// one-hour floor that covers an assertion carrying no (or a very short) expiry.
    /// </summary>
    /// <param name="nowUtc">The current time.</param>
    /// <param name="assertionExpiryUtc">The assertion's effective NotOnOrAfter, or null when it declares none.</param>
    /// <returns>The UTC instant until which the assertion ID must be retained.</returns>
    internal static DateTime ComputeRetention(DateTime nowUtc, DateTime? assertionExpiryUtc)
    {
        // The one-hour floor bounds retention when an assertion carries no (or a very short) expiry; the
        // skew margin matches the clock skew the signature/time validation allows.
        var floor = nowUtc.AddHours(1);
        if (assertionExpiryUtc.HasValue)
        {
            var expiryWithSkew = assertionExpiryUtc.Value + SamlAssertionTime.ClockSkew;
            if (expiryWithSkew > floor)
            {
                return expiryWithSkew;
            }
        }

        return floor;
    }

    /// <summary>
    /// Records the assertion ID as consumed. Returns false when the assertion has no usable ID, has
    /// already been consumed within its validity window (a replay), or the cache is full of still-valid
    /// entries (a fail-closed cap refusal). A false return always rejects the login, so refusing at the
    /// cap never reopens the replay window.
    /// </summary>
    /// <param name="assertionId">The assertion ID.</param>
    /// <param name="expiryUtc">When the entry may be evicted (the assertion's retention horizon).</param>
    /// <param name="nowUtc">The current time.</param>
    /// <param name="shouldWarnCapacity">True for at most one caller per interval when a fail-closed cap refusal occurred, so the caller can log it once; false on any other outcome (first use, replay, missing ID).</param>
    /// <returns>True if this is the first use; false on replay, a missing ID, or a fail-closed cap refusal.</returns>
    internal bool TryConsume(string? assertionId, DateTime expiryUtc, DateTime nowUtc, out bool shouldWarnCapacity)
    {
        PruneExpired(nowUtc);
        shouldWarnCapacity = false;

        // Fail closed: without an ID we cannot enforce one-time use.
        if (string.IsNullOrEmpty(assertionId))
        {
            return false;
        }

        // Global cap. Only a NEW id would grow the set (an id already present is either a replay we reject
        // below or an expired entry we replace in place, neither of which grows it). At the cap, reclaim
        // expired entries the throttled sweep may have skipped, and only if the cache is STILL full of
        // unexpired entries refuse the login (return false) — never evict a live entry, which would drop a
        // within-window consumed assertion and reopen its replay window (#32).
        if (_consumed.Count >= _maxEntries && !_consumed.ContainsKey(assertionId))
        {
            SweepExpired(nowUtc);
            if (_consumed.Count >= _maxEntries && !_consumed.ContainsKey(assertionId))
            {
                // A genuine fail-closed cap refusal: the cache is full of still-live consumed assertions and
                // this new one is turned away (the login fails closed). Signal it once per interval — its own
                // gate, so a flood of refusals cannot amplify into log volume — so an operator can see the
                // replay cache is under real pressure (#470). The refusal itself is unchanged.
                shouldWarnCapacity = _capWarnGate.TryEnter(nowUtc);
                return false;
            }
        }

        while (true)
        {
            // Atomic first-use claim: the single winner of TryAdd is the first use, so two concurrent
            // presentations of the same assertion cannot both succeed.
            if (_consumed.TryAdd(assertionId, expiryUtc))
            {
                return true;
            }

            // An entry for this id already exists. Re-read it (it may have just been swept away).
            if (!_consumed.TryGetValue(assertionId, out var existing))
            {
                continue;
            }

            // A still-valid entry is a replay: reject, and never refresh its expiry (refreshing would
            // extend the replay window it guards).
            if (existing > nowUtc)
            {
                return false;
            }

            // Present but expired: a reused xsd:ID from a genuinely new login (assertion IDs are unique in
            // practice, so this is a correctness belt, not a hot path). It must not false-reject the new
            // login, so replace it — but only if it is still the exact stale value we read, so a racing
            // consumer of the same id cannot also win. A lost race loops and re-evaluates (the value is now
            // fresh, so it is treated as a replay).
            if (_consumed.TryUpdate(assertionId, expiryUtc, existing))
            {
                return true;
            }
        }
    }

    // Drops expired entries, at most once per prune interval. Enumerating a ConcurrentDictionary yields a
    // safe moving snapshot and the KeyValuePair TryRemove overload is atomic, so this is correct under
    // concurrent TryConsume — the size is bounded by the cap in TryConsume, not by this sweep.
    private void PruneExpired(DateTime nowUtc)
    {
        if (_pruneGate.TryEnter(nowUtc))
        {
            SweepExpired(nowUtc);
        }
    }

    // Removes every entry whose retention has elapsed. Uses the KeyValuePair overload so an entry a
    // concurrent consume refreshed to a live expiry between the read and the remove is not dropped.
    private void SweepExpired(DateTime nowUtc)
    {
        foreach (var kvp in _consumed)
        {
            if (kvp.Value <= nowUtc)
            {
                _consumed.TryRemove(kvp);
            }
        }
    }
}
