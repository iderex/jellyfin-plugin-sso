using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The in-flight SAML login-outcome store (#251): the assertion-consumer callback validates the signed
/// assertion ONCE, then stores the resulting <see cref="SamlLoginOutcome"/> here keyed by a fresh CSPRNG
/// token and hands the intermediate auth page only that token — never the assertion. The same-origin
/// session-mint leg redeems the token once and completes the login from the stored outcome, so the signed
/// XML no longer round-trips through the browser and is not parsed or validated a second time. This is the
/// SAML analogue of <see cref="OidcStateStore"/>'s one-time authorize-state redeem: cap-bounded
/// registration, an atomic one-time claim, and an <see cref="IntervalGate"/>-throttled expired-entry sweep.
/// </summary>
/// <remarks>
/// A single stored variant, not the OpenID two-phase Pending -> Ready swap: a SAML login is FULLY verified
/// at the callback (signature, time, audience, recipient, role gate, one-time replay consume and the
/// verified-identity construction all complete there), so what is stored is already the redeemable outcome.
/// Holding a <see cref="SamlLoginOutcome"/> is therefore proof the assertion passed every gate, and the
/// redeem is the sole one-time claim — a token is redeemable at most once even under concurrent posts.
/// </remarks>
internal sealed class SamlOutcomeStore
{
    // An approximate ceiling on outstanding login outcomes, so a flood of validated callbacks cannot grow
    // the store without bound (mirrors OidcStateStore / SamlRequestCache). At the cap a fresh outcome is
    // refused rather than evicting an in-flight one; the callback path is reached only after full signature
    // validation, so it is not anonymously floodable, and rate-limiting at the edge (#128) is the primary
    // defense.
    internal const int DefaultMaxEntries = 100_000;

    // How long a stored login outcome may live before it is rejected/pruned. It bounds the gap between the
    // ACS callback rendering the page and the browser posting the token back — a fast same-origin round
    // trip — so it matches the sibling in-flight lifetimes (the outstanding-request/authorize-state window).
    internal static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(15);

    // The expired-entry sweep is an O(n) scan; throttling it to at most once per this interval keeps it off
    // the hot path (mirrors the siblings). Throttling only defers memory reclamation — the redeem predicate
    // rejects an expired outcome independently, so a not-yet-swept entry never completes a login.
    internal static readonly TimeSpan DefaultPruneInterval = TimeSpan.FromMinutes(1);

    private readonly int _maxEntries;
    private readonly TimeSpan _lifetime;

    // Concurrent requests add to, redeem from, and prune this map; a plain Dictionary corrupts or throws
    // under that interleaving. The redeem is a single atomic TryRemove, so one outcome completes at most one
    // login even under concurrent posts. Ordinal matches the CSPRNG token's exact-byte comparison.
    private readonly ConcurrentDictionary<string, SamlLoginOutcome> _outcomes = new(StringComparer.Ordinal);

    // Throttles the sweep to one run per interval; the gate owns the atomic cursor. See PruneExpired.
    private readonly IntervalGate _pruneGate;

    // Throttles the capacity-full warning (CWE-400) to one signal per interval, so a flood of refused
    // registrations cannot amplify into unbounded log volume (parity with the siblings).
    private readonly IntervalGate _capWarnGate;

    // Per-client occupancy sub-cap (#327): bounds how much of the global budget one client key can hold, so
    // a single source cannot fill the store and lock out everyone else's logins.
    private readonly PerClientBudgetLimiter _perClient;

    internal SamlOutcomeStore()
        : this(DefaultMaxEntries, DefaultLifetime, DefaultPruneInterval)
    {
    }

    // Test constructor: small caps and lifetimes make the cap and expiry paths reachable in unit tests (the
    // production values are unreachable there). IntervalGate rejects a non-positive interval.
    internal SamlOutcomeStore(int maxEntries, TimeSpan lifetime, TimeSpan pruneInterval)
    {
        _maxEntries = maxEntries;
        _lifetime = lifetime;
        _pruneGate = new IntervalGate(pruneInterval);
        _capWarnGate = new IntervalGate(pruneInterval);
        _perClient = PerClientBudgetLimiter.FromGlobalCap(maxEntries);
    }

    /// <summary>Gets the live entry count. Test-only, like Clear.</summary>
    internal int Count => _outcomes.Count;

    /// <summary>
    /// A fresh 256-bit CSPRNG token, hex-encoded. A token that misses the store falls through to the
    /// deprecation branch's assertion validation, which fails closed regardless: the hex string may be
    /// Base64-decodable, but its decoded bytes are not a SAML response, so the XML parse rejects it.
    /// </summary>
    /// <returns>The new one-time outcome token.</returns>
    internal static string NewToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// Registers a fully-verified login outcome under its CSPRNG token. At the cap a NEW token is refused
    /// (that one login fails closed) rather than evicting an in-flight outcome — evicting would drop a user
    /// already mid-login. On refusal, <paramref name="shouldWarnCapacity"/> is true for at most one caller
    /// per interval; the warning line stays at the call site so the log-forging inline sanitizer never
    /// crosses a helper boundary.
    /// </summary>
    /// <param name="outcome">The verified outcome; its token keys the entry and its Created drives the throttled warning.</param>
    /// <param name="shouldWarnCapacity">True when the caller should emit the throttled capacity warning.</param>
    /// <returns>True if the outcome was registered; false if refused (per-client sub-cap, global cap, or token collision).</returns>
    internal bool TryAdd(SamlLoginOutcome outcome, out bool shouldWarnCapacity)
    {
        // Per-client sub-cap (#327): reserve this client's slot BEFORE the global insert so one source
        // cannot fill the whole budget and lock out every other login. A null key is exempt.
        if (!_perClient.TryReserve(outcome.ClientKey))
        {
            shouldWarnCapacity = _capWarnGate.TryEnter(outcome.Created);
            return false;
        }

        if ((_outcomes.Count >= _maxEntries && !_outcomes.ContainsKey(outcome.Token))
            || !_outcomes.TryAdd(outcome.Token, outcome))
        {
            // The entry never entered the store (global cap, or a CSPRNG-token collision losing the atomic
            // add) — release the reservation so the client's bucket does not leak a slot.
            _perClient.Release(outcome.ClientKey);
            shouldWarnCapacity = _capWarnGate.TryEnter(outcome.Created);
            return false;
        }

        shouldWarnCapacity = false;
        return true;
    }

    /// <summary>
    /// The one-time atomic claim: the store is keyed by the outcome token, which is exactly the value the
    /// mint leg presents, so this is an O(1) lookup plus an atomic TryRemove — only the request that wins the
    /// removal proceeds, so one outcome completes at most one login even under concurrent posts. Redeemable
    /// only while the outcome still belongs to the route provider (so a token cannot be replayed against
    /// another provider's endpoint) and is within its lifetime; an unknown, expired, provider-mismatched or
    /// already-claimed token returns null (fail closed).
    /// </summary>
    /// <param name="token">The outcome token the mint leg presented.</param>
    /// <param name="provider">The provider named in the consuming request's route.</param>
    /// <param name="now">The current time.</param>
    /// <returns>The redeemed outcome, or null when not redeemable.</returns>
    internal SamlLoginOutcome TryRedeem(string token, string provider, DateTime now)
    {
        if (string.IsNullOrEmpty(token)
            || !_outcomes.TryGetValue(token, out var outcome)
            || !IsCurrentFor(outcome, provider, now)
            || !_outcomes.TryRemove(new KeyValuePair<string, SamlLoginOutcome>(token, outcome)))
        {
            return null;
        }

        // Only the winner of the atomic TryRemove reaches here, so the client's slot is released exactly once.
        _perClient.Release(outcome.ClientKey);
        return outcome;
    }

    /// <summary>
    /// Removes every outcome whose lifetime has elapsed, at most once per prune interval so a flood does not
    /// amplify the O(n) scan into CPU load. Safe concurrently with additions and redeems because it operates
    /// on a <see cref="ConcurrentDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <param name="now">The reference time driving both the gate and the expiry evaluation.</param>
    internal void PruneExpired(DateTime now)
    {
        if (!_pruneGate.TryEnter(now))
        {
            return;
        }

        foreach (var kvp in _outcomes.Where(kvp => now.Subtract(kvp.Value.Created) > _lifetime))
        {
            // Release only on the winning removal so a concurrent redeem does not double-release the slot.
            if (_outcomes.TryRemove(kvp.Key, out var removed))
            {
                _perClient.Release(removed.ClientKey);
            }
        }
    }

    /// <summary>Test-only: drops every entry, restoring a fresh store between tests.</summary>
    internal void Clear()
    {
        _outcomes.Clear();
        _perClient.Clear();
    }

    /// <summary>Test-only: seeds one outcome directly, bypassing the callback leg.</summary>
    /// <param name="outcome">The outcome to store under its own token.</param>
    internal void Seed(SamlLoginOutcome outcome) => _outcomes[outcome.Token] = outcome;

    // Whether a stored outcome still belongs to the route provider and has not expired. The provider check
    // is the token-scoping guard: without it, an outcome verified at a low-trust provider could be replayed
    // against a higher-trust provider's mint endpoint. A negative age (Created in the future, e.g. a
    // backward clock step) is rejected too, so a clock anomaly cannot make an outcome effectively never
    // expire.
    private bool IsCurrentFor(SamlLoginOutcome outcome, string provider, DateTime now)
    {
        if (!string.Equals(outcome.Provider, provider, StringComparison.Ordinal))
        {
            return false;
        }

        var age = now.Subtract(outcome.Created);
        return age >= TimeSpan.Zero && age <= _lifetime;
    }
}

/// <summary>
/// One fully-verified SAML login, held server-side between the assertion-consumer callback (which builds it
/// after complete validation) and the same-origin session-mint leg (which redeems it once). Immutable: the
/// redeem is an atomic remove of the whole record, so a redeemer never observes a torn outcome. It carries
/// the protocol-agnostic <see cref="VerifiedIdentity"/> the mint path needs plus the correlation facts the
/// mint leg still enforces there (the assertion's <c>InResponseTo</c>, matched against the browser-binding
/// cookie that the cross-site ACS POST could not carry).
/// </summary>
/// <param name="Token">The CSPRNG token keying the entry — the only value that crosses to the browser.</param>
/// <param name="Provider">The provider that verified the login; a token is redeemable only on its own provider's endpoint.</param>
/// <param name="Identity">The verified identity and privileges the mint path is keyed on (#473).</param>
/// <param name="InResponseTo">The assertion's <c>InResponseTo</c> (empty for an unsolicited response), correlated + browser-bound at the mint leg (#415).</param>
/// <param name="ClientKey">The normalized client key that reserved this outcome's per-client budget slot (#327), or null for an exempt source.</param>
/// <param name="Created">When the outcome was created, used to time it out.</param>
internal sealed record SamlLoginOutcome(
    string Token,
    string Provider,
    VerifiedIdentity Identity,
    string InResponseTo,
    string ClientKey,
    DateTime Created);
