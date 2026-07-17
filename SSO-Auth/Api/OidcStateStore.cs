using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Duende.IdentityModel.OidcClient;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The in-flight OpenID authorize-state store: cap-bounded registration at challenge, a non-consuming
/// peek at the callback, and a one-time atomic redeem at mint/link. Owns the dictionary, the lifetime,
/// the throttled expired-entry sweep, and the throttled capacity-warning signal (#246, #318).
/// </summary>
internal sealed class OidcStateStore
{
    // An approximate ceiling on outstanding OpenID authorize states, so an anonymous challenge flood
    // cannot grow the store without bound (mirrors SamlRequestCache); at the cap a fresh challenge is
    // refused rather than evicting an in-flight state, and rate-limiting at the edge (#128) is the
    // primary defense (#246).
    internal const int DefaultMaxEntries = 100_000;

    // How long an in-flight OpenID authorize state may live before it is rejected/pruned. This bounds
    // the whole interactive leg (OidChallenge -> IdP login/MFA/consent -> callback -> mint), so it
    // must accommodate a real user completing MFA, not just a fast round trip.
    internal static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(15);

    // The expired-state sweep (PruneExpired) is an O(n) scan; throttling it to at most once per this
    // interval stops an anonymous challenge flood from amplifying into CPU load (mirrors
    // SamlRequestCache). This only defers memory reclamation — the peek/redeem predicates reject an
    // expired state independently, so a not-yet-swept entry never grants a login (#246).
    internal static readonly TimeSpan DefaultPruneInterval = TimeSpan.FromMinutes(1);

    private readonly int _maxEntries;
    private readonly TimeSpan _lifetime;

    // Concurrent requests add to, enumerate, and prune this map (challenge / auth / link / sweep); a
    // plain Dictionary corrupts or throws under that interleaving. StringComparer.Ordinal is what the
    // default string comparer already is — stated explicitly so the ordinal token matching is visible.
    private readonly ConcurrentDictionary<string, TimedAuthorizeState> _states = new(StringComparer.Ordinal);

    // Throttles the sweep to one run per interval; the gate owns the atomic cursor. See PruneExpired.
    private readonly IntervalGate _pruneGate;

    // Throttles the capacity-full warning (#246, CWE-400) to one signal per interval: under a flood
    // every refused challenge would otherwise emit a warning, amplifying the flood into unbounded log
    // volume. The gate self-heals a backward wall-clock step.
    private readonly IntervalGate _capWarnGate;

    // Per-client occupancy sub-cap (#327): bounds how much of the global budget one client key can hold,
    // so a single anonymous source cannot fill the store and lock out everyone else's logins.
    private readonly PerClientBudgetLimiter _perClient;

    internal OidcStateStore()
        : this(DefaultMaxEntries, DefaultLifetime, DefaultPruneInterval)
    {
    }

    // Test constructor: small caps and lifetimes make the cap and expiry paths reachable in unit
    // tests (the production values are unreachable there). IntervalGate rejects a non-positive interval.
    internal OidcStateStore(int maxEntries, TimeSpan lifetime, TimeSpan pruneInterval)
    {
        _maxEntries = maxEntries;
        _lifetime = lifetime;
        _pruneGate = new IntervalGate(pruneInterval);
        _capWarnGate = new IntervalGate(pruneInterval);
        _perClient = PerClientBudgetLimiter.FromGlobalCap(maxEntries);
    }

    /// <summary>Gets the live entry count. Test-only, like Seed/Clear: production code reads _states.Count directly.</summary>
    internal int Count => _states.Count;

    /// <summary>
    /// Registers a fresh challenge's authorize state, keyed by its CSPRNG state token — so the key
    /// always equals the token the callback presents. At the cap a NEW key is refused (that one login
    /// fails closed) rather than evicting an in-flight state — evicting would drop a user already
    /// mid-login (a mass-lockout hazard under a flood). The check-then-insert is not serialized (no
    /// lock on the anonymous hot path), so concurrent adds can transiently overshoot by at most the
    /// number of in-flight threads. On refusal, <paramref name="shouldWarnCapacity"/> is true for at
    /// most one caller per interval; the warning line itself stays at the controller so the
    /// log-forging inline sanitizer never crosses a helper boundary.
    /// </summary>
    /// <param name="state">The OidcClient authorize state whose token keys the entry.</param>
    /// <param name="provider">The provider the state is minted for.</param>
    /// <param name="isLinking">Whether this flow is a linking request rather than a login.</param>
    /// <param name="now">The current time, recorded as the entry's creation instant.</param>
    /// <param name="bindingId">The browser-binding id to record on the entry, matched at the callback (#326).</param>
    /// <param name="clientKey">The normalized client key for the per-client sub-cap (#327), or null to exempt.</param>
    /// <param name="providerInformation">The challenge's already-validated OpenID discovery metadata to carry to the callback (#247), or null.</param>
    /// <param name="shouldWarnCapacity">True when the caller should emit the throttled capacity warning.</param>
    /// <returns>True if the state was registered; false if refused (per-client sub-cap, global cap, or the key already existed).</returns>
    internal bool TryAdd(AuthorizeState state, string provider, bool isLinking, DateTime now, string bindingId, string clientKey, ProviderInformation providerInformation, out bool shouldWarnCapacity)
    {
        // Per-client sub-cap (#327): reserve this client's slot BEFORE the global insert so one source
        // cannot fill the whole budget and lock out every other login. A null key is exempt (the shared
        // proxy/private-source bucket, still bounded by the global cap below).
        if (!_perClient.TryReserve(clientKey))
        {
            shouldWarnCapacity = _capWarnGate.TryEnter(now);
            return false;
        }

        if ((_states.Count >= _maxEntries && !_states.ContainsKey(state.State))
            || !_states.TryAdd(state.State, new TimedAuthorizeState(state, now) { IsLinking = isLinking, Provider = provider, BindingId = bindingId, ClientKey = clientKey, ProviderInformation = providerInformation }))
        {
            // The entry never entered the store (global cap, or a CSPRNG-token collision losing the
            // atomic add) — release the reservation so the client's bucket does not leak a slot.
            _perClient.Release(clientKey);
            shouldWarnCapacity = _capWarnGate.TryEnter(now);
            return false;
        }

        shouldWarnCapacity = false;
        return true;
    }

    /// <summary>
    /// The callback's non-consuming check: returns the pending state only when it exists, was minted
    /// for this provider, and is within its lifetime; null otherwise, so a state issued for one
    /// provider cannot be validated on another's callback. No removal: the value is an unguessable
    /// CSPRNG token, and expiry pruning is handled by the sweep. A peek structurally cannot mint a
    /// session — only <see cref="TryRedeem"/> constructs a <see cref="RedeemedState"/> (#318).
    /// </summary>
    /// <param name="token">The state token the callback presented.</param>
    /// <param name="provider">The provider named in the consuming request's route.</param>
    /// <param name="now">The current time.</param>
    /// <param name="presentedBindingId">The browser-binding id the callback presented (its cookie value) (#326).</param>
    /// <returns>The pending state, or null when unknown, expired, provider-mismatched, or binding-mismatched.</returns>
    internal PendingState PeekCurrent(string token, string provider, DateTime now, string presentedBindingId)
    {
        return !string.IsNullOrEmpty(token)
            && _states.TryGetValue(token, out var state)
            && IsCurrentFor(state, provider, now)
            && AuthorizeStateBinding.Matches(state.BindingId, presentedBindingId)
            ? new PendingState(state)
            : null;
    }

    /// <summary>
    /// The one-time atomic claim: the store is keyed by the authorize-state token, which is exactly
    /// the presented response value, so this is an O(1) lookup plus an atomic
    /// TryRemove(KeyValuePair) — only the request that wins the removal proceeds, so one state mints
    /// at most one session even under concurrent posts. The sole constructor of
    /// <see cref="RedeemedState"/>; this idiom exists exactly once (#318).
    /// </summary>
    /// <param name="responseData">The authorization-response value the caller presented.</param>
    /// <param name="provider">The provider named in the consuming request's route.</param>
    /// <param name="now">The current time.</param>
    /// <param name="presentedBindingId">The browser-binding id the caller presented (its cookie value) (#326).</param>
    /// <returns>The redeemed snapshot, or null when not redeemable, already claimed, or binding-mismatched.</returns>
    internal RedeemedState TryRedeem(string responseData, string provider, DateTime now, string presentedBindingId)
    {
        if (string.IsNullOrEmpty(responseData)
            || !_states.TryGetValue(responseData, out var state)
            || !IsRedeemableBy(state, responseData, provider, now)
            || !AuthorizeStateBinding.Matches(state.BindingId, presentedBindingId)
            || !_states.TryRemove(new KeyValuePair<string, TimedAuthorizeState>(responseData, state)))
        {
            return null;
        }

        // Only the winner of the atomic TryRemove reaches here, so the client's slot is released exactly
        // once (#327).
        _perClient.Release(state.ClientKey);
        return new RedeemedState(state);
    }

    /// <summary>
    /// Removes every authorize state whose lifetime has elapsed, at most once per prune interval so an
    /// anonymous challenge flood does not amplify the O(n) scan into CPU load; the gate lets exactly
    /// one caller per interval run it (#246). Safe concurrently with additions and removals because it
    /// operates on a <see cref="ConcurrentDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <param name="now">The reference time driving both the gate and the expiry evaluation.</param>
    internal void PruneExpired(DateTime now)
    {
        if (!_pruneGate.TryEnter(now))
        {
            return;
        }

        // Strict '>' so an entry exactly at lifetime is kept, matching the <= acceptance in the
        // predicates. Deliberately no negative-age guard here: a future-Created entry (backward clock
        // step) is dead weight the predicates already reject; it is swept once the clock passes it.
        foreach (var kvp in _states.Where(kvp => now.Subtract(kvp.Value.Created) > _lifetime))
        {
            // Release only on the winning removal so a concurrent redeem does not double-release the
            // client's slot (#327).
            if (_states.TryRemove(kvp.Key, out var removed))
            {
                _perClient.Release(removed.ClientKey);
            }
        }
    }

    /// <summary>
    /// Projects the store to non-secret summaries for the admin debug endpoint. The raw store holds
    /// the authorize-state token and the PKCE code_verifier / nonce; those must never be serialized
    /// out, even to an admin.
    /// </summary>
    /// <returns>One summary per in-flight state.</returns>
    internal IEnumerable<Summary> Summaries() =>
        _states.Values.Select(s => new Summary(s.Provider, s.Created, s.Valid, s.IsLinking));

    /// <summary>Test-only: drops every entry, restoring a fresh store between tests.</summary>
    internal void Clear()
    {
        _states.Clear();
        _perClient.Clear();
    }

    /// <summary>Test-only: seeds one entry directly, bypassing the challenge leg.</summary>
    /// <param name="token">The state token to key the entry under.</param>
    /// <param name="state">The entry to store.</param>
    internal void Seed(string token, TimedAuthorizeState state) => _states[token] = state;

    // Whether a stored state still belongs to the given provider and has not expired. Used at the
    // OpenID callback before a state is validated: a state minted for one provider must not be
    // accepted on another provider's callback, and a state older than its lifetime is not honored.
    private bool IsCurrentFor(TimedAuthorizeState state, string provider, DateTime now)
    {
        if (state == null || !string.Equals(state.Provider, provider, StringComparison.Ordinal))
        {
            return false;
        }

        // Reject a negative age (Created in the future, e.g. a backward clock step) as well as an
        // over-lifetime one, so a clock anomaly cannot make a state effectively never expire.
        var age = now.Subtract(state.Created);
        return age >= TimeSpan.Zero && age <= _lifetime;
    }

    // Whether a stored state may be redeemed to mint a session or create a link: it must be
    // validated, its authorization-response value must match the presented one, and it must still
    // belong to the route provider and be unexpired. The provider check is the state-scoping guard:
    // without it, a state validated at a low-trust provider could be replayed against a higher-trust
    // provider's endpoint, bypassing that provider's login/role gate (cross-provider state replay).
    private bool IsRedeemableBy(TimedAuthorizeState state, string responseData, string provider, DateTime now)
    {
        return state != null
            && state.Valid
            && state.State != null
            && string.Equals(state.State.State, responseData, StringComparison.Ordinal)
            && IsCurrentFor(state, provider, now);
    }

    /// <summary>
    /// A non-secret projection of one in-flight state for the admin debug endpoint (property names
    /// and order match the anonymous type it replaces).
    /// </summary>
    /// <param name="Provider">The provider the state was minted for.</param>
    /// <param name="Created">When the state was created.</param>
    /// <param name="Valid">Whether the login has been verified.</param>
    /// <param name="IsLinking">Whether the flow is a linking request.</param>
    internal readonly record struct Summary(string Provider, DateTime Created, bool Valid, bool IsLinking);
}
