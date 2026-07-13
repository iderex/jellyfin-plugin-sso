using System;
using System.Collections.Concurrent;
using System.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Helpers for maintaining the in-flight OpenID authorize-state store in a thread-safe manner.
/// </summary>
internal static class AuthStateStore
{
    /// <summary>
    /// Removes every authorize state whose lifetime has elapsed. Safe to call concurrently with
    /// additions and removals because it operates on a <see cref="ConcurrentDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <param name="states">The state store to prune.</param>
    /// <param name="now">The reference time used to evaluate expiry.</param>
    /// <param name="lifetime">How long a state may live before it is considered expired.</param>
    internal static void InvalidateExpired(
        ConcurrentDictionary<string, TimedAuthorizeState> states,
        DateTime now,
        TimeSpan lifetime)
    {
        foreach (var kvp in states.Where(kvp => now.Subtract(kvp.Value.Created) > lifetime))
        {
            states.TryRemove(kvp.Key, out _);
        }
    }

    /// <summary>
    /// Adds a new authorize state unless the store already holds <paramref name="maxEntries"/> entries.
    /// At the cap a NEW key is refused (that one login fails closed) rather than evicting an in-flight
    /// state — evicting would drop a user already mid-login (a mass-lockout hazard under a flood). This
    /// bounds memory under an anonymous challenge flood on the busiest login endpoint, mirroring
    /// <see cref="SamlRequestCache"/>. The check-then-insert is not serialized (no lock on the anonymous
    /// hot path), so concurrent adds can transiently overshoot by at most the number of in-flight threads.
    /// </summary>
    /// <param name="states">The state store.</param>
    /// <param name="key">The authorize-state value used as the key.</param>
    /// <param name="value">The state to store.</param>
    /// <param name="maxEntries">The approximate ceiling on stored entries.</param>
    /// <returns>True if the state was added; false if the key already existed or the store is at capacity.</returns>
    internal static bool TryAdd(
        ConcurrentDictionary<string, TimedAuthorizeState> states,
        string key,
        TimedAuthorizeState value,
        int maxEntries)
    {
        if (states.Count >= maxEntries && !states.ContainsKey(key))
        {
            return false;
        }

        return states.TryAdd(key, value);
    }

    /// <summary>
    /// Whether a stored state still belongs to the given provider and has not expired. Used at the
    /// OpenID callback before a state is validated: a state minted for one provider must not be
    /// accepted on another provider's callback, and a state older than its lifetime is not honored.
    /// </summary>
    /// <param name="state">The stored state, or null.</param>
    /// <param name="provider">The provider named in the consuming request's route.</param>
    /// <param name="now">The current time.</param>
    /// <param name="lifetime">How long a state may live.</param>
    /// <returns>True only when the state exists, belongs to the provider, and is within its lifetime.</returns>
    internal static bool IsCurrentFor(TimedAuthorizeState state, string provider, DateTime now, TimeSpan lifetime)
    {
        if (state == null || !string.Equals(state.Provider, provider, StringComparison.Ordinal))
        {
            return false;
        }

        // Reject a negative age (Created in the future, e.g. a backward clock step) as well as an
        // over-lifetime one, so a clock anomaly cannot make a state effectively never expire.
        var age = now.Subtract(state.Created);
        return age >= TimeSpan.Zero && age <= lifetime;
    }

    /// <summary>
    /// Whether a stored state may be redeemed to mint a session or create a link: it must be
    /// validated, its authorization-response value must match the presented one, and it must still
    /// belong to the route provider and be unexpired. The provider check is the state-scoping guard:
    /// without it, a state validated at a low-trust provider could be replayed against a higher-trust
    /// provider's endpoint, bypassing that provider's login/role gate (cross-provider state replay).
    /// </summary>
    /// <param name="state">The stored state, or null.</param>
    /// <param name="responseData">The authorization-response value the caller presented.</param>
    /// <param name="provider">The provider named in the consuming request's route.</param>
    /// <param name="now">The current time.</param>
    /// <param name="lifetime">How long a state may live.</param>
    /// <returns>True only when the state is valid, matches the response value, belongs to the provider, and is unexpired.</returns>
    internal static bool IsRedeemableBy(TimedAuthorizeState state, string responseData, string provider, DateTime now, TimeSpan lifetime)
    {
        return state != null
            && state.Valid
            && state.State != null
            && string.Equals(state.State.State, responseData, StringComparison.Ordinal)
            && IsCurrentFor(state, provider, now, lifetime);
    }
}
