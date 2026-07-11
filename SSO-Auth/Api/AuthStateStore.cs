using System;
using System.Collections.Concurrent;

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
        foreach (var kvp in states)
        {
            if (now.Subtract(kvp.Value.Created) > lifetime)
            {
                states.TryRemove(kvp.Key, out _);
            }
        }
    }
}
