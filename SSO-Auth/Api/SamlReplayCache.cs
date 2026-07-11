using System;
using System.Collections.Concurrent;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Tracks SAML assertion IDs that have already been used to mint a session, so a captured assertion
/// cannot be replayed within its validity window. Entries are retained until the supplied expiry and
/// evicted opportunistically.
/// </summary>
internal sealed class SamlReplayCache
{
    private readonly ConcurrentDictionary<string, DateTime> _consumed = new(StringComparer.Ordinal);

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
    /// Records the assertion ID as consumed. Returns false when the assertion has no usable ID or has
    /// already been consumed within its validity window (a replay).
    /// </summary>
    /// <param name="assertionId">The assertion ID.</param>
    /// <param name="expiryUtc">When the entry may be evicted (typically the assertion's NotOnOrAfter).</param>
    /// <param name="nowUtc">The current time.</param>
    /// <returns>True if this is the first use; false on replay or a missing ID.</returns>
    internal bool TryConsume(string assertionId, DateTime expiryUtc, DateTime nowUtc)
    {
        foreach (var kvp in _consumed)
        {
            if (kvp.Value <= nowUtc)
            {
                _consumed.TryRemove(kvp.Key, out _);
            }
        }

        // Fail closed: without an ID we cannot enforce one-time use.
        if (string.IsNullOrEmpty(assertionId))
        {
            return false;
        }

        return _consumed.TryAdd(assertionId, expiryUtc);
    }
}
