using System;
using System.Collections.Concurrent;
using System.Linq;

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
    // A generous ceiling: at the request lifetime below, this only bites under an abandoned-login
    // flood, and even then it evicts the soonest-to-expire entries rather than growing unbounded.
    private const int MaxEntries = 100_000;

    private readonly ConcurrentDictionary<string, DateTime> _outstanding = new(StringComparer.Ordinal);

    /// <summary>
    /// Records an issued request ID as outstanding until <paramref name="expiryUtc"/>. A blank ID is
    /// ignored (the correlation at consume time then fails closed).
    /// </summary>
    /// <param name="requestId">The request ID (scoped by the caller, e.g. by provider).</param>
    /// <param name="expiryUtc">When the entry may be evicted (the request's validity horizon).</param>
    /// <param name="nowUtc">The current time.</param>
    internal void Register(string requestId, DateTime expiryUtc, DateTime nowUtc)
    {
        Prune(nowUtc);
        if (string.IsNullOrEmpty(requestId))
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
        Prune(nowUtc);
        if (string.IsNullOrEmpty(requestId))
        {
            return false;
        }

        return _outstanding.TryRemove(requestId, out var expiry) && expiry > nowUtc;
    }

    // Drops expired entries, and if the cache is still over the ceiling, evicts the soonest-to-expire
    // entries down to it — so the size is bounded even under a flood of never-answered challenges.
    private void Prune(DateTime nowUtc)
    {
        foreach (var kvp in _outstanding)
        {
            if (kvp.Value <= nowUtc)
            {
                _outstanding.TryRemove(kvp.Key, out _);
            }
        }

        var overflow = _outstanding.Count - MaxEntries;
        if (overflow <= 0)
        {
            return;
        }

        foreach (var kvp in _outstanding.OrderBy(e => e.Value).Take(overflow))
        {
            _outstanding.TryRemove(kvp.Key, out _);
        }
    }
}
