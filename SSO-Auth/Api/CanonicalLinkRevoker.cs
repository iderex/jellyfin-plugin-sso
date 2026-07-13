using System;
using System.Collections.Generic;
using System.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Removes canonical-link entries that point at a given Jellyfin user. An admin revoking a user's SSO
/// access must clear these links, because SSO login resolves through the per-provider CanonicalLinks
/// maps (key -> user id), not <c>AuthenticationProviderId</c>. Pure so the remove-by-value contract is
/// unit-testable independent of the controller and the config lock.
/// </summary>
internal static class CanonicalLinkRevoker
{
    /// <summary>
    /// Removes every entry whose value is <paramref name="userId"/> from the links map.
    /// </summary>
    /// <param name="links">The provider's canonical-links map (key -> user id); a null map is a no-op.</param>
    /// <param name="userId">The Jellyfin user id whose links to remove.</param>
    /// <returns>The number of entries removed.</returns>
    internal static int RemoveUser(IDictionary<string, Guid> links, Guid userId)
    {
        if (links is null)
        {
            return 0;
        }

        // Materialize the matching keys before removing so the map is not mutated during enumeration.
        var keys = links.Where(pair => pair.Value == userId).Select(pair => pair.Key).ToList();
        foreach (var key in keys)
        {
            links.Remove(key);
        }

        return keys.Count;
    }
}
