using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Pure login-authorization gate for SAML: decides whether an assertion's roles satisfy the
/// provider's configured login allow-list. Must be enforced at BOTH the assertion-consumer page and
/// the session-minting endpoint — enforcing it only at the page is fail-open, because a caller can
/// POST an assertion straight to the minting endpoint and skip the page.
/// </summary>
internal static class SamlLoginPolicy
{
    /// <summary>
    /// Determines whether a login is permitted.
    /// </summary>
    /// <param name="assertionRoles">The role values carried by the (already signature-validated) assertion.</param>
    /// <param name="allowedRoles">The provider's configured login allow-list.</param>
    /// <returns>True when no allow-list is configured (RBAC off) or the assertion carries at least one allowed role.</returns>
    internal static bool IsLoginAllowed(IEnumerable<string> assertionRoles, string[] allowedRoles)
    {
        // No allow-list configured => role-based login is disabled, everyone authenticated is allowed.
        if (allowedRoles == null || allowedRoles.Length == 0)
        {
            return true;
        }

        if (assertionRoles != null)
        {
            foreach (var role in assertionRoles)
            {
                foreach (var allowed in allowedRoles)
                {
                    // Static Equals is null-safe (a null allowed entry returns false rather than throwing).
                    if (string.Equals(allowed, role, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
