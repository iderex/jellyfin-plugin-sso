#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

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
    internal static bool IsLoginAllowed(IEnumerable<string?>? assertionRoles, string?[]? allowedRoles)
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
                // Skip empty/null role values so a missing role can never satisfy the allow-list
                // (a null/empty on both sides must not authorize).
                if (string.IsNullOrEmpty(role))
                {
                    continue;
                }

                if (allowedRoles.Any(allowed => !string.IsNullOrEmpty(allowed) && string.Equals(allowed, role, StringComparison.Ordinal)))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
