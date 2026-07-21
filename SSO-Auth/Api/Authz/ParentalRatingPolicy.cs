using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Authz;

/// <summary>
/// Reduces a login's roles to a maximum parental-rating-score ceiling (#736), the scalar-policy counterpart
/// of the boolean <see cref="PermissionRolePolicy"/>. When <c>EnableParentalRatingRoles</c> is on, each
/// configured mapping whose roles the login holds contributes its score, and the MOST RESTRICTIVE (minimum)
/// wins — never the loosest. A login that matches no mapping (or the feature being off) yields null, so the
/// mint leaves the account's existing ceiling untouched: an unmapped or malformed claim never raises it.
/// </summary>
internal static class ParentalRatingPolicy
{
    /// <summary>
    /// The parental-rating-score ceiling the login's roles resolve to, or null when the feature is off or no
    /// mapping matched (leave the existing ceiling untouched).
    /// </summary>
    /// <param name="roles">The login's role values.</param>
    /// <param name="config">The provider configuration carrying the mappings.</param>
    /// <returns>The minimum matched score, or null when nothing applies.</returns>
    internal static int? Resolve(IEnumerable<string> roles, ProviderConfigBase config)
    {
        // Master switch off (the default) or no mappings configured: SSO manages no ceiling, so the mint
        // leaves MaxParentalRatingScore exactly as it was — byte-for-byte the pre-#736 behavior.
        if (!config.EnableParentalRatingRoles || config.ParentalRatingRoleMappings is null)
        {
            return null;
        }

        var loginRoles = roles as IReadOnlyCollection<string> ?? new List<string>(roles);

        int? ceiling = null;
        foreach (var mapping in config.ParentalRatingRoleMappings)
        {
            // Fail closed toward the LESS permissive outcome: a null entry contributes nothing (it is
            // rejected at config-save validation; at runtime we skip rather than throw so a single bad entry
            // cannot 500 the login). A negative score is likewise rejected on save.
            if (mapping is null || !MatchesAnyRole(mapping.Roles, loginRoles))
            {
                continue;
            }

            // Minimum-wins: the smallest matched ceiling is the most restrictive, so a login matching several
            // groups never ends up looser than the strictest group allows.
            ceiling = ceiling is { } current ? Math.Min(current, mapping.Score) : mapping.Score;
        }

        return ceiling;
    }

    // A login holding any of the mapping's roles matches. The configured role is trimmed and compared
    // ordinally to the (verbatim) login roles, null-safe — the same matching the boolean policy uses.
    private static bool MatchesAnyRole(string[]? mappingRoles, IReadOnlyCollection<string> loginRoles)
    {
        if (mappingRoles is null)
        {
            return false;
        }

        foreach (var role in mappingRoles)
        {
            var trimmed = role?.Trim();
            if (string.IsNullOrEmpty(trimmed))
            {
                continue;
            }

            foreach (var loginRole in loginRoles)
            {
                if (string.Equals(loginRole, trimmed, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
