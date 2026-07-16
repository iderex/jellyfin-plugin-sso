using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Maps the roles carried by a verified login (OpenID or SAML) to the privileges they grant, according
/// to the provider configuration. Pure: it derives the grants from (roles, config) and makes no decision
/// about the session itself — every grant is monotonic (only ever granted), and the caller merges the
/// result into the authorize state (OR-ing the booleans, appending the folders). One mapper for both
/// protocols, since every member it reads lives on <see cref="ProviderConfigBase"/> (#367). The SAML
/// caller ignores <see cref="RoleGrants.Valid"/> — SAML login validity is decided by
/// <see cref="SamlLoginPolicy"/>, not here.
/// </summary>
internal static class RolePrivilegeMapper
{
    /// <summary>
    /// Evaluates the privileges granted by the given roles under the given configuration.
    /// </summary>
    /// <param name="roles">The roles extracted from the verified login (OpenID claims or SAML attributes).</param>
    /// <param name="config">The provider configuration.</param>
    /// <returns>The granted privileges; booleans are false and the folder list empty when nothing matches.</returns>
    internal static RoleGrants Evaluate(IEnumerable<string> roles, ProviderConfigBase config)
    {
        var valid = false;
        var admin = false;
        var enableLiveTv = false;
        var enableLiveTvManagement = false;
        var folders = new List<string>();

        foreach (var role in roles)
        {
            if (IsOnList(config.Roles, role))
            {
                valid = true;
            }

            if (IsOnList(config.AdminRoles, role))
            {
                admin = true;
            }

            if (config.EnableFolderRoles && config.FolderRoleMapping != null)
            {
                foreach (var folderRoleMap in config.FolderRoleMapping)
                {
                    // The configured (trusted, admin-authored) map-role is trimmed before comparison; the
                    // IdP-supplied role is compared raw, so there is no whitespace-injection vector (#367).
                    if (string.Equals(role, folderRoleMap.Role?.Trim(), StringComparison.Ordinal))
                    {
                        folders.AddRange(folderRoleMap.Folders);
                    }
                }
            }

            if (config.EnableLiveTvRoles)
            {
                if (IsOnList(config.LiveTvRoles, role))
                {
                    enableLiveTv = true;
                }

                if (IsOnList(config.LiveTvManagementRoles, role))
                {
                    enableLiveTvManagement = true;
                }
            }
        }

        return new RoleGrants(valid, admin, enableLiveTv, enableLiveTvManagement, folders);
    }

    // Whether the login's role is on a configured allow-list. Null-safe both ways (ordinal): a null list
    // or a null entry is simply not a match — never a NullReferenceException — so an admin misconfiguration
    // or a stray null fails closed (grants nothing) instead of throwing a 500.
    private static bool IsOnList(IEnumerable<string> allowed, string role) =>
        allowed != null && allowed.Any(entry => string.Equals(role, entry, StringComparison.Ordinal));

    /// <summary>
    /// The privileges a set of roles grants under a provider configuration.
    /// </summary>
    /// <param name="Valid">Whether any role is on the login allow-list (<see cref="ProviderConfigBase.Roles"/>). Ignored by the SAML caller, whose validity is decided by <see cref="SamlLoginPolicy"/>.</param>
    /// <param name="Admin">Whether any role is on the admin list (<see cref="ProviderConfigBase.AdminRoles"/>).</param>
    /// <param name="EnableLiveTv">Whether any role grants Live TV (only when role-based Live TV is enabled).</param>
    /// <param name="EnableLiveTvManagement">Whether any role grants Live TV management (only when role-based Live TV is enabled).</param>
    /// <param name="Folders">The folders granted by matching folder-role mappings (only when folder roles are enabled).</param>
    internal readonly record struct RoleGrants(
        bool Valid,
        bool Admin,
        bool EnableLiveTv,
        bool EnableLiveTvManagement,
        List<string> Folders);
}
