using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Maps the roles carried by an OpenID login to the privileges they grant, according to the
/// provider configuration. Pure: it derives the grants from (roles, config) and makes no decision
/// about the session itself — the caller merges the result into the authorize state (OR-ing the
/// booleans, appending the folders), which is why every grant here is monotonic (only ever granted,
/// never revoked). This mirrors, one-for-one, the per-role logic that used to live inline in the OID
/// callback.
/// </summary>
internal static class OidcRolePrivilegeMapper
{
    /// <summary>
    /// Evaluates the privileges granted by the given roles under the given configuration.
    /// </summary>
    /// <param name="roles">The roles extracted from the login's claims (across all matching claims).</param>
    /// <param name="config">The OpenID provider configuration.</param>
    /// <returns>The granted privileges; booleans are false and the folder list empty when nothing matches.</returns>
    internal static RoleGrants Evaluate(IEnumerable<string> roles, OidConfig config)
    {
        var valid = false;
        var admin = false;
        var enableLiveTv = false;
        var enableLiveTvManagement = false;
        var folders = new List<string>();

        foreach (var role in roles)
        {
            if (config.Roles != null && config.Roles.Any(allowed => role.Equals(allowed, StringComparison.Ordinal)))
            {
                valid = true;
            }

            if (config.AdminRoles != null && config.AdminRoles.Any(adminRole => role.Equals(adminRole, StringComparison.Ordinal)))
            {
                admin = true;
            }

            if (config.EnableFolderRoles)
            {
                // Deliberately not null-guarded and iterated with foreach (not LINQ Where): this
                // preserves the OID callback's exact behavior, including throwing NullReferenceException
                // when FolderRoleMapping is null (an admin misconfiguration; fails closed). Tracked in #89.
                foreach (var folderRoleMap in config.FolderRoleMapping)
                {
                    if (role.Equals(folderRoleMap.Role?.Trim(), StringComparison.Ordinal))
                    {
                        folders.AddRange(folderRoleMap.Folders);
                    }
                }
            }

            if (config.EnableLiveTvRoles)
            {
                if (config.LiveTvRoles != null && config.LiveTvRoles.Any(liveTvRole => role.Equals(liveTvRole, StringComparison.Ordinal)))
                {
                    enableLiveTv = true;
                }

                if (config.LiveTvManagementRoles != null && config.LiveTvManagementRoles.Any(managementRole => role.Equals(managementRole, StringComparison.Ordinal)))
                {
                    enableLiveTvManagement = true;
                }
            }
        }

        return new RoleGrants(valid, admin, enableLiveTv, enableLiveTvManagement, folders);
    }

    /// <summary>
    /// The privileges a set of roles grants under a provider configuration.
    /// </summary>
    /// <param name="Valid">Whether any role is on the login allow-list (<see cref="ProviderConfigBase.Roles"/>).</param>
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
