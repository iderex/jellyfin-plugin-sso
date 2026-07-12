using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Maps the roles carried by a SAML assertion to the privileges they grant, according to the
/// provider configuration. Pure: it derives the grants from (roles, config) and makes no decision
/// about the session (login validity is decided separately by <see cref="SamlLoginPolicy"/>), so
/// every grant here is monotonic — the caller OR-s the booleans and appends the folders.
///
/// This mirrors the SAML callback's per-role logic one-for-one, including its quirks, which differ
/// from the OpenID path (see <see cref="OidcRolePrivilegeMapper"/>): the comparison receiver is the
/// configured value (<c>allowedRole.Equals(role)</c>), the folder-role list IS null-checked, and the
/// folder role is compared without trimming. The matching loops are intentionally kept as
/// no-break <c>foreach</c> (not LINQ) so the exact iteration and exception behavior — e.g. a
/// NullReferenceException on a null role entry even after an earlier match — is preserved.
/// </summary>
internal static class SamlRolePrivilegeMapper
{
    /// <summary>
    /// Evaluates the privileges granted by the given roles under the given configuration.
    /// </summary>
    /// <param name="roles">The role values carried by the (already signature-validated) assertion.</param>
    /// <param name="config">The SAML provider configuration.</param>
    /// <returns>The granted privileges; booleans are false and the folder list empty when nothing matches.</returns>
    internal static RoleGrants Evaluate(IEnumerable<string> roles, SamlConfig config)
    {
        var admin = false;
        var enableLiveTv = false;
        var enableLiveTvManagement = false;
        var folders = new List<string>();

        foreach (string role in roles)
        {
            if (config.AdminRoles != null)
            {
                foreach (string allowedRole in config.AdminRoles)
                {
                    if (allowedRole.Equals(role, StringComparison.Ordinal))
                    {
                        admin = true;
                    }
                }
            }

            if (config.EnableFolderRoles && config.FolderRoleMapping != null)
            {
                foreach (FolderRoleMap folderRoleMap in config.FolderRoleMapping)
                {
                    if (folderRoleMap.Role.Equals(role, StringComparison.Ordinal))
                    {
                        folders.AddRange(folderRoleMap.Folders);
                    }
                }
            }

            if (config.EnableLiveTvRoles)
            {
                if (config.LiveTvRoles != null)
                {
                    foreach (string allowedLiveTvRole in config.LiveTvRoles)
                    {
                        if (allowedLiveTvRole.Equals(role, StringComparison.Ordinal))
                        {
                            enableLiveTv = true;
                        }
                    }
                }

                if (config.LiveTvManagementRoles != null)
                {
                    foreach (string allowedLiveTvManagementRole in config.LiveTvManagementRoles)
                    {
                        if (allowedLiveTvManagementRole.Equals(role, StringComparison.Ordinal))
                        {
                            enableLiveTvManagement = true;
                        }
                    }
                }
            }
        }

        return new RoleGrants(admin, enableLiveTv, enableLiveTvManagement, folders);
    }

    /// <summary>
    /// The privileges a set of SAML roles grants under a provider configuration.
    /// </summary>
    /// <param name="Admin">Whether any role is on the admin list.</param>
    /// <param name="EnableLiveTv">Whether any role grants Live TV (only when role-based Live TV is enabled).</param>
    /// <param name="EnableLiveTvManagement">Whether any role grants Live TV management (only when role-based Live TV is enabled).</param>
    /// <param name="Folders">The folders granted by matching folder-role mappings (only when folder roles are enabled).</param>
    internal readonly record struct RoleGrants(
        bool Admin,
        bool EnableLiveTv,
        bool EnableLiveTvManagement,
        List<string> Folders);
}
