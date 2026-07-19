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
                    if (string.Equals(role, folderRoleMap.Role?.Trim(), StringComparison.Ordinal) && folderRoleMap.Folders != null)
                    {
                        // A null Folders on a matching entry (a config/deserialization edge) grants nothing
                        // for it rather than throwing an ArgumentNullException — fail closed, like IsOnList (#675).
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

    /// <summary>
    /// Assembles the full authorize-state privilege set for a login: the statically-enabled folders
    /// (when folder roles are off) plus the role-granted folders, and the config-default-then-role-grant
    /// merge for admin / Live TV / Live TV management. Single home for the post-<see cref="Evaluate"/>
    /// merge that used to be duplicated, byte-identical, in the OpenID and SAML authorize-state builders
    /// (#508). The OpenID builder OR-s the returned <see cref="AssembledPrivileges.Valid"/> into its own
    /// running validity; the SAML builder ignores it — validity there is decided by
    /// <see cref="SamlLoginPolicy"/>, not here.
    /// </summary>
    /// <param name="roles">The roles extracted from the verified login (OpenID claims or SAML attributes).</param>
    /// <param name="config">The provider configuration.</param>
    /// <returns>The assembled privileges, ready for the caller to fold into its authorize state.</returns>
    internal static AssembledPrivileges AssemblePrivileges(IEnumerable<string> roles, ProviderConfigBase config)
    {
        // Folders start from the statically-enabled set only when folder roles are off; role-granted
        // folders are appended below.
        var folders = !config.EnableFolderRoles && config.EnabledFolders != null
            ? new List<string>(config.EnabledFolders)
            : new List<string>();

        var grants = Evaluate(roles, config);
        folders.AddRange(grants.Folders);

        return new AssembledPrivileges(
            grants.Valid,
            grants.Admin,
            config.EnableLiveTv || grants.EnableLiveTv,
            config.EnableLiveTvManagement || grants.EnableLiveTvManagement,
            folders);
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

    /// <summary>
    /// The assembled authorize-state privileges for a login, produced by <see cref="AssemblePrivileges"/>.
    /// </summary>
    /// <param name="Valid">Whether any role is on the login allow-list. Ignored by the SAML caller, whose validity is decided by <see cref="SamlLoginPolicy"/>.</param>
    /// <param name="Admin">Whether the login grants administrator rights.</param>
    /// <param name="EnableLiveTv">Whether the login grants Live TV access (config default OR role grant).</param>
    /// <param name="EnableLiveTvManagement">Whether the login grants Live TV management (config default OR role grant).</param>
    /// <param name="Folders">The enabled folders (statically enabled plus role-granted).</param>
    internal readonly record struct AssembledPrivileges(
        bool Valid,
        bool Admin,
        bool EnableLiveTv,
        bool EnableLiveTvManagement,
        List<string> Folders);
}
