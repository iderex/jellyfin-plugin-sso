using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Derives the per-login authorize-state privileges (admin, Live TV, Live TV management, folder
/// access) from a validated SAML assertion's roles and the provider configuration. Pure: it reads
/// only (roles, config) and returns the derived values, which the SAML callback applies to the
/// session parameters. Login validity is decided separately by <see cref="SamlLoginPolicy"/> and the
/// username is the assertion's NameID, so — unlike the OpenID builder
/// (<see cref="OidcAuthorizeStateBuilder"/>) — neither is derived here. Mirrors, one-for-one, the
/// privilege derivation that used to live inline in the callback.
/// </summary>
internal static class SamlAuthorizeStateBuilder
{
    /// <summary>
    /// Derives the authorize-state privileges from the assertion's roles and the provider configuration.
    /// </summary>
    /// <param name="roles">The role values carried by the (already signature-validated) assertion.</param>
    /// <param name="config">The SAML provider configuration.</param>
    /// <returns>The derived authorize-state privileges.</returns>
    internal static SamlAuthorizeState Build(IEnumerable<string> roles, SamlConfig config)
    {
        // Assemble the role-derived privileges (folders, admin, Live TV) in the single shared home
        // (#508). Login validity is decided separately by SamlLoginPolicy, so the assembled Valid is
        // ignored here.
        var privileges = RolePrivilegeMapper.AssemblePrivileges(roles, config);

        // Assemble the generic role→permission grants for the full boolean PermissionKind surface (#164).
        // Default-deny and empty when the feature is off, so it changes nothing for existing deployments.
        var permissionGrants = PermissionRolePolicy.Map(roles, config);

        return new SamlAuthorizeState(privileges.Admin, privileges.EnableLiveTv, privileges.EnableLiveTvManagement, privileges.Folders, permissionGrants);
    }

    /// <summary>
    /// The authorize-state privileges derived from a SAML login.
    /// </summary>
    /// <param name="Admin">Whether the login grants administrator rights.</param>
    /// <param name="EnableLiveTv">Whether the login grants Live TV access.</param>
    /// <param name="EnableLiveTvManagement">Whether the login grants Live TV management.</param>
    /// <param name="Folders">The enabled folders (statically enabled plus role-granted).</param>
    /// <param name="PermissionGrants">The generic role→permission grants (#164); null (treated as empty) when the feature is off.</param>
    internal readonly record struct SamlAuthorizeState(
        bool Admin,
        bool EnableLiveTv,
        bool EnableLiveTvManagement,
        List<string> Folders,
        IReadOnlyList<PermissionGrant>? PermissionGrants = null);
}
