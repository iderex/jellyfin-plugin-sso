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
        // Folders start from the statically-enabled set only when folder roles are off; role-granted
        // folders are appended below.
        var folders = !config.EnableFolderRoles && config.EnabledFolders != null
            ? new List<string>(config.EnabledFolders)
            : new List<string>();

        // Map the roles to privileges and merge (monotonic: only ever grants). Login validity is
        // decided separately by SamlLoginPolicy, so it is not mapped here. Admin starts false, so its
        // OR-merge is a plain assignment; Live TV starts from the config default and is OR-ed.
        var grants = SamlRolePrivilegeMapper.Evaluate(roles, config);
        var admin = grants.Admin;
        var enableLiveTv = config.EnableLiveTv | grants.EnableLiveTv;
        var enableLiveTvManagement = config.EnableLiveTvManagement | grants.EnableLiveTvManagement;
        folders.AddRange(grants.Folders);

        return new SamlAuthorizeState(admin, enableLiveTv, enableLiveTvManagement, folders);
    }

    /// <summary>
    /// The authorize-state privileges derived from a SAML login.
    /// </summary>
    /// <param name="Admin">Whether the login grants administrator rights.</param>
    /// <param name="EnableLiveTv">Whether the login grants Live TV access.</param>
    /// <param name="EnableLiveTvManagement">Whether the login grants Live TV management.</param>
    /// <param name="Folders">The enabled folders (statically enabled plus role-granted).</param>
    internal readonly record struct SamlAuthorizeState(
        bool Admin,
        bool EnableLiveTv,
        bool EnableLiveTvManagement,
        List<string> Folders);
}
