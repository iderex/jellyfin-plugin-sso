using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests for <see cref="SamlAuthorizeStateBuilder.Build"/> — the admin/Live TV/
/// folder privilege derivation extracted from the SAML callback. These pin the exact behavior (folder
/// defaulting, the config-default-then-role-grant merge for Live TV, and the admin/folder grants) so
/// the extraction is a proven no-op. Login validity and the username are decided elsewhere, so they
/// are not part of the derivation and not tested here.
/// </summary>
public class SamlAuthorizeStateBuilderTests
{
    private static SamlConfig Config(System.Action<SamlConfig> configure)
    {
        var config = new SamlConfig();
        configure(config);
        return config;
    }

    [Fact]
    public void NoRoles_NoConfigDefaults_YieldsNoPrivileges()
    {
        var result = SamlAuthorizeStateBuilder.Build(new List<string>(), Config(_ => { }));

        Assert.False(result.Admin);
        Assert.False(result.EnableLiveTv);
        Assert.False(result.EnableLiveTvManagement);
        Assert.Empty(result.Folders);
    }

    [Fact]
    public void LiveTv_DefaultsFromConfig_EvenWithoutRoles()
    {
        var config = Config(c =>
        {
            c.EnableLiveTv = true;
            c.EnableLiveTvManagement = true;
        });

        var result = SamlAuthorizeStateBuilder.Build(new List<string>(), config);

        Assert.True(result.EnableLiveTv);
        Assert.True(result.EnableLiveTvManagement);
    }

    [Fact]
    public void FolderRolesOff_CopiesEnabledFolders()
    {
        var config = Config(c =>
        {
            c.EnableFolderRoles = false;
            c.EnabledFolders = new[] { "movies", "shows" };
        });

        var result = SamlAuthorizeStateBuilder.Build(new List<string>(), config);

        Assert.Equal(new List<string> { "movies", "shows" }, result.Folders);
    }

    [Fact]
    public void FolderRolesOn_IgnoresStaticFolders_AppendsRoleGranted()
    {
        var config = Config(c =>
        {
            c.EnableFolderRoles = true;
            c.EnabledFolders = new[] { "static" };
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "media", Folders = new List<string> { "movies" } },
            };
        });

        var result = SamlAuthorizeStateBuilder.Build(new List<string> { "media" }, config);

        // Folder roles on → the statically-enabled set is NOT copied; only role-granted folders apply.
        Assert.Equal(new List<string> { "movies" }, result.Folders);
    }

    [Fact]
    public void AdminRole_GrantsAdmin()
    {
        var config = Config(c => c.AdminRoles = new[] { "admins" });

        var result = SamlAuthorizeStateBuilder.Build(new List<string> { "admins" }, config);

        Assert.True(result.Admin);
    }

    [Fact]
    public void NonMatchingRole_GrantsNothing()
    {
        var config = Config(c =>
        {
            c.AdminRoles = new[] { "admins" };
            c.EnableLiveTvRoles = true;
            c.LiveTvRoles = new[] { "tv" };
        });

        var result = SamlAuthorizeStateBuilder.Build(new List<string> { "outsiders" }, config);

        Assert.False(result.Admin);
        Assert.False(result.EnableLiveTv);
    }

    [Fact]
    public void LiveTv_GrantedByRole_WhenConfigDefaultOff()
    {
        // Pins the role-grant OR for the plain Live TV flag: the config default is off, so a true
        // result can only come from the role grant being merged in.
        var config = Config(c =>
        {
            c.EnableLiveTv = false;
            c.EnableLiveTvRoles = true;
            c.LiveTvRoles = new[] { "tv" };
        });

        var result = SamlAuthorizeStateBuilder.Build(new List<string> { "tv" }, config);

        Assert.True(result.EnableLiveTv);
    }

    [Fact]
    public void LiveTvManagement_GrantedByRole()
    {
        var config = Config(c =>
        {
            c.EnableLiveTvRoles = true;
            c.LiveTvManagementRoles = new[] { "tv-admin" };
        });

        var result = SamlAuthorizeStateBuilder.Build(new List<string> { "tv-admin" }, config);

        Assert.True(result.EnableLiveTvManagement);
    }

    [Fact]
    public void LiveTv_ConfigDefaultAndRoleGrant_StaysTrue()
    {
        // Pins the (true, true) row of the OR merge: a config default AND a role grant together must
        // still yield true (an accidental XOR would flip it off).
        var config = Config(c =>
        {
            c.EnableLiveTv = true;
            c.EnableLiveTvManagement = true;
            c.EnableLiveTvRoles = true;
            c.LiveTvRoles = new[] { "tv" };
            c.LiveTvManagementRoles = new[] { "tv" };
        });

        var result = SamlAuthorizeStateBuilder.Build(new List<string> { "tv" }, config);

        Assert.True(result.EnableLiveTv);
        Assert.True(result.EnableLiveTvManagement);
    }

    [Fact]
    public void LiveTvRolesDisabled_RoleDoesNotGrantLiveTv()
    {
        // EnableLiveTvRoles is off, so a matching Live TV role is ignored (faithful to the mapper).
        var config = Config(c =>
        {
            c.EnableLiveTvRoles = false;
            c.LiveTvRoles = new[] { "tv" };
        });

        var result = SamlAuthorizeStateBuilder.Build(new List<string> { "tv" }, config);

        Assert.False(result.EnableLiveTv);
    }

    [Fact]
    public void PermissionRoles_AreThreadedFromRolesOntoTheDerivedState()
    {
        // #164 wiring (SAML side, symmetric with the OIDC builder): the generic role→permission grants
        // are derived from the assertion's roles and the provider config and carried on the derived state
        // (thence to the mint). The matched role grants its permission; a configured-but-unmatched
        // permission is explicitly revoked. Pins the SAML grant-threading branch so a regression that drops
        // it (silently losing all SAML grants AND default-deny revokes) fails here.
        var config = Config(c =>
        {
            c.EnablePermissionRoles = true;
            c.PermissionRoleMappings = new List<PermissionRoleMap>
            {
                new PermissionRoleMap { Permission = "EnableContentDownloading", Roles = new[] { "downloaders" } },
                new PermissionRoleMap { Permission = "EnableContentDeletion", Roles = new[] { "deleters" } },
            };
        });

        var result = SamlAuthorizeStateBuilder.Build(new List<string> { "downloaders" }, config);

        Assert.NotNull(result.PermissionGrants);
        Assert.Contains(result.PermissionGrants!, g => g.Kind == Jellyfin.Database.Implementations.Enums.PermissionKind.EnableContentDownloading && g.Granted);
        Assert.Contains(result.PermissionGrants!, g => g.Kind == Jellyfin.Database.Implementations.Enums.PermissionKind.EnableContentDeletion && !g.Granted);
    }

    [Fact]
    public void PermissionRoles_FeatureOff_LeavesTheGrantsEmpty()
    {
        // With the master switch off, no generic grants are derived even when a mapping and a matching role
        // are present (default-deny; Jellyfin's own defaults govern).
        var config = Config(c =>
        {
            c.EnablePermissionRoles = false;
            c.PermissionRoleMappings = new List<PermissionRoleMap>
            {
                new PermissionRoleMap { Permission = "EnableContentDownloading", Roles = new[] { "downloaders" } },
            };
        });

        var result = SamlAuthorizeStateBuilder.Build(new List<string> { "downloaders" }, config);

        Assert.NotNull(result.PermissionGrants);
        Assert.Empty(result.PermissionGrants!);
    }
}
