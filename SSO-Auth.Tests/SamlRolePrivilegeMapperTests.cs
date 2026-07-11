using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests for <see cref="SamlRolePrivilegeMapper.Evaluate"/> — the role→privilege
/// mapping extracted from the SAML callback. These pin the exact behavior, including the quirks that
/// differ from the OpenID path: the folder-role list is null-checked (no throw), the folder role is
/// matched without trimming, the comparison receiver is the configured value (so a null configured
/// entry throws), and login validity is NOT decided here.
/// </summary>
public class SamlRolePrivilegeMapperTests
{
    private static SamlConfig Config(Action<SamlConfig> configure)
    {
        var config = new SamlConfig();
        configure(config);
        return config;
    }

    [Fact]
    public void NoConfiguredRoles_GrantsNothing()
    {
        var grants = SamlRolePrivilegeMapper.Evaluate(new[] { "anything" }, Config(_ => { }));

        Assert.False(grants.Admin);
        Assert.False(grants.EnableLiveTv);
        Assert.False(grants.EnableLiveTvManagement);
        Assert.Empty(grants.Folders);
    }

    [Fact]
    public void EmptyRoles_GrantsNothing()
    {
        var config = Config(c => c.AdminRoles = new[] { "admins" });
        Assert.False(SamlRolePrivilegeMapper.Evaluate(Array.Empty<string>(), config).Admin);
    }

    [Fact]
    public void RoleOnAdminList_GrantsAdmin()
    {
        var config = Config(c => c.AdminRoles = new[] { "jellyfin-admins" });

        Assert.True(SamlRolePrivilegeMapper.Evaluate(new[] { "jellyfin-admins" }, config).Admin);
        Assert.False(SamlRolePrivilegeMapper.Evaluate(new[] { "jellyfin-users" }, config).Admin);
    }

    [Fact]
    public void RoleMatchingIsOrdinalCaseSensitive()
    {
        var config = Config(c => c.AdminRoles = new[] { "Admins" });
        Assert.False(SamlRolePrivilegeMapper.Evaluate(new[] { "admins" }, config).Admin);
    }

    [Fact]
    public void FolderRolesDisabled_GrantsNoFolders()
    {
        var config = Config(c =>
        {
            c.EnableFolderRoles = false;
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "media", Folders = new List<string> { "movies" } },
            };
        });

        Assert.Empty(SamlRolePrivilegeMapper.Evaluate(new[] { "media" }, config).Folders);
    }

    [Fact]
    public void FolderRolesEnabled_NullMapping_DoesNotThrow_GrantsNoFolders()
    {
        // Unlike the OpenID path, the SAML callback null-checks FolderRoleMapping, so a null mapping
        // with EnableFolderRoles on is a safe no-op (no NullReferenceException).
        var config = Config(c =>
        {
            c.EnableFolderRoles = true;
            c.FolderRoleMapping = null;
        });

        Assert.Empty(SamlRolePrivilegeMapper.Evaluate(new[] { "media" }, config).Folders);
    }

    [Fact]
    public void FolderRolesEnabled_MatchesRoleWithoutTrimming()
    {
        // Unlike the OpenID path, the SAML mapping is matched WITHOUT trimming, so a padded map role
        // does not match an unpadded assertion role.
        var config = Config(c =>
        {
            c.EnableFolderRoles = true;
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "  media  ", Folders = new List<string> { "movies" } },
                new FolderRoleMap { Role = "music", Folders = new List<string> { "songs" } },
            };
        });

        Assert.Empty(SamlRolePrivilegeMapper.Evaluate(new[] { "media" }, config).Folders);
        Assert.Equal(new List<string> { "songs" }, SamlRolePrivilegeMapper.Evaluate(new[] { "music" }, config).Folders);
    }

    [Fact]
    public void FolderRolesEnabled_AccumulatesAcrossRolesAndMaps_PreservingDuplicates()
    {
        var config = Config(c =>
        {
            c.EnableFolderRoles = true;
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "media", Folders = new List<string> { "movies" } },
                new FolderRoleMap { Role = "media", Folders = new List<string> { "movies", "shows" } },
                new FolderRoleMap { Role = "music", Folders = new List<string> { "songs" } },
            };
        });

        var grants = SamlRolePrivilegeMapper.Evaluate(new[] { "media", "music" }, config);
        Assert.Equal(new List<string> { "movies", "movies", "shows", "songs" }, grants.Folders);
    }

    [Fact]
    public void LiveTvRolesDisabled_GrantsNoLiveTv()
    {
        var config = Config(c =>
        {
            c.EnableLiveTvRoles = false;
            c.LiveTvRoles = new[] { "tv" };
            c.LiveTvManagementRoles = new[] { "tv-admin" };
        });

        var grants = SamlRolePrivilegeMapper.Evaluate(new[] { "tv", "tv-admin" }, config);
        Assert.False(grants.EnableLiveTv);
        Assert.False(grants.EnableLiveTvManagement);
    }

    [Fact]
    public void LiveTvRolesEnabled_GrantsLiveTvAndManagement()
    {
        var config = Config(c =>
        {
            c.EnableLiveTvRoles = true;
            c.LiveTvRoles = new[] { "tv" };
            c.LiveTvManagementRoles = new[] { "tv-admin" };
        });

        Assert.True(SamlRolePrivilegeMapper.Evaluate(new[] { "tv" }, config).EnableLiveTv);
        Assert.True(SamlRolePrivilegeMapper.Evaluate(new[] { "tv-admin" }, config).EnableLiveTvManagement);
        Assert.False(SamlRolePrivilegeMapper.Evaluate(new[] { "tv" }, config).EnableLiveTvManagement);
    }

    [Fact]
    public void LiveTvRolesEnabled_NullRoleLists_DoNotThrowAndGrantNothing()
    {
        var config = Config(c =>
        {
            c.EnableLiveTvRoles = true;
            c.LiveTvRoles = null;
            c.LiveTvManagementRoles = null;
        });

        var grants = SamlRolePrivilegeMapper.Evaluate(new[] { "tv" }, config);
        Assert.False(grants.EnableLiveTv);
        Assert.False(grants.EnableLiveTvManagement);
    }

    [Fact]
    public void NullConfiguredAdminRole_Throws()
    {
        // Characterizes the SAML receiver quirk: allowedRole.Equals(role) throws when a configured
        // role entry is null (the loop does not break on an earlier match either). Preserved by the
        // faithful extraction; a null entry is an admin misconfiguration and fails closed.
        var config = Config(c => c.AdminRoles = new string?[] { null });

        Assert.Throws<NullReferenceException>(() => SamlRolePrivilegeMapper.Evaluate(new[] { "x" }, config));
    }

    [Fact]
    public void MultipleRoles_AnyMatchGrantsAdmin()
    {
        var config = Config(c => c.AdminRoles = new[] { "admins" });
        Assert.True(SamlRolePrivilegeMapper.Evaluate(new[] { "nope", "admins", "other" }, config).Admin);
    }

    [Fact]
    public void NullConfiguredAdminRoleAfterAMatch_StillThrows()
    {
        // The matching loop has no early break, so a null configured entry after an earlier match
        // still throws — this is exactly why the extraction keeps foreach rather than Any(predicate),
        // which would short-circuit before reaching the null entry. Preserves the original behavior.
        var config = Config(c => c.AdminRoles = new[] { "admins", null });

        Assert.Throws<NullReferenceException>(() => SamlRolePrivilegeMapper.Evaluate(new[] { "admins" }, config));
    }
}
