using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests for <see cref="OidcRolePrivilegeMapper.Evaluate"/> — the role→privilege
/// mapping extracted from the OID callback. These pin the exact behavior (including its quirks) so
/// the extraction is a proven no-op and the mapping can be reasoned about in isolation.
/// </summary>
public class OidcRolePrivilegeMapperTests
{
    private static OidConfig Config(Action<OidConfig> configure)
    {
        var config = new OidConfig();
        configure(config);
        return config;
    }

    [Fact]
    public void NoConfiguredRoles_GrantsNothing()
    {
        var grants = OidcRolePrivilegeMapper.Evaluate(new[] { "anything" }, Config(_ => { }));

        Assert.False(grants.Valid);
        Assert.False(grants.Admin);
        Assert.False(grants.EnableLiveTv);
        Assert.False(grants.EnableLiveTvManagement);
        Assert.Empty(grants.Folders);
    }

    [Fact]
    public void EmptyRoles_GrantsNothing()
    {
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin" };
            c.AdminRoles = new[] { "admins" };
        });

        var grants = OidcRolePrivilegeMapper.Evaluate(Array.Empty<string>(), config);

        Assert.False(grants.Valid);
        Assert.False(grants.Admin);
    }

    [Fact]
    public void RoleOnAllowList_GrantsValid()
    {
        var config = Config(c => c.Roles = new[] { "users", "jellyfin" });

        Assert.True(OidcRolePrivilegeMapper.Evaluate(new[] { "jellyfin" }, config).Valid);
        Assert.False(OidcRolePrivilegeMapper.Evaluate(new[] { "other" }, config).Valid);
    }

    [Fact]
    public void RoleOnAdminList_GrantsAdmin()
    {
        var config = Config(c => c.AdminRoles = new[] { "jellyfin-admins" });

        Assert.True(OidcRolePrivilegeMapper.Evaluate(new[] { "jellyfin-admins" }, config).Admin);
        Assert.False(OidcRolePrivilegeMapper.Evaluate(new[] { "jellyfin-users" }, config).Admin);
    }

    [Fact]
    public void RoleMatchingIsOrdinalCaseSensitive()
    {
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin" };
            c.AdminRoles = new[] { "Admins" };
        });

        Assert.False(OidcRolePrivilegeMapper.Evaluate(new[] { "Jellyfin" }, config).Valid);
        Assert.False(OidcRolePrivilegeMapper.Evaluate(new[] { "admins" }, config).Admin);
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

        Assert.Empty(OidcRolePrivilegeMapper.Evaluate(new[] { "media" }, config).Folders);
    }

    [Fact]
    public void FolderRolesEnabled_AddsFoldersForMatchingRole_TrimmingMapRole()
    {
        var config = Config(c =>
        {
            c.EnableFolderRoles = true;
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "  media  ", Folders = new List<string> { "movies", "shows" } },
                new FolderRoleMap { Role = "music", Folders = new List<string> { "songs" } },
            };
        });

        // The map Role is trimmed before comparison, so "media" matches "  media  ".
        var grants = OidcRolePrivilegeMapper.Evaluate(new[] { "media" }, config);
        Assert.Equal(new List<string> { "movies", "shows" }, grants.Folders);
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

        var grants = OidcRolePrivilegeMapper.Evaluate(new[] { "media", "music" }, config);

        // Order follows role order then mapping order; duplicates are kept (AddRange, no dedup).
        Assert.Equal(new List<string> { "movies", "movies", "shows", "songs" }, grants.Folders);
    }

    [Fact]
    public void FolderRolesEnabled_NullMapping_Throws()
    {
        // Characterizes a pre-existing latent NullReferenceException: EnableFolderRoles is on but
        // FolderRoleMapping is null (the OID path, unlike SAML, does not null-check it). Preserved
        // by the faithful extraction and tracked separately; a hostile IdP cannot trigger it (it is
        // an admin misconfiguration), and it fails closed (a 500, no session).
        var config = Config(c =>
        {
            c.EnableFolderRoles = true;
            c.FolderRoleMapping = null;
        });

        Assert.Throws<NullReferenceException>(() => OidcRolePrivilegeMapper.Evaluate(new[] { "media" }, config));
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

        var grants = OidcRolePrivilegeMapper.Evaluate(new[] { "tv", "tv-admin" }, config);
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

        Assert.True(OidcRolePrivilegeMapper.Evaluate(new[] { "tv" }, config).EnableLiveTv);
        Assert.True(OidcRolePrivilegeMapper.Evaluate(new[] { "tv-admin" }, config).EnableLiveTvManagement);
        Assert.False(OidcRolePrivilegeMapper.Evaluate(new[] { "tv" }, config).EnableLiveTvManagement);
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

        var grants = OidcRolePrivilegeMapper.Evaluate(new[] { "tv" }, config);
        Assert.False(grants.EnableLiveTv);
        Assert.False(grants.EnableLiveTvManagement);
    }

    [Fact]
    public void MultipleRoles_AnyMatchGrants()
    {
        var config = Config(c => c.Roles = new[] { "jellyfin" });

        Assert.True(OidcRolePrivilegeMapper.Evaluate(new[] { "nope", "jellyfin", "other" }, config).Valid);
    }
}
