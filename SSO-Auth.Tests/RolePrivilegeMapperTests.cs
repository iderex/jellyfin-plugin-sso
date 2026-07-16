using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for the unified <see cref="RolePrivilegeMapper.Evaluate"/> (#367) — the role→privilege mapping
/// shared by the OpenID and SAML callbacks. Every member it reads lives on
/// <see cref="ProviderConfigBase"/>, so one mapper serves both protocols; the tests run it against both
/// an <see cref="OidConfig"/> and a <see cref="SamlConfig"/>. The three former per-protocol quirks are
/// now reconciled to one robust behavior: role comparison is null-safe both ways (no NullReferenceException
/// on a null role or a null configured entry), the folder-role mapping is null-guarded, and the trusted
/// configured folder-role is trimmed before comparison. Grants are monotonic; the SAML caller ignores
/// <see cref="RolePrivilegeMapper.RoleGrants.Valid"/>.
/// </summary>
public class RolePrivilegeMapperTests
{
    private static OidConfig Oid(Action<OidConfig> configure)
    {
        var config = new OidConfig();
        configure(config);
        return config;
    }

    private static SamlConfig Saml(Action<SamlConfig> configure)
    {
        var config = new SamlConfig();
        configure(config);
        return config;
    }

    [Fact]
    public void UnauthorizedRole_WithPopulatedConfig_GrantsNothing()
    {
        var config = Oid(c =>
        {
            c.Roles = new[] { "user" };
            c.AdminRoles = new[] { "admin" };
            c.EnableFolderRoles = true;
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "media", Folders = new List<string> { "movies" } },
            };
            c.EnableLiveTvRoles = true;
            c.LiveTvRoles = new[] { "tv" };
            c.LiveTvManagementRoles = new[] { "tvadmin" };
        });

        var grants = RolePrivilegeMapper.Evaluate(new[] { "outsider" }, config);

        Assert.False(grants.Valid);
        Assert.False(grants.Admin);
        Assert.False(grants.EnableLiveTv);
        Assert.False(grants.EnableLiveTvManagement);
        Assert.Empty(grants.Folders);
    }

    [Fact]
    public void NoConfiguredRoles_GrantsNothing()
    {
        var grants = RolePrivilegeMapper.Evaluate(new[] { "anything" }, Oid(_ => { }));

        Assert.False(grants.Valid);
        Assert.False(grants.Admin);
        Assert.False(grants.EnableLiveTv);
        Assert.False(grants.EnableLiveTvManagement);
        Assert.Empty(grants.Folders);
    }

    [Fact]
    public void EmptyRoles_GrantsNothing()
    {
        var config = Oid(c =>
        {
            c.Roles = new[] { "jellyfin" };
            c.AdminRoles = new[] { "admins" };
        });

        var grants = RolePrivilegeMapper.Evaluate(Array.Empty<string>(), config);

        Assert.False(grants.Valid);
        Assert.False(grants.Admin);
    }

    [Fact]
    public void RoleOnAllowList_GrantsValid()
    {
        var config = Oid(c => c.Roles = new[] { "users", "jellyfin" });

        Assert.True(RolePrivilegeMapper.Evaluate(new[] { "jellyfin" }, config).Valid);
        Assert.False(RolePrivilegeMapper.Evaluate(new[] { "other" }, config).Valid);
    }

    [Fact]
    public void RoleOnAdminList_GrantsAdmin()
    {
        var config = Oid(c => c.AdminRoles = new[] { "jellyfin-admins" });

        Assert.True(RolePrivilegeMapper.Evaluate(new[] { "jellyfin-admins" }, config).Admin);
        Assert.False(RolePrivilegeMapper.Evaluate(new[] { "jellyfin-users" }, config).Admin);
    }

    [Fact]
    public void RoleMatchingIsOrdinalCaseSensitive()
    {
        var config = Oid(c =>
        {
            c.Roles = new[] { "jellyfin" };
            c.AdminRoles = new[] { "Admins" };
        });

        Assert.False(RolePrivilegeMapper.Evaluate(new[] { "Jellyfin" }, config).Valid);
        Assert.False(RolePrivilegeMapper.Evaluate(new[] { "admins" }, config).Admin);
    }

    [Fact]
    public void MultipleRoles_AnyMatchGrants()
    {
        var config = Oid(c => c.Roles = new[] { "jellyfin" });

        Assert.True(RolePrivilegeMapper.Evaluate(new[] { "nope", "jellyfin", "other" }, config).Valid);
    }

    // --- Folder roles ---

    [Fact]
    public void FolderRolesDisabled_GrantsNoFolders()
    {
        var config = Oid(c =>
        {
            c.EnableFolderRoles = false;
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "media", Folders = new List<string> { "movies" } },
            };
        });

        Assert.Empty(RolePrivilegeMapper.Evaluate(new[] { "media" }, config).Folders);
    }

    [Fact]
    public void FolderRolesEnabled_AddsFoldersForMatchingRole_TrimmingTheConfiguredMapRole()
    {
        // #367: the trusted configured map-role is trimmed before comparison (formerly OpenID-only), so
        // "media" matches "  media  ". The IdP-supplied role is compared raw, so there is no
        // whitespace-injection vector. This now holds for BOTH protocols.
        var config = Oid(c =>
        {
            c.EnableFolderRoles = true;
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "  media  ", Folders = new List<string> { "movies", "shows" } },
                new FolderRoleMap { Role = "music", Folders = new List<string> { "songs" } },
            };
        });

        Assert.Equal(new List<string> { "movies", "shows" }, RolePrivilegeMapper.Evaluate(new[] { "media" }, config).Folders);
    }

    [Fact]
    public void FolderRolesEnabled_Saml_AlsoTrimsTheConfiguredMapRole()
    {
        // #367 reconciliation: the SAML path formerly matched WITHOUT trimming; it now trims like OpenID.
        var config = Saml(c =>
        {
            c.EnableFolderRoles = true;
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "  media  ", Folders = new List<string> { "movies" } },
            };
        });

        Assert.Equal(new List<string> { "movies" }, RolePrivilegeMapper.Evaluate(new[] { "media" }, config).Folders);
    }

    [Fact]
    public void FolderRolesEnabled_AccumulatesAcrossRolesAndMaps_PreservingDuplicates()
    {
        var config = Oid(c =>
        {
            c.EnableFolderRoles = true;
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "media", Folders = new List<string> { "movies" } },
                new FolderRoleMap { Role = "media", Folders = new List<string> { "movies", "shows" } },
                new FolderRoleMap { Role = "music", Folders = new List<string> { "songs" } },
            };
        });

        var grants = RolePrivilegeMapper.Evaluate(new[] { "media", "music" }, config);

        // Order follows role order then mapping order; duplicates are kept (AddRange, no dedup).
        Assert.Equal(new List<string> { "movies", "movies", "shows", "songs" }, grants.Folders);
    }

    [Fact]
    public void FolderRolesEnabled_NullMapping_DoesNotThrow_GrantsNoFolders()
    {
        // #367 reconciliation: the OpenID path formerly threw a NullReferenceException here (a 500,
        // fail-closed). The mapping is now null-guarded in both protocols, so an admin misconfiguration
        // (EnableFolderRoles on, FolderRoleMapping null) grants no folders instead of failing the login.
        var config = Oid(c =>
        {
            c.EnableFolderRoles = true;
            c.FolderRoleMapping = null;
        });

        Assert.Empty(RolePrivilegeMapper.Evaluate(new[] { "media" }, config).Folders);
    }

    // --- Null-safe comparison (reconciled) ---

    [Fact]
    public void NullConfiguredEntry_DoesNotThrow_GrantsNothingForIt()
    {
        // #367 reconciliation: the SAML path formerly threw on a null configured admin entry (the
        // comparison receiver was the configured value). Comparison is now null-safe both ways, so a
        // null entry is simply not a match — no NullReferenceException.
        var config = Saml(c => c.AdminRoles = new[] { "admins", null! });

        Assert.False(RolePrivilegeMapper.Evaluate(new[] { "x" }, config).Admin);
        Assert.True(RolePrivilegeMapper.Evaluate(new[] { "admins" }, config).Admin); // the real entry still matches
    }

    [Fact]
    public void NullRoleFromIdp_DoesNotThrow_GrantsNothingForIt()
    {
        // A null role value from the identity provider is not a match rather than a NullReferenceException.
        var config = Oid(c => c.Roles = new[] { "jellyfin" });

        Assert.True(RolePrivilegeMapper.Evaluate(new[] { null!, "jellyfin" }, config).Valid);
    }

    // --- Live TV roles ---

    [Fact]
    public void LiveTvRolesDisabled_GrantsNoLiveTv()
    {
        var config = Oid(c =>
        {
            c.EnableLiveTvRoles = false;
            c.LiveTvRoles = new[] { "tv" };
            c.LiveTvManagementRoles = new[] { "tv-admin" };
        });

        var grants = RolePrivilegeMapper.Evaluate(new[] { "tv", "tv-admin" }, config);
        Assert.False(grants.EnableLiveTv);
        Assert.False(grants.EnableLiveTvManagement);
    }

    [Fact]
    public void LiveTvRolesEnabled_GrantsLiveTvAndManagement()
    {
        var config = Oid(c =>
        {
            c.EnableLiveTvRoles = true;
            c.LiveTvRoles = new[] { "tv" };
            c.LiveTvManagementRoles = new[] { "tv-admin" };
        });

        Assert.True(RolePrivilegeMapper.Evaluate(new[] { "tv" }, config).EnableLiveTv);
        Assert.True(RolePrivilegeMapper.Evaluate(new[] { "tv-admin" }, config).EnableLiveTvManagement);
        Assert.False(RolePrivilegeMapper.Evaluate(new[] { "tv" }, config).EnableLiveTvManagement);
    }

    [Fact]
    public void LiveTvRolesEnabled_NullRoleLists_DoNotThrowAndGrantNothing()
    {
        var config = Oid(c =>
        {
            c.EnableLiveTvRoles = true;
            c.LiveTvRoles = null;
            c.LiveTvManagementRoles = null;
        });

        var grants = RolePrivilegeMapper.Evaluate(new[] { "tv" }, config);
        Assert.False(grants.EnableLiveTv);
        Assert.False(grants.EnableLiveTvManagement);
    }

    [Fact]
    public void Valid_IsComputedFromRolesForBothConfigTypes()
    {
        // The unified mapper computes Valid from config.Roles for a SamlConfig too; the SAML caller
        // ignores it (SamlLoginPolicy owns validity), but the field is populated the same way.
        var saml = Saml(c => c.Roles = new[] { "jellyfin" });
        Assert.True(RolePrivilegeMapper.Evaluate(new[] { "jellyfin" }, saml).Valid);
        Assert.False(RolePrivilegeMapper.Evaluate(new[] { "other" }, saml).Valid);
    }
}
