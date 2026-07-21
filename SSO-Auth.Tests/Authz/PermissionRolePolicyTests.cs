// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="PermissionRolePolicy"/> — the generic role→permission mapping (#164) that extends
/// the dedicated admin/folder/Live TV surface to the full boolean <see cref="PermissionKind"/> surface.
/// These pin the security-load-bearing guarantees: the mapping is default-deny and authoritative (a
/// configured permission is granted only when a matching role is present and otherwise EXPLICITLY revoked,
/// so a missing/empty/unmapped claim never grants), the feature is off by default, the dedicated
/// permissions (notably IsAdministrator) cannot be granted through the generic map, and role matching is
/// ordinal. Each grant/deny case would flip to a failing assertion if the policy were loosened.
/// </summary>
public class PermissionRolePolicyTests
{
    private static OidConfig Config(bool enable, params PermissionRoleMap[] mappings) => new OidConfig
    {
        EnablePermissionRoles = enable,
        PermissionRoleMappings = mappings.ToList(),
    };

    private static PermissionRoleMap Map(string permission, params string[] roles) => new PermissionRoleMap
    {
        Permission = permission,
        Roles = roles,
    };

    private static bool? GrantFor(IReadOnlyList<PermissionGrant> grants, PermissionKind kind)
    {
        var matches = grants.Where(g => g.Kind == kind).ToList();
        return matches.Count == 0 ? null : matches[0].Granted;
    }

    // --- Feature gate: off by default, nothing is managed ---

    [Fact]
    public void Map_FeatureOff_EvenWithAMatchingRole_ReturnsEmpty()
    {
        // The master switch is the fail-closed default: with it off, SSO manages no extra permission even
        // when a mapping would match — byte-for-byte the pre-#164 behavior.
        var config = Config(enable: false, Map("EnableContentDownloading", "media"));

        var grants = PermissionRolePolicy.Map(new[] { "media" }, config);

        Assert.Empty(grants);
    }

    [Fact]
    public void Map_FeatureOn_NoMappings_ReturnsEmpty()
    {
        var grants = PermissionRolePolicy.Map(new[] { "media" }, Config(enable: true));

        Assert.Empty(grants);
    }

    // --- Grant / default-deny core ---

    [Fact]
    public void Map_MatchingRole_GrantsThePermission()
    {
        var config = Config(enable: true, Map("EnableContentDownloading", "downloaders"));

        var grants = PermissionRolePolicy.Map(new[] { "downloaders" }, config);

        Assert.Equal(true, GrantFor(grants, PermissionKind.EnableContentDownloading));
    }

    [Fact]
    public void Map_ConfiguredPermissionButNoMatchingRole_ExplicitlyRevokes()
    {
        // Default-deny AND authoritative: a permission the admin listed is still emitted when no role
        // matches, as an explicit REVOKE (false). A missing claim never leaves a stale grant in place and
        // never silently grants.
        var config = Config(enable: true, Map("EnableContentDownloading", "downloaders"));

        var grants = PermissionRolePolicy.Map(new[] { "someone-else" }, config);

        Assert.Equal(false, GrantFor(grants, PermissionKind.EnableContentDownloading));
    }

    [Fact]
    public void Map_UnmappedPermission_IsNeverEmitted()
    {
        // A permission not listed at all is not in the result, so the mint leaves it untouched (Jellyfin's
        // own default governs it). Only EXPLICITLY configured permissions are managed by SSO.
        var config = Config(enable: true, Map("EnableContentDownloading", "downloaders"));

        var grants = PermissionRolePolicy.Map(new[] { "downloaders" }, config);

        Assert.Null(GrantFor(grants, PermissionKind.EnableContentDeletion));
        Assert.Null(GrantFor(grants, PermissionKind.EnableMediaConversion));
    }

    // --- No privilege escalation through the generic map ---

    [Theory]
    [InlineData("IsAdministrator")]
    [InlineData("EnableAllFolders")]
    [InlineData("EnableLiveTvAccess")]
    [InlineData("EnableLiveTvManagement")]
    [InlineData("IsDisabled")] // #165 Finding H1: never role-mappable — an SSO login must not disable an account
    public void Map_DedicatedPermission_IsNeverGrantedThroughTheGenericMap_EvenWithAMatchingRole(string permission)
    {
        // The four permissions with their own dedicated config fields/flows cannot be granted here — this is
        // the anti-escalation guarantee: an admin cannot mint IsAdministrator (or all-folders / Live TV)
        // through the generic map, even when the login carries the mapped role. IsDisabled is barred for a
        // stronger reason (#165 Finding H1): a role that mapped to it would let a single SSO login lock the
        // account (including the break-glass admin) out. All resolve to no grant.
        var config = Config(enable: true, Map(permission, "privileged"));

        var grants = PermissionRolePolicy.Map(new[] { "privileged" }, config);

        Assert.Empty(grants);
    }

    [Fact]
    public void Map_IsDisabled_IsNeverEmitted_EvenWithoutAMatchingRole()
    {
        // #165 Finding H1, the negative fail-closed branch: because IsDisabled is barred from the generic map,
        // it is emitted NEITHER as a grant NOR as an authoritative revoke — it never reaches the mint's grant
        // list in any form, so no SSO login can ever toggle the account-disabled flag. (Contrast an ordinary
        // permission, which is emitted as an explicit revoke when no role matches.)
        var config = Config(enable: true, Map("IsDisabled", "some-role"));

        var granted = PermissionRolePolicy.Map(new[] { "some-role" }, config);
        var revoked = PermissionRolePolicy.Map(new[] { "no-match" }, config);

        Assert.Null(GrantFor(granted, PermissionKind.IsDisabled));
        Assert.Null(GrantFor(revoked, PermissionKind.IsDisabled));
    }

    [Fact]
    public void Map_UnknownPermissionName_GrantsNothing()
    {
        // Fail closed: an unknown permission name resolves to no grant (it is also rejected at config-save
        // validation, but the runtime path must not throw on it either).
        var config = Config(enable: true, Map("NotARealPermission", "any"));

        var grants = PermissionRolePolicy.Map(new[] { "any" }, config);

        Assert.Empty(grants);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Map_BlankPermissionName_GrantsNothing(string? permission)
    {
        var config = Config(enable: true, Map(permission!, "any"));

        var grants = PermissionRolePolicy.Map(new[] { "any" }, config);

        Assert.Empty(grants);
    }

    // --- Ordinal role matching, config-side trim, null-safety ---

    [Fact]
    public void Map_RoleMatchingIsOrdinalCaseSensitive()
    {
        // Deterministic ordinal matching (consistent with the auth-path comparison hardening): a differently
        // cased login role is NOT a match, so the permission is explicitly revoked rather than granted.
        var config = Config(enable: true, Map("EnableContentDownloading", "Downloaders"));

        var grants = PermissionRolePolicy.Map(new[] { "downloaders" }, config);

        Assert.Equal(false, GrantFor(grants, PermissionKind.EnableContentDownloading));
    }

    [Fact]
    public void Map_ConfiguredRoleIsTrimmedBeforeComparison_LoginRoleComparedRaw()
    {
        // The configured (trusted, admin-authored) role is trimmed; the IdP-supplied role is compared raw
        // and ordinal — mirroring the folder-role comparison hardening (#367), so stray config whitespace is
        // not a mismatch while an IdP role cannot inject whitespace to force a match.
        var config = Config(enable: true, Map("EnableContentDownloading", "  downloaders  "));

        var grants = PermissionRolePolicy.Map(new[] { "downloaders" }, config);

        Assert.Equal(true, GrantFor(grants, PermissionKind.EnableContentDownloading));
    }

    [Fact]
    public void Map_NullRolesArray_DoesNotThrow_Revokes()
    {
        var config = Config(enable: true, new PermissionRoleMap { Permission = "EnableContentDownloading", Roles = null });

        var grants = PermissionRolePolicy.Map(new[] { "media" }, config);

        Assert.Equal(false, GrantFor(grants, PermissionKind.EnableContentDownloading));
    }

    [Fact]
    public void Map_NullEntryAmongMappings_IsSkipped()
    {
        var config = new OidConfig
        {
            EnablePermissionRoles = true,
            PermissionRoleMappings = new List<PermissionRoleMap> { null!, Map("EnableContentDownloading", "media") },
        };

        var grants = PermissionRolePolicy.Map(new[] { "media" }, config);

        Assert.Equal(true, GrantFor(grants, PermissionKind.EnableContentDownloading));
    }

    // --- Determinism: duplicates OR-ed, emitted once ---

    [Fact]
    public void Map_SamePermissionInSeveralEntries_IsOredAndEmittedOnce()
    {
        // A permission named in several entries is granted iff ANY entry's roles match (OR), and it is
        // emitted exactly once so the mint never applies it twice with conflicting values.
        var config = Config(
            enable: true,
            Map("EnableContentDownloading", "no-match"),
            Map("EnableContentDownloading", "yes-match"));

        var grants = PermissionRolePolicy.Map(new[] { "yes-match" }, config);

        Assert.Single(grants, g => g.Kind == PermissionKind.EnableContentDownloading);
        Assert.Equal(true, GrantFor(grants, PermissionKind.EnableContentDownloading));
    }

    [Fact]
    public void Map_MultipleDistinctPermissions_AllEmitted()
    {
        var config = Config(
            enable: true,
            Map("EnableContentDownloading", "media"),
            Map("EnableContentDeletion", "editors"),
            Map("EnableCollectionManagement", "editors"));

        var grants = PermissionRolePolicy.Map(new[] { "media", "editors" }, config);

        Assert.Equal(true, GrantFor(grants, PermissionKind.EnableContentDownloading));
        Assert.Equal(true, GrantFor(grants, PermissionKind.EnableContentDeletion));
        Assert.Equal(true, GrantFor(grants, PermissionKind.EnableCollectionManagement));
    }

    // --- Classify: the validation predicate ---

    [Theory]
    [InlineData("EnableContentDownloading")]
    [InlineData("EnableContentDeletion")]
    [InlineData("EnableSubtitleManagement")]
    public void Classify_KnownNonDedicatedPermission_IsValid(string permission)
    {
        Assert.Equal(PermissionRolePolicy.PermissionNameStatus.Valid, PermissionRolePolicy.Classify(permission));
    }

    [Theory]
    [InlineData("IsAdministrator")]
    [InlineData("EnableAllFolders")]
    [InlineData("EnableLiveTvAccess")]
    [InlineData("EnableLiveTvManagement")]
    [InlineData("IsDisabled")] // #165 Finding H1: barred from role mapping alongside the dedicated set
    public void Classify_DedicatedPermission_IsDedicated(string permission)
    {
        Assert.Equal(PermissionRolePolicy.PermissionNameStatus.Dedicated, PermissionRolePolicy.Classify(permission));
    }

    [Theory]
    [InlineData("NotARealPermission")]
    [InlineData("enablecontentdownloading")] // mis-cased: canonical name comparison is ordinal
    [InlineData("11")] // a numeric string must not resolve to a permission by ordinal value
    [InlineData("EnableContentDownloading ")] // trailing space is trimmed, so this is actually valid — see below
    public void Classify_UnknownOrMiscasedName_IsUnknown_ExceptTrimmedValid(string permission)
    {
        var status = PermissionRolePolicy.Classify(permission);

        // The trimmed-but-otherwise-valid name is Valid (leading/trailing whitespace is trimmed); every
        // other case here is Unknown.
        if (permission.Trim() == "EnableContentDownloading")
        {
            Assert.Equal(PermissionRolePolicy.PermissionNameStatus.Valid, status);
        }
        else
        {
            Assert.Equal(PermissionRolePolicy.PermissionNameStatus.Unknown, status);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Classify_BlankName_IsEmpty(string? permission)
    {
        Assert.Equal(PermissionRolePolicy.PermissionNameStatus.Empty, PermissionRolePolicy.Classify(permission));
    }
}
