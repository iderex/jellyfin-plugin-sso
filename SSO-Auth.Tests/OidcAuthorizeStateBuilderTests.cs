using System;
using System.Collections.Generic;
using System.Security.Claims;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests for <see cref="OidcAuthorizeStateBuilder.Build"/> — the username/validity/
/// avatar/folder derivation extracted from the OID callback. These pin the exact behavior (including
/// the last-claim-wins username, the sub-claim fallback, and the fail-closed null-Roles throw) so the
/// extraction is a proven no-op and the derivation is testable in isolation.
/// </summary>
public class OidcAuthorizeStateBuilderTests
{
    private static OidConfig Config(Action<OidConfig> configure)
    {
        var config = new OidConfig();
        configure(config);
        return config;
    }

    private static List<Claim> Claims(params (string Type, string Value)[] claims)
    {
        var list = new List<Claim>();
        foreach (var (type, value) in claims)
        {
            list.Add(new Claim(type, value));
        }

        return list;
    }

    [Fact]
    public void NoClaims_NoRolesConfigured_NotValid()
    {
        var result = OidcAuthorizeStateBuilder.Build(Claims(), Config(_ => { }));

        Assert.Null(result.Username);
        Assert.False(result.Valid);
        Assert.False(result.Admin);
        Assert.False(result.EnableLiveTv);
        Assert.False(result.EnableLiveTvManagement);
        Assert.Empty(result.Folders);
        Assert.Null(result.AvatarUrl);
    }

    [Fact]
    public void PreferredUsernameClaim_NoRolesConfigured_IsValid()
    {
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice")), Config(_ => { }));

        Assert.Equal("alice", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void CustomUsernameClaim_IsRespected()
    {
        var config = Config(c => c.DefaultUsernameClaim = "email");
        var result = OidcAuthorizeStateBuilder.Build(Claims(("email", "alice@example.com")), config);

        Assert.Equal("alice@example.com", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void LastMatchingUsernameClaimWins()
    {
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "first"), ("preferred_username", "second")),
            Config(_ => { }));

        Assert.Equal("second", result.Username);
    }

    [Fact]
    public void AllowListConfigured_MatchingRole_IsValid()
    {
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "jellyfin-users")),
            config);

        Assert.Equal("alice", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void AllowListConfigured_NoMatchingRole_NotValid()
    {
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "outsiders")),
            config);

        Assert.Equal("alice", result.Username);
        Assert.False(result.Valid);
    }

    [Fact]
    public void AdminRole_GrantsAdmin_ViaNestedJsonRoleClaim()
    {
        var config = Config(c =>
        {
            c.AdminRoles = new[] { "admins" };
            c.RoleClaim = "realm_access.roles";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("realm_access", "{\"roles\":[\"admins\"]}")),
            config);

        Assert.True(result.Admin);
    }

    [Fact]
    public void SubFallback_WhenNotValidAndRolesEmpty_UsesSubAndIsValid()
    {
        // No preferred-username claim, an empty (non-null) allow-list → the sub claim is the username
        // and, because the allow-list is empty, the login is valid.
        var config = Config(c => c.Roles = Array.Empty<string>());
        var result = OidcAuthorizeStateBuilder.Build(Claims(("sub", "subject-123")), config);

        Assert.Equal("subject-123", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void SubFallback_NotReached_WhenAlreadyValid()
    {
        // A preferred-username claim with no allow-list makes the login valid, so the sub fallback
        // (which would overwrite the username) is not entered.
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("sub", "subject-123")),
            Config(_ => { }));

        Assert.Equal("alice", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void SubFallback_LastSubClaimWins()
    {
        var config = Config(c => c.Roles = Array.Empty<string>());
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("sub", "first"), ("sub", "second")),
            config);

        Assert.Equal("second", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void ValidViaRoleGrant_SubClaimDoesNotOverwriteUsername()
    {
        // Validity granted by the allow-list match keeps the fallback out, so the sub claim must not
        // replace the preferred-username value.
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "jellyfin-users"), ("sub", "subject-123")),
            config);

        Assert.Equal("alice", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void EscapedDotInRoleClaim_IsTreatedAsLiteralDot()
    {
        // "realm\.access" is one segment named "realm.access", not a two-segment path.
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "realm\\.access";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("realm.access", "jellyfin-users")),
            config);

        Assert.True(result.Valid);
    }

    [Fact]
    public void SubFallback_NullRolesArray_Throws()
    {
        // Faithful to the original: the sub fallback does not null-check config.Roles, so when RBAC is
        // off (Roles == null) and only a sub claim is present, it throws (fails closed). Tracked in #89.
        var config = Config(c => c.Roles = null);

        Assert.Throws<NullReferenceException>(() => OidcAuthorizeStateBuilder.Build(Claims(("sub", "subject-123")), config));
    }

    [Fact]
    public void AvatarUrlFormat_ResolvedFromClaims()
    {
        var config = Config(c => c.AvatarUrlFormat = "https://avatars.example.com/@{sub}.png");
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice"), ("sub", "123")), config);

        Assert.Equal("https://avatars.example.com/123.png", result.AvatarUrl);
    }

    [Fact]
    public void NoAvatarUrlFormat_YieldsNull()
    {
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice")), Config(_ => { }));
        Assert.Null(result.AvatarUrl);
    }

    [Fact]
    public void FolderRolesOff_CopiesEnabledFolders()
    {
        var config = Config(c =>
        {
            c.EnableFolderRoles = false;
            c.EnabledFolders = new[] { "movies", "shows" };
        });

        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice")), config);
        Assert.Equal(new List<string> { "movies", "shows" }, result.Folders);
    }

    [Fact]
    public void FolderRolesOn_AppendsRoleGrantedFolders()
    {
        var config = Config(c =>
        {
            c.EnableFolderRoles = true;
            c.RoleClaim = "role";
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "media", Folders = new List<string> { "movies" } },
            };
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "media")),
            config);

        Assert.Equal(new List<string> { "movies" }, result.Folders);
    }

    [Fact]
    public void LiveTv_DefaultsFromConfig_ThenRoleGrantsAdd()
    {
        var config = Config(c =>
        {
            c.EnableLiveTv = true;
            c.EnableLiveTvManagement = false;
            c.EnableLiveTvRoles = true;
            c.RoleClaim = "role";
            c.LiveTvManagementRoles = new[] { "tv-admin" };
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "tv-admin")),
            config);

        Assert.True(result.EnableLiveTv);            // from config default
        Assert.True(result.EnableLiveTvManagement);  // granted by the role
    }
}
