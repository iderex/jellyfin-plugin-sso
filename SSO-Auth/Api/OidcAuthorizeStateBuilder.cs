using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth.Config;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Derives the per-login authorize-state values (username, login validity, admin, Live TV, folder
/// access, avatar) from a verified OpenID login's claims and the provider configuration. Pure: it
/// reads only (claims, config) and returns the derived values, which the OID callback assigns onto
/// the fresh authorize state. Mirrors, one-for-one, the derivation that used to live inline in the
/// callback — including its quirks (username is the last matching claim; the "sub" claim is a
/// fallback only when no allow-list made the login valid; a null <c>Roles</c> array in that fallback
/// still throws, an admin misconfiguration that fails closed).
/// </summary>
internal static class OidcAuthorizeStateBuilder
{
    // Splits the role-claim path on dots that are not escaped with a backslash ("a.b\.c" -> "a", "b.c").
    // Compiled once and reused: it runs for every claim on every login (hot path), so it must not be
    // recompiled per call. The match timeout is defense-in-depth on the match input: the pattern is
    // fixed and linear (a fixed-width lookbehind plus a literal dot) so it cannot backtrack into a
    // timeout, but the cap guarantees role parsing can never block the login path.
    private static readonly Regex RoleClaimSplitRegex =
        new Regex(@"(?<!\\)\.", RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    /// <summary>
    /// Derives the authorize-state values from the login's claims and the provider configuration.
    /// </summary>
    /// <param name="claims">The claims of the verified OpenID login.</param>
    /// <param name="config">The OpenID provider configuration.</param>
    /// <returns>The derived authorize-state values.</returns>
    internal static OidcAuthorizeState Build(IEnumerable<Claim> claims, OidConfig config)
    {
        // Materialize so the claims can be enumerated more than once (avatar format, role claim, sub fallback).
        var claimList = claims as IReadOnlyList<Claim> ?? claims.ToList();

        // Folders start from the statically-enabled set only when folder roles are off; role-granted
        // folders are appended below.
        var folders = !config.EnableFolderRoles && config.EnabledFolders != null
            ? new List<string>(config.EnabledFolders)
            : new List<string>();

        var enableLiveTv = config.EnableLiveTv;
        var enableLiveTvManagement = config.EnableLiveTvManagement;

        string? avatarUrl = null;
        if (config.AvatarUrlFormat is not null)
        {
            avatarUrl = claimList.Aggregate(
                config.AvatarUrlFormat,
                (s, claim) => s.Contains($"@{{{claim.Type}}}") ? s.Replace($"@{{{claim.Type}}}", claim.Value) : s);
        }

        // The role-claim path depends only on config.RoleClaim, so process it once rather than per claim.
        // The regex splits on dots not escaped with a backslash; escaped "\." are then normalized to ".".
        string[] roleClaimSegments = string.IsNullOrEmpty(config.RoleClaim)
            ? Array.Empty<string>()
            : RoleClaimSplitRegex.Split(config.RoleClaim.Trim())
                .Select(segment => segment.Replace("\\.", "."))
                .ToArray();

        string? username = null;
        var valid = false;
        var roles = new List<string>();
        foreach (var claim in claimList)
        {
            if (claim.Type == (config.DefaultUsernameClaim?.Trim() ?? "preferred_username"))
            {
                username = claim.Value;
                if (config.Roles == null || config.Roles.Length == 0)
                {
                    valid = true;
                }
            }

            // Collect the roles carried by every claim on the configured role-claim path.
            if (roleClaimSegments.Length > 0 && claim.Type == roleClaimSegments[0])
            {
                roles.AddRange(OidcRoleExtractor.ExtractRoles(roleClaimSegments, claim.Value));
            }
        }

        // Map the collected roles to privileges and merge (monotonic: only ever grants).
        var grants = OidcRolePrivilegeMapper.Evaluate(roles, config);
        valid |= grants.Valid;
        var admin = grants.Admin;
        enableLiveTv |= grants.EnableLiveTv;
        enableLiveTvManagement |= grants.EnableLiveTvManagement;
        folders.AddRange(grants.Folders);

        // If the provider doesn't supply the preferred-username claim, fall back to the "sub" claim.
        if (!valid)
        {
            foreach (var claim in claimList)
            {
                if (claim.Type == "sub")
                {
                    username = claim.Value;

                    // Faithful to the original: unlike the preferred-username branch above, this does
                    // NOT null-check config.Roles, so a null Roles array here throws (an admin
                    // misconfiguration where RBAC is off and the provider supplies only "sub"). The
                    // null-forgiving operator keeps that exact fail-closed behavior; tracked in #89.
                    if (config.Roles!.Length == 0)
                    {
                        valid = true;
                    }
                }
            }
        }

        return new OidcAuthorizeState(username, valid, admin, enableLiveTv, enableLiveTvManagement, folders, avatarUrl);
    }

    /// <summary>
    /// The authorize-state values derived from an OpenID login.
    /// </summary>
    /// <param name="Username">The resolved username (last matching preferred-username or sub claim), or null when none is present.</param>
    /// <param name="Valid">Whether the login is permitted (no allow-list, or a role matched the allow-list).</param>
    /// <param name="Admin">Whether the login grants administrator rights.</param>
    /// <param name="EnableLiveTv">Whether the login grants Live TV access.</param>
    /// <param name="EnableLiveTvManagement">Whether the login grants Live TV management.</param>
    /// <param name="Folders">The enabled folders (statically enabled plus role-granted).</param>
    /// <param name="AvatarUrl">The resolved avatar URL, or null when no avatar format is configured.</param>
    internal readonly record struct OidcAuthorizeState(
        string? Username,
        bool Valid,
        bool Admin,
        bool EnableLiveTv,
        bool EnableLiveTvManagement,
        List<string> Folders,
        string? AvatarUrl);
}
