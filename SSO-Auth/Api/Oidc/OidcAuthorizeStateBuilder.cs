// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

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
    /// <param name="issuer">
    /// The validated id_token's issuer, read from the RAW token by the caller (#186). It is passed in rather
    /// than scanned from <paramref name="claims"/> because OidcClient filters the standard protocol claims
    /// (<c>iss</c>, <c>aud</c>, <c>exp</c>, …) out of the redeemed principal, so the claim list here never
    /// carries <c>iss</c>. Null when the token carried none; the canonical link then stays un-stamped.
    /// </param>
    /// <returns>The derived authorize-state values.</returns>
    internal static OidcAuthorizeState Build(IEnumerable<Claim> claims, OidConfig config, string? issuer = null)
    {
        // Materialize so the claims can be enumerated more than once (avatar format, role claim, sub fallback).
        var claimList = claims as IReadOnlyList<Claim> ?? claims.ToList();

        var avatarUrl = ResolveAvatarUrl(claimList, config);
        var (username, valid, roles) = ScanClaims(claimList, config);

        // The stable subject identifier used to key the account link (#155): the "sub" claim, which
        // OIDC Core requires and (post-#134) the id_token validator has verified. Unlike the username
        // (derived from the mutable preferred_username), it never changes for a given end user at a
        // given provider, so an IdP-side rename cannot detach or re-link the account. The last "sub"
        // wins, matching the sub fallback below. Independent of validity — the link key is needed
        // whenever the login is valid, not only in the fallback path; the callback rejects a valid
        // login that resolved no subject (fail closed).
        var subject = ResolveSubject(claimList);

        // The provider's assertion that the login's email is verified (#218), carried to the adoption
        // gate so a provider that requires it can refuse a name-based adoption without one. Null when the
        // claim is absent (the IdP does not emit it, or the "email" scope was not requested); the gate
        // treats absent exactly like false — fail closed — when the requirement is on. Independent of
        // validity and of the username, like the subject above.
        var emailVerified = ResolveEmailVerified(claimList);

        // Assemble the role-derived privileges (folders, admin, Live TV) in the single shared home
        // (#508); OR the assembled validity into the running validity — the SAML builder ignores it.
        var privileges = RolePrivilegeMapper.AssemblePrivileges(roles, config);
        valid |= privileges.Valid;
        var admin = privileges.Admin;
        var enableLiveTv = privileges.EnableLiveTv;
        var enableLiveTvManagement = privileges.EnableLiveTvManagement;
        var folders = privileges.Folders;

        // Assemble the generic role→permission grants for the full boolean PermissionKind surface (#164).
        // Default-deny and empty when the feature is off, so it changes nothing for existing deployments.
        var permissionGrants = PermissionRolePolicy.Map(roles, config);

        // Reduce the roles to a parental-rating-score ceiling (#736): null when the feature is off or no
        // mapping matched, so the mint leaves the account's existing ceiling untouched.
        var maxParentalRatingScore = ParentalRatingPolicy.Resolve(roles, config);

        // If nothing has validated the login yet, fall back to the stable "sub" as the username. The
        // subject was already resolved above (last "sub" wins), so this reuses it instead of scanning
        // the claims a second time. Faithful to the original: unlike the preferred-username branch, this
        // does NOT null-check config.Roles, so a null Roles array throws here (an admin misconfiguration
        // where RBAC is off and the provider supplies only "sub") — the null-forgiving operator keeps
        // that exact fail-closed behavior, tracked in #89. Reached only when a sub exists (subject is
        // non-null), matching the old loop, which touched Roles only inside a sub-claim iteration.
        if (!valid && subject != null)
        {
            username = subject;
            valid = config.Roles!.Length == 0;
        }

        // Fail closed (#95): a valid login must also have resolved an identity. A role matching the
        // allow-list can make the login valid while no username/sub claim resolved a username; such a
        // state used to reach account creation with a null name and fail with a 500 — reject it as an
        // invalid login instead. Whitespace-only counts as unresolved: Jellyfin's own username
        // validation rejects it anyway, so no legitimate login can carry one.
        valid = valid && !string.IsNullOrWhiteSpace(username);

        return new OidcAuthorizeState(username, subject, issuer, emailVerified, valid, admin, enableLiveTv, enableLiveTvManagement, folders, avatarUrl, permissionGrants, maxParentalRatingScore);
    }

    // The last "sub" claim value, or null when none is present. Kept separate from the username
    // derivation: sub is the identity key regardless of how the username was resolved.
    private static string? ResolveSubject(IReadOnlyList<Claim> claims)
    {
        string? subject = null;
        foreach (var claim in claims)
        {
            if (string.Equals(claim.Type, "sub", StringComparison.Ordinal))
            {
                subject = claim.Value;
            }
        }

        return subject;
    }

    // The last "email_verified" claim parsed as a boolean, or null when the claim is absent or carries a
    // non-boolean value. OIDC serializes it as a JSON boolean, which surfaces here as the string "true"/
    // "false"; anything else is treated as absent (null), which the adoption gate fails closed on when a
    // verified email is required. Last wins, matching the subject/username derivations.
    private static bool? ResolveEmailVerified(IReadOnlyList<Claim> claims)
    {
        bool? emailVerified = null;
        foreach (var claim in claims)
        {
            if (string.Equals(claim.Type, "email_verified", StringComparison.Ordinal)
                && bool.TryParse(claim.Value, out var parsed))
            {
                emailVerified = parsed;
            }
        }

        return emailVerified;
    }

    // Resolves the avatar URL. With a configured format the template wins: @{claimType} tokens are
    // substituted (for a duplicate claim type the first occurrence wins — after the first Replace the
    // token is gone, and Replace on an absent token returns the instance unchanged). With no format
    // (null or empty) the resolver falls back to the standard OIDC `picture` claim verbatim (#723) so a
    // standards-compliant IdP yields an avatar with zero configuration — UNLESS the admin has opted out
    // via DisableAvatarFromPictureClaim, in which case no candidate is produced and nothing is fetched.
    // Either way this only produces a CANDIDATE URL: AvatarService.TrySetAsync still gates the fetch
    // through AvatarUrlValidator, so a `picture` (or templated) URL to a private/loopback host is refused
    // exactly the same.
    private static string? ResolveAvatarUrl(IReadOnlyList<Claim> claims, OidConfig config)
    {
        if (string.IsNullOrEmpty(config.AvatarUrlFormat))
        {
            return config.DisableAvatarFromPictureClaim ? null : ResolvePictureClaim(claims);
        }

        return claims.Aggregate(
            config.AvatarUrlFormat,
            (s, claim) => s.Replace($"@{{{claim.Type}}}", claim.Value));
    }

    // The last non-empty "picture" claim value, or null when none is present (#723). Last wins, matching
    // the subject/username/email_verified derivations; an empty value is treated as absent so the caller
    // skips the fetch rather than handing an empty URL to the validator.
    private static string? ResolvePictureClaim(IReadOnlyList<Claim> claims)
    {
        string? picture = null;
        foreach (var claim in claims)
        {
            if (string.Equals(claim.Type, "picture", StringComparison.Ordinal) && !string.IsNullOrEmpty(claim.Value))
            {
                picture = claim.Value;
            }
        }

        return picture;
    }

    // Splits the configured role-claim path on unescaped dots; escaped "\." are normalized to ".".
    // Computed once per login — the path depends only on the configuration, not on any claim.
    private static string[] SplitRoleClaimPath(OidConfig config)
    {
        return string.IsNullOrEmpty(config.RoleClaim)
            ? Array.Empty<string>()
            : RoleClaimSplitRegex.Split(config.RoleClaim.Trim())
                .Select(segment => segment.Replace("\\.", "."))
                .ToArray();
    }

    // Single pass over the claims: resolves the username (the LAST matching preferred-username /
    // DefaultUsernameClaim claim wins), decides validity when no allow-list is configured, and
    // collects the roles carried by every claim on the configured role-claim path.
    private static (string? Username, bool Valid, List<string> Roles) ScanClaims(IReadOnlyList<Claim> claims, OidConfig config)
    {
        var roleClaimSegments = SplitRoleClaimPath(config);

        // Depends only on the configuration, so it is resolved once, not per claim.
        var usernameClaimType = config.DefaultUsernameClaim?.Trim() ?? "preferred_username";

        string? username = null;
        var valid = false;
        var roles = new List<string>();
        foreach (var claim in claims)
        {
            if (string.Equals(claim.Type, usernameClaimType, StringComparison.Ordinal))
            {
                username = claim.Value;
                if (config.Roles == null || config.Roles.Length == 0)
                {
                    valid = true;
                }
            }

            if (roleClaimSegments.Length > 0 && string.Equals(claim.Type, roleClaimSegments[0], StringComparison.Ordinal))
            {
                roles.AddRange(OidcRoleExtractor.ExtractRoles(roleClaimSegments, claim.Value));
            }
        }

        return (username, valid, roles);
    }

    /// <summary>
    /// The authorize-state values derived from an OpenID login.
    /// </summary>
    /// <param name="Username">The resolved username (last matching preferred-username or sub claim), or null when none is present.</param>
    /// <param name="Subject">The stable subject identifier (the "sub" claim) used to key the account link, or null when absent.</param>
    /// <param name="Issuer">The id_token issuer (the "iss" claim) the account link is issuer-bound to, or null when absent (#186).</param>
    /// <param name="EmailVerified">The login's "email_verified" claim (true/false), or null when the claim is absent, used by the adoption gate (#218).</param>
    /// <param name="Valid">Whether the login is permitted (no allow-list, or a role matched the allow-list).</param>
    /// <param name="Admin">Whether the login grants administrator rights.</param>
    /// <param name="EnableLiveTv">Whether the login grants Live TV access.</param>
    /// <param name="EnableLiveTvManagement">Whether the login grants Live TV management.</param>
    /// <param name="Folders">The enabled folders (statically enabled plus role-granted).</param>
    /// <param name="AvatarUrl">The resolved avatar candidate URL: the configured AvatarUrlFormat template with @{claim} tokens substituted, or — when no template is configured (null/empty) — the standard OIDC "picture" claim (#723); null when neither yields a value. Only a candidate: the fetch is still gated by AvatarUrlValidator.</param>
    /// <param name="PermissionGrants">The generic role→permission grants (#164); null (treated as empty) when the feature is off.</param>
    /// <param name="MaxParentalRatingScore">The parental-rating-score ceiling (#736); null when the feature is off or no mapping matched (leave the existing ceiling untouched).</param>
    internal readonly record struct OidcAuthorizeState(
        string? Username,
        string? Subject,
        string? Issuer,
        bool? EmailVerified,
        bool Valid,
        bool Admin,
        bool EnableLiveTv,
        bool EnableLiveTvManagement,
        List<string> Folders,
        string? AvatarUrl,
        IReadOnlyList<PermissionGrant>? PermissionGrants = null,
        int? MaxParentalRatingScore = null)
    {
        /// <summary>
        /// Gets the raw OpenID <c>id_token</c>, captured at the callback for a later RP-initiated logout
        /// <c>id_token_hint</c> (#727, SLO-1b). Set via <c>with</c> after the role gate; null unless Single
        /// Logout is on. A bearer secret — it rides the one-time in-memory Ready and is encrypted once
        /// persisted at capture.
        /// </summary>
        internal string? IdToken { get; init; }

        /// <summary>
        /// Gets the OpenID <c>sid</c> claim (the identity-provider session identifier), captured for logout
        /// matching (#727); null when the token carried none.
        /// </summary>
        internal string? SessionIndex { get; init; }

        /// <summary>
        /// Gets the OpenID <c>end_session_endpoint</c> from discovery (#727, SLO-2), captured so an
        /// RP-initiated logout needs no runtime rediscovery; null when the OP advertises none.
        /// </summary>
        internal string? EndSessionEndpoint { get; init; }

        /// <summary>
        /// Redacts the bearer <see cref="IdToken"/> from the record's synthesized string form (#727), so a
        /// stray <c>$"{state}"</c> or a logged state can never spill the id_token.
        /// </summary>
        /// <returns>A diagnostic string with the id_token redacted.</returns>
        public override string ToString()
            => $"OidcAuthorizeState {{ Username = {Username}, Subject = {Subject}, Valid = {Valid}, Admin = {Admin}, SessionIndex = {SessionIndex}, IdToken = {(IdToken is null ? "null" : "<redacted>")} }}";
    }
}
