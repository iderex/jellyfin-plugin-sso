using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api.Identity;

/// <summary>
/// The protocol-agnostic keystone the session-minting path is keyed on (#473): the fully-verified
/// identity and privileges that an OpenID or SAML login resolves, once — and only once — all of that
/// protocol's validation has passed. Both protocols funnel their result into this one shape, so the
/// shared completion path (<c>ResolveOrCreateAsync -&gt; SessionParameters -&gt; SessionMinter</c>)
/// takes a <see cref="VerifiedIdentity"/> and nothing else; a caller cannot reach the mint with a raw,
/// unvalidated response because there is no other way to obtain one.
/// </summary>
/// <remarks>
/// The constructor is PRIVATE, so the type is unforgeable from outside: the only way to obtain an instance
/// is one of the two protocol factories (<see cref="FromValidatedOidc"/>, <see cref="FromValidatedSaml"/>),
/// each of which takes a protocol-agnostic
/// <see cref="ValidatedLogin"/> — the primitive facts a completed validation resolved. Each protocol builds
/// that bundle and calls the factory ONLY once its validation has passed:
/// <list type="bullet">
/// <item>OpenID: inside <c>AuthorizeSession.Ready</c>, handed out only by <c>OidcStateStore.TryRedeem</c>
/// after the atomic one-time claim of a promoted (role-gate-passed) state.</item>
/// <item>SAML: at the session-minting validator (<c>SamlAssertionValidator</c>) after the response has
/// passed signature, time-bound, audience, recipient and replay validation.</item>
/// </list>
/// The construction lock is pinned as a fitness function
/// (<c>ArchitectureConformanceTests.VerifiedIdentity_IsConstructedOnlyByProtocolValidators</c>): the private
/// constructor keeps <c>new VerifiedIdentity(...)</c> inside this file, and the source scan keeps
/// each factory's call site to its own validator. Taking a
/// <see cref="ValidatedLogin"/> instead of the protocol state types is the #790 dependency inversion — the
/// keystone no longer depends on the OpenID or SAML modules. The two protocol-facing labels
/// (<see cref="LinkMode"/>, <see cref="AuditProtocol"/>) are the only branch the completion path needs.
/// </remarks>
internal sealed record VerifiedIdentity
{
    // Private so the type cannot be constructed from unvalidated data: the two static factories below are
    // the sole construction sites, and each stands for a completed protocol validation. Anything that
    // holds a VerifiedIdentity therefore holds proof the login was verified (#473).
    private VerifiedIdentity(
        ProviderMode linkMode,
        string auditProtocol,
        string provider,
        string subject,
        string? issuer,
        string username,
        bool? emailVerified,
        bool admin,
        IReadOnlyList<string> folders,
        bool enableLiveTv,
        bool enableLiveTvManagement,
        string? avatarUrl,
        IReadOnlyList<PermissionGrant> permissionGrants,
        int? maxParentalRatingScore)
    {
        LinkMode = linkMode;
        AuditProtocol = auditProtocol;
        Provider = provider;
        Subject = subject;
        Issuer = issuer;
        Username = username;
        EmailVerified = emailVerified;
        Admin = admin;
        Folders = folders;
        EnableLiveTv = enableLiveTv;
        EnableLiveTvManagement = enableLiveTvManagement;
        AvatarUrl = avatarUrl;
        PermissionGrants = permissionGrants;
        MaxParentalRatingScore = maxParentalRatingScore;
    }

    /// <summary>Gets the protocol the canonical-link store keys this identity under (#369).</summary>
    internal ProviderMode LinkMode { get; }

    /// <summary>Gets the protocol label ("OpenID"/"SAML") recorded in the login audit line.</summary>
    internal string AuditProtocol { get; }

    /// <summary>Gets the provider that verified this login.</summary>
    internal string Provider { get; }

    /// <summary>Gets the stable subject identifier keying the account link (OpenID "sub"; the SAML NameID) (#155).</summary>
    internal string Subject { get; }

    /// <summary>
    /// Gets the issuer the account link is bound to — the OpenID id_token's "iss" claim, or null for SAML
    /// (out of scope) and for a token that carried none. Used to stamp and re-check the per-link issuer
    /// binding (#186).
    /// </summary>
    internal string? Issuer { get; }

    /// <summary>Gets the username the login resolves (the OpenID username; the SAML NameID).</summary>
    internal string Username { get; }

    /// <summary>Gets the login's <c>email_verified</c> claim (true/false), or null when absent — SAML always null (#218).</summary>
    internal bool? EmailVerified { get; }

    /// <summary>Gets a value indicating whether the login grants administrator rights.</summary>
    internal bool Admin { get; }

    /// <summary>Gets the folders the login grants access to (statically enabled plus role-granted).</summary>
    internal IReadOnlyList<string> Folders { get; }

    /// <summary>Gets a value indicating whether the login may view live TV.</summary>
    internal bool EnableLiveTv { get; }

    /// <summary>Gets a value indicating whether the login may manage live TV.</summary>
    internal bool EnableLiveTvManagement { get; }

    /// <summary>Gets the avatar URL the login resolves, or null when none — SAML always null.</summary>
    internal string? AvatarUrl { get; }

    /// <summary>
    /// Gets the generic role→permission grants the login resolves (#164): one authoritative grant per
    /// permission the administrator explicitly mapped, applied at the mint (default-deny). Empty when the
    /// feature is off, so no extra permission is touched.
    /// </summary>
    internal IReadOnlyList<PermissionGrant> PermissionGrants { get; }

    /// <summary>
    /// Gets the parental-rating-score ceiling the login resolves (#736): the minimum (most restrictive) of
    /// the matched role→ceiling mappings, applied at the mint under EnableAuthorization. Null when the feature
    /// is off or no mapping matched, so the account's existing ceiling is left untouched.
    /// </summary>
    internal int? MaxParentalRatingScore { get; }

    /// <summary>
    /// Mints the verified identity of an OpenID login. Called only from the OpenID redeem path
    /// (<c>AuthorizeSession.Ready</c>), which the store hands out only through its one-time atomic redeem of a
    /// promoted (role-gate-passed) state — so a raw or unvalidated login can never reach it.
    /// </summary>
    /// <param name="login">The primitive facts the OpenID role-gate resolved for the completed login.</param>
    /// <returns>The verified OpenID identity.</returns>
    internal static VerifiedIdentity FromValidatedOidc(ValidatedLogin login) => Build(ProviderMode.Oid, "OpenID", login);

    /// <summary>
    /// Mints the verified identity of a SAML login. Called only from the SAML session-minting validator
    /// (<c>SamlAssertionValidator</c>), reached only after the response has passed signature, time-bound,
    /// audience, recipient and replay validation, the login allow-list, and the non-empty-NameID guard (#95).
    /// </summary>
    /// <param name="login">The primitive facts the SAML validation resolved for the completed login.</param>
    /// <returns>The verified SAML identity.</returns>
    internal static VerifiedIdentity FromValidatedSaml(ValidatedLogin login) => Build(ProviderMode.Saml, "SAML", login);

    // The two protocol factories set the protocol label + link mode (the only protocol-facing branch, #369)
    // and fold in the protocol-agnostic ValidatedLogin. Taking that neutral bundle rather than the OpenID /
    // SAML state types is the #790 dependency inversion — the keystone no longer references either protocol
    // module; the arrow points from each protocol INTO the keystone.
    private static VerifiedIdentity Build(ProviderMode linkMode, string auditProtocol, ValidatedLogin login) =>
        new(
            linkMode,
            auditProtocol,
            login.Provider,
            login.Subject,
            login.Issuer,
            login.Username,
            login.EmailVerified,
            login.Admin,
            login.Folders,
            login.EnableLiveTv,
            login.EnableLiveTvManagement,
            login.AvatarUrl,
            login.PermissionGrants,
            login.MaxParentalRatingScore);
}
