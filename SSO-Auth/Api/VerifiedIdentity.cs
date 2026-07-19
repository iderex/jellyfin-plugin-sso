using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The protocol-agnostic keystone the session-minting path is keyed on (#473): the fully-verified
/// identity and privileges that an OpenID or SAML login resolves, once — and only once — all of that
/// protocol's validation has passed. Both protocols funnel their result into this one shape, so the
/// shared completion path (<c>ResolveOrCreateAsync -&gt; SessionParameters -&gt; SessionMinter</c>)
/// takes a <see cref="VerifiedIdentity"/> and nothing else; a caller cannot reach the mint with a raw,
/// unvalidated response because there is no other way to obtain one.
/// </summary>
/// <remarks>
/// The constructor is PRIVATE, so the type is unforgeable from outside: the only way to obtain an
/// instance is one of the two named factories, each of which represents a completed protocol validation.
/// <list type="bullet">
/// <item><see cref="FromOidcRedemption"/>, built inside <see cref="AuthorizeSession.Ready"/> and handed
/// out only by <see cref="OidcStateStore.TryRedeem"/> after the atomic one-time claim of a promoted
/// (role-gate-passed) state.</item>
/// <item><see cref="FromValidatedSaml"/>, called only at the SAML session-minting endpoint after the
/// response has passed signature, time-bound, audience, recipient and replay validation.</item>
/// </list>
/// This construction lock is pinned as a fitness function
/// (<c>ArchitectureConformanceTests.VerifiedIdentity_IsConstructedOnlyByProtocolValidators</c>). The two
/// protocol-facing labels (<see cref="LinkMode"/>, <see cref="AuditProtocol"/>) are the only branch the
/// completion path needs; a richer protocol abstraction is deferred to a later #318 step rather than
/// pre-empted here.
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
        IReadOnlyList<PermissionGrant> permissionGrants)
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
    /// Builds the verified identity of an OpenID login from the role-gate result. Called from inside
    /// <see cref="AuthorizeSession.Ready"/>, which the store produces only for a promoted (role-gate-passed)
    /// state and hands out only through the one-time atomic redeem — so this can never run before that claim.
    /// The subject and username are non-null by that point: the callback rejects a valid login that resolved
    /// no subject (#155) and no username (#95) before the state is promoted, so the null-forgiving reads
    /// preserve that upstream fail-closed guarantee rather than re-deciding it here.
    /// </summary>
    /// <param name="provider">The provider that verified the login.</param>
    /// <param name="derived">The passed role-gate result carrying the resolved identity and privileges.</param>
    /// <returns>The verified OpenID identity.</returns>
    internal static VerifiedIdentity FromOidcRedemption(string provider, OidcAuthorizeStateBuilder.OidcAuthorizeState derived) =>
        new(
            ProviderMode.Oid,
            "OpenID",
            provider,
            derived.Subject!,
            derived.Issuer,
            derived.Username!,
            derived.EmailVerified,
            derived.Admin,
            derived.Folders,
            derived.EnableLiveTv,
            derived.EnableLiveTvManagement,
            derived.AvatarUrl,
            derived.PermissionGrants ?? Array.Empty<PermissionGrant>());

    /// <summary>
    /// Builds the verified identity of a SAML login. Called only at the SAML session-minting endpoint after
    /// the response has passed signature, time-bound, audience, recipient and replay validation, the login
    /// allow-list, and the non-empty-NameID guard (#95) — so a raw or unvalidated response can never reach
    /// this factory. SAML keys the link directly on the NameID (subject and username are the same value) and
    /// carries no <c>email_verified</c> claim, avatar, or issuer binding (all null — issuer binding is
    /// OpenID-only, #186).
    /// </summary>
    /// <param name="provider">The provider that verified the login.</param>
    /// <param name="nameId">The validated, non-empty NameID; the link key and the username.</param>
    /// <param name="privileges">The privileges derived from the assertion's roles and the provider configuration.</param>
    /// <returns>The verified SAML identity.</returns>
    internal static VerifiedIdentity FromValidatedSaml(string provider, string nameId, SamlAuthorizeStateBuilder.SamlAuthorizeState privileges) =>
        new(
            ProviderMode.Saml,
            "SAML",
            provider,
            nameId,
            null,
            nameId,
            null,
            privileges.Admin,
            privileges.Folders,
            privileges.EnableLiveTv,
            privileges.EnableLiveTvManagement,
            null,
            privileges.PermissionGrants ?? Array.Empty<PermissionGrant>());
}
