using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;

namespace Jellyfin.Plugin.SSO_Auth.Api.Identity;

/// <summary>
/// The protocol-agnostic result of a completed login validation — the primitive facts a protocol validator
/// has resolved, from which <see cref="VerifiedIdentity"/>'s protocol factories mint the keystone identity
/// (#790, dependency inversion). It carries only BCL / <see cref="PermissionGrant"/> values and no protocol
/// identity of its own (the protocol label and link mode are set by the protocol-named factory), so the
/// identity keystone no longer depends on the OpenID or SAML modules. Each validator destructures its own
/// state into this named bundle (init-only properties, so a caller cannot transpose a positional argument)
/// and hands it to its factory. Holding a <see cref="ValidatedLogin"/> is NOT the keystone — it is a plain,
/// in-principle-forgeable data carrier; the un-forgeable proof of a completed validation stays
/// <see cref="VerifiedIdentity"/> (private constructor, two factories, and the conformance rule pinning each
/// factory's call site to its validator).
/// </summary>
internal sealed record ValidatedLogin
{
    /// <summary>Gets the provider that verified this login.</summary>
    internal required string Provider { get; init; }

    /// <summary>Gets the stable subject identifier keying the account link (OpenID "sub"; the SAML NameID).</summary>
    internal required string Subject { get; init; }

    /// <summary>Gets the id_token issuer the account link is bound to, or null (SAML, and a token that carried none) (#186).</summary>
    internal string? Issuer { get; init; }

    /// <summary>Gets the username the login resolves (the OpenID username; the SAML NameID).</summary>
    internal required string Username { get; init; }

    /// <summary>Gets the login's <c>email_verified</c> claim (true/false), or null when absent — SAML always null (#218).</summary>
    internal bool? EmailVerified { get; init; }

    /// <summary>Gets a value indicating whether the login grants administrator rights.</summary>
    internal required bool Admin { get; init; }

    /// <summary>Gets the folders the login grants access to (statically enabled plus role-granted).</summary>
    internal required IReadOnlyList<string> Folders { get; init; }

    /// <summary>Gets a value indicating whether the login may view live TV.</summary>
    internal required bool EnableLiveTv { get; init; }

    /// <summary>Gets a value indicating whether the login may manage live TV.</summary>
    internal required bool EnableLiveTvManagement { get; init; }

    /// <summary>Gets the avatar URL the login resolves, or null when none — SAML always null.</summary>
    internal string? AvatarUrl { get; init; }

    /// <summary>Gets the generic role→permission grants the login resolves (#164), or empty when the feature is off.</summary>
    internal required IReadOnlyList<PermissionGrant> PermissionGrants { get; init; }

    /// <summary>Gets the parental-rating-score ceiling the login resolves (#736), or null when the feature is off or no mapping matched (leave the existing ceiling untouched).</summary>
    internal int? MaxParentalRatingScore { get; init; }
}
