namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>
/// Client-visible rejection categories. Each member maps to exactly one status and fixed message in
/// <see cref="LoginStatusMapper"/>; a new rejection cause requires a new member AND a mapper entry —
/// never a fall-through. Members exist only once a call site constructs them, so the enum grows with
/// the conversion steps of #318.
/// </summary>
internal enum PublicReason
{
    /// <summary>Unknown OR disabled provider — deliberately indistinguishable, so neither can be probed (no enumeration oracle).</summary>
    UnknownProvider,

    /// <summary>Authorize state unknown, expired, minted for another provider, or already redeemed (replay) — one body for all.</summary>
    InvalidState,

    /// <summary>The account-link policy refused the login (name taken with adoption off, or an unresolved identity).</summary>
    AccountLinkForbidden,

    /// <summary>OIDC callback validation failed (the RFC 9207 issuer mix-up check).</summary>
    SsoResponseInvalid,

    /// <summary>SAML assertion malformed, invalid, unsolicited, or replayed — one body for all (#199, #156, #219).</summary>
    SamlResponseInvalid,

    /// <summary>RequirePkce is set but the authorization server does not advertise S256 (#141). Operator-facing by design.</summary>
    PkceNotSupported,

    /// <summary>RequireVerifiedEmailForLogin is set but the login carried no verified email (absent/false/unparseable) (#166). Operator-facing by design.</summary>
    EmailNotVerified,
}
