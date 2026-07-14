namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Client-visible rejection categories. Each member maps to exactly one status and fixed message in
/// <see cref="LoginStatusMapper"/>; a new rejection cause requires a new member AND a mapper entry —
/// never a fall-through. Members exist only once a call site constructs them, so the enum grows with
/// the conversion steps of #318.
/// </summary>
internal enum PublicReason
{
    /// <summary>OIDC callback validation failed (the RFC 9207 issuer mix-up check).</summary>
    SsoResponseInvalid,

    /// <summary>SAML assertion malformed, invalid, unsolicited, or replayed — one body for all (#199, #156, #219).</summary>
    SamlResponseInvalid,

    /// <summary>RequirePkce is set but the authorization server does not advertise S256 (#141). Operator-facing by design.</summary>
    PkceNotSupported,

    /// <summary>RequirePkce is set but the discovery document could not be read (#141). Operator-facing by design.</summary>
    PkceUnverifiable,
}
