namespace Jellyfin.Plugin.SSO_Auth.Api.Logout;

/// <summary>
/// The protocol-specific logout bits captured at login that the shared <c>VerifiedIdentity</c>
/// keystone does not carry (#727, SLO-1b): the identity-provider session index and, for OpenID, the raw
/// <c>id_token</c> used later as an <c>id_token_hint</c>. The provider, subject, and issuer come from the
/// verified identity itself, so this carries only the extra fields, keeping the keystone unpolluted.
/// </summary>
/// <param name="SessionIndex">The OpenID <c>sid</c> claim or the SAML <c>SessionIndex</c>, or null when absent.</param>
/// <param name="IdToken">The raw OpenID <c>id_token</c> (a bearer secret), or null for SAML.</param>
/// <param name="EndSessionEndpoint">The OpenID <c>end_session_endpoint</c> from discovery, stored so an RP-initiated logout needs no runtime rediscovery (#727, SLO-2); null for SAML or when the OP advertises none.</param>
internal readonly record struct LogoutContext(string? SessionIndex, string? IdToken, string? EndSessionEndpoint = null)
{
    /// <summary>
    /// Redacts the bearer <see cref="IdToken"/> from the record's synthesized string form, so a stray
    /// <c>$"{context}"</c> or <c>logger.Log(..., context)</c> can never spill the id_token into a log.
    /// </summary>
    /// <returns>A diagnostic string with the id_token redacted.</returns>
    public override string ToString()
        => $"LogoutContext {{ SessionIndex = {SessionIndex}, IdToken = {(IdToken is null ? "null" : "<redacted>")} }}";
}
