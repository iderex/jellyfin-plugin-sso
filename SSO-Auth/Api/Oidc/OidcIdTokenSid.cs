using System;
using System.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Reads the <c>sid</c> (identity-provider session identifier) claim from the RAW, already-validated
/// id_token for the Single Logout capture (#727), NOT from the redeemed <c>result.User</c> principal. With
/// <c>LoadProfile</c> on (the default), OidcClient merges the UNSIGNED UserInfo response into
/// <c>result.User</c>, so a UserInfo-supplied <c>sid</c> is not signature-covered — and <c>sid</c> is an
/// ID-Token / Logout-Token claim (OpenID Connect Session Management / Back-Channel Logout), not a UserInfo
/// one. Reading it from the signature-verified id_token keeps a divergent or attacker-influenced UserInfo
/// <c>sid</c> from poisoning the persisted logout key, exactly as <see cref="OidcIdTokenAcr"/> reads
/// <c>acr</c> and <see cref="OidcResponseIssuer"/> re-reads <c>iss</c> from the raw token.
/// </summary>
internal static class OidcIdTokenSid
{
    /// <summary>
    /// The id_token's <c>sid</c> claim value, or null when the token is absent/degenerate or carries no
    /// <c>sid</c>. The token was validated by <see cref="OidcIdTokenValidator"/> before this runs, so it
    /// parses; the guard and catch are defensive so a degenerate token can never turn the capture into a 500.
    /// </summary>
    /// <param name="identityToken">The redeemed, already-validated id_token.</param>
    /// <returns>The signature-verified <c>sid</c> claim value, or null.</returns>
    internal static string? Read(string? identityToken)
    {
        if (string.IsNullOrEmpty(identityToken))
        {
            return null;
        }

        try
        {
            return new JsonWebToken(identityToken).Claims
                .LastOrDefault(c => string.Equals(c.Type, "sid", StringComparison.Ordinal))?.Value;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (SecurityTokenException)
        {
            return null;
        }
    }
}
