using System;
using System.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Reads the <c>acr</c> claim from the RAW, already-validated id_token for the step-up / MFA gate (#757),
/// NOT from the redeemed <c>result.User</c> principal. With <c>LoadProfile</c> on (the default), OidcClient
/// merges the UNSIGNED UserInfo response into <c>result.User</c>, so a UserInfo-supplied <c>acr</c> is not
/// signature-covered — trusting it would let a provider that reports a user's registered assurance level
/// (rather than this session's actual one) satisfy a step-up requirement the session did not meet. The gate
/// must trust only the signature-verified id_token, so the value is read here from <c>result.IdentityToken</c>
/// — exactly the reason <see cref="OidcResponseIssuer"/> re-reads <c>iss</c> from the raw token rather than
/// the filtered principal.
/// </summary>
internal static class OidcIdTokenAcr
{
    /// <summary>
    /// The id_token's <c>acr</c> claim value, or null when the token is absent/degenerate or carries no
    /// <c>acr</c>. The token was validated by <see cref="OidcIdTokenValidator"/> before this runs, so it
    /// parses; the guard and catch are defensive so a degenerate token can never turn the gate into a 500.
    /// </summary>
    /// <param name="identityToken">The redeemed, already-validated id_token.</param>
    /// <returns>The signature-verified <c>acr</c> claim value, or null.</returns>
    internal static string? Read(string? identityToken)
    {
        if (string.IsNullOrEmpty(identityToken))
        {
            return null;
        }

        try
        {
            return new JsonWebToken(identityToken).Claims
                .LastOrDefault(c => string.Equals(c.Type, "acr", StringComparison.Ordinal))?.Value;
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
