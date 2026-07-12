using System;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// RFC 9207 authorization-response issuer check (OpenID Connect mix-up defense, #125). The library the
/// plugin uses (Duende.IdentityModel.OidcClient 7.1.0) parses the response <c>iss</c> parameter but never
/// validates it, and strips it from the resulting claims, so the check has to live here. The expected
/// issuer is the <c>iss</c> of the id_token the code redeemed to: that token has already been
/// signature-validated and issuer-matched against the discovery document by <see cref="OidcIdTokenValidator"/>,
/// so it is a trusted stand-in for "the provider this callback is bound to". When the authorization
/// response advertises a different issuer, the response came from a different authorization server than
/// the one whose token we hold — a mix-up signal — and the caller rejects the login (fail closed).
/// </summary>
internal static class OidcResponseIssuer
{
    /// <summary>
    /// Determines whether a present authorization-response <c>iss</c> disagrees with the id_token issuer.
    /// Absence of <paramref name="responseIssuer"/> is tolerated (many IdPs do not yet emit it, and
    /// requiring it would lock them out); a present value that does not match the token issuer is a
    /// mismatch. If the token issuer cannot be read while a response issuer is present, that also counts
    /// as a mismatch — the safe default when the two cannot be shown to agree.
    /// </summary>
    /// <param name="responseIssuer">The <c>iss</c> query parameter from the authorization response, if any.</param>
    /// <param name="identityToken">The redeemed id_token (already validated upstream).</param>
    /// <returns><see langword="true"/> when a present response issuer does not match the token issuer.</returns>
    internal static bool IsMismatch(string? responseIssuer, string? identityToken)
    {
        if (string.IsNullOrEmpty(responseIssuer))
        {
            return false;
        }

        return !string.Equals(responseIssuer, TokenIssuer(identityToken), StringComparison.Ordinal);
    }

    // The id_token was validated by OidcIdTokenValidator before this runs, so it parses; the guard and
    // catch are defensive so a degenerate token can never turn the mix-up check itself into a 500.
    private static string? TokenIssuer(string? identityToken)
    {
        if (string.IsNullOrEmpty(identityToken))
        {
            return null;
        }

        try
        {
            return new JsonWebToken(identityToken).Issuer;
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
