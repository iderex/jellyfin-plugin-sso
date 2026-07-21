// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// RFC 9207 authorization-response issuer check (OpenID Connect mix-up defense, #125, hardened in #210).
/// The library the plugin uses (Duende.IdentityModel.OidcClient 7.1.0) parses the response <c>iss</c>
/// parameter but never validates it, and strips it from the resulting claims, so the check has to live
/// here. A present response <c>iss</c> must match the authorization server this callback is bound to —
/// identified by its discovery issuer (<see cref="Duende.IdentityModel.OidcClient.ProviderInformation.IssuerName"/>,
/// the value RFC 9207 §2.4 names) OR by the redeemed id_token's own issuer. Both are accepted because a
/// provider whose issuer legitimately differs from its discovery location (the <c>DoNotValidateIssuerName</c>
/// escape hatch — templated / multi-tenant setups) emits a response <c>iss</c> equal to the concrete
/// id_token issuer, not the templated discovery issuer; requiring the discovery issuer alone would lock
/// that supported configuration out. A response <c>iss</c> that matches neither means the response came
/// from a different authorization server than the one this callback is bound to — a mix-up — so reject.
/// </summary>
internal static class OidcResponseIssuer
{
    /// <summary>
    /// Decides whether the RFC 9207 check rejects this authorization response. A present
    /// <paramref name="responseIssuer"/> is accepted only when it ordinally equals the discovery issuer
    /// (<paramref name="discoveryIssuer"/>) or the id_token issuer; matching neither is a mix-up and is
    /// rejected, as is a present response issuer while both anchors are unknown. Absence of a response
    /// issuer is tolerated only when the server did not advertise the parameter (<paramref name="required"/>
    /// is false), so IdPs that never emit <c>iss</c> keep working; when the server advertises
    /// <c>authorization_response_iss_parameter_supported</c> (RFC 9207 §2.4) its absence is a downgrade
    /// and is rejected.
    /// </summary>
    /// <param name="responseIssuer">The <c>iss</c> query parameter from the authorization response, if any.</param>
    /// <param name="discoveryIssuer">The authorization server's discovery issuer identifier, or null when it could not be determined.</param>
    /// <param name="identityToken">The redeemed id_token (already validated upstream), whose issuer is the second accepted anchor.</param>
    /// <param name="required">Whether the server advertised the response-<c>iss</c> parameter, making its presence mandatory.</param>
    /// <returns><see langword="true"/> when the response must be rejected.</returns>
    internal static bool IsRejected(string? responseIssuer, string? discoveryIssuer, string? identityToken, bool required)
    {
        if (string.IsNullOrEmpty(responseIssuer))
        {
            return required;
        }

        return !string.Equals(responseIssuer, discoveryIssuer, StringComparison.Ordinal)
            && !string.Equals(responseIssuer, TokenIssuer(identityToken), StringComparison.Ordinal);
    }

    /// <summary>
    /// Reports whether the discovery document advertises the RFC 9207 authorization-response <c>iss</c>
    /// parameter (<c>authorization_response_iss_parameter_supported: true</c>, §2.4). Read at challenge
    /// and carried on the authorize state so the callback can require <c>iss</c> without a second fetch.
    /// Fails tolerant (<c>false</c>) on absence, a non-true value, or malformed/blank JSON — an
    /// unreadable flag must not lock out a provider that omits <c>iss</c>.
    /// </summary>
    /// <param name="discoveryJson">The raw OpenID discovery document JSON.</param>
    /// <returns><c>true</c> only when the parameter is explicitly advertised as <c>true</c>.</returns>
    internal static bool DiscoveryAdvertisesResponseIssuer(string? discoveryJson)
    {
        if (string.IsNullOrWhiteSpace(discoveryJson))
        {
            return false;
        }

        try
        {
            return JObject.Parse(discoveryJson)["authorization_response_iss_parameter_supported"] is JValue { Type: JTokenType.Boolean } value
                && value.Value<bool>();
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// The validated id_token's issuer (its <c>iss</c> claim), or null when the token is absent/degenerate.
    /// Read from the RAW token rather than the redeemed <c>result.User</c> claims because OidcClient filters
    /// the standard protocol claims (<c>iss</c>, <c>aud</c>, <c>exp</c>, …) out of the principal — the same
    /// reason the mix-up check above re-reads it here. This is the authoritative (iss, sub) issuer the
    /// canonical link is bound to (#186).
    /// </summary>
    /// <param name="identityToken">The redeemed, already-validated id_token.</param>
    /// <returns>The token's issuer; null when the token does not parse, and empty when it carries no <c>iss</c> (JsonWebToken.Issuer returns "" for an absent claim). Both are treated as "no issuer" by every consumer (IsNullOrWhiteSpace / ordinal Equals), so the link stays un-stamped.</returns>
    internal static string? IdTokenIssuer(string? identityToken) => TokenIssuer(identityToken);

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
