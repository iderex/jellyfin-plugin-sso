// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Duende.IdentityModel.OidcClient.Results;
using Jellyfin.Plugin.SSO_Auth.Api.Crypto;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Validates the OpenID Connect id_token per OIDC Core 1.0 section 3.1.3.7. OidcClient 7.x ships no
/// validator of its own: with <c>IdentityTokenValidator</c> unset it falls back to a decode-only
/// stub, so signature, issuer, audience and lifetime all went unchecked. This validator restores the
/// mandatory checks — signature against the discovery JWKS, iss against the discovery issuer,
/// aud/azp against the client id, exp/nbf with the client's clock skew — under an asymmetric-only
/// signature-algorithm allowlist (the posture of the SAML side's SamlSignatureAlgorithms).
/// Every failure rejects the login (fail closed).
/// </summary>
internal sealed class OidcIdTokenValidator : IIdentityTokenValidator
{
    /// <inheritdoc />
    public async Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, OidcClientOptions options, CancellationToken cancellationToken = default)
    {
        // ECDsa instances built from the JWKS are ours to dispose; RSA keys built from RSAParameters
        // are not disposable. Tracked here so the finally can release the native handles rather than
        // leaving them for the finalizer to reclaim (this runs on every login).
        var ephemeralKeys = new List<IDisposable>();
        try
        {
            // Signature (against the discovery JWKS, under the asymmetric-only allowlist), issuer,
            // audience and lifetime are enforced atomically by the handler from the parameters built
            // below; any failure rejects (fail closed). MapInboundClaims=false keeps the raw JWT claim
            // types — the default mapping would rename "sub" and friends to SOAP-style URIs and break
            // every ordinal claim comparison downstream.
            var handler = new JsonWebTokenHandler { MapInboundClaims = false };
            var result = await handler.ValidateTokenAsync(identityToken, OidcSignatureKeys.BuildValidationParameters(options, ephemeralKeys)).ConfigureAwait(false);
            if (!result.IsValid)
            {
                return Reject(MapError(result.Exception));
            }

            var token = (JsonWebToken)result.SecurityToken;
            var azp = result.ClaimsIdentity.FindFirst("azp")?.Value;

            var authorizedPartyError = CheckAuthorizedParty(azp, options.ClientId);
            if (authorizedPartyError != null)
            {
                return Reject(authorizedPartyError);
            }

            var audienceError = CheckAudienceRestriction(azp, token);
            if (audienceError != null)
            {
                return Reject(audienceError);
            }

            return new IdentityTokenValidationResult
            {
                User = new ClaimsPrincipal(result.ClaimsIdentity),
                SignatureAlgorithm = token.Alg,
            };
        }
        finally
        {
            foreach (var key in ephemeralKeys)
            {
                key.Dispose();
            }
        }
    }

    // azp (OIDC Core 3.1.3.7 rule 5): optional, but when present it MUST equal this client's id —
    // a token authorized for a different party must not log in here. Returns the rejection reason, or
    // null when the check passes.
    private static string? CheckAuthorizedParty(string? azp, string clientId) =>
        azp != null && !string.Equals(azp, clientId, StringComparison.Ordinal)
            ? "Identity token validation failed: azp mismatch"
            : null;

    // rules 3-4: with more than one audience the token MUST carry an azp (already pinned to this client
    // by CheckAuthorizedParty). A multi-audience token WITHOUT azp is rejected — it may have been minted
    // for a different party that merely lists this client as a co-audience. ValidateAudience only checks
    // that our id is among the audiences, so this closes the "additional audiences" clause. Returns the
    // rejection reason, or null when the check passes.
    private static string? CheckAudienceRestriction(string? azp, JsonWebToken token) =>
        azp == null && token.Audiences.Count() > 1
            ? "Identity token validation failed: multiple audiences without azp"
            : null;

    private static IdentityTokenValidationResult Reject(string error) => new() { Error = error };

    // The exact string "invalid_signature" is the OidcClient contract: its response processor reacts
    // to it by refreshing the discovery JWKS and retrying once, which is what heals a signing-key
    // rotation between discovery and callback. A signature that fails against a KNOWN key maps there
    // too — after a rotation an IdP may reuse a kid with new material, and the refresh either repairs
    // the validation or the retry fails closed. Everything else reports only the exception type:
    // IdentityModel exception messages can embed token claim values, which must not reach the logs.
    private static string MapError(Exception? exception) => exception switch
    {
        SecurityTokenSignatureKeyNotFoundException => "invalid_signature",
        SecurityTokenInvalidSignatureException => "invalid_signature",
        null => "Identity token validation failed",
        _ => $"Identity token validation failed: {exception.GetType().Name}",
    };
}
