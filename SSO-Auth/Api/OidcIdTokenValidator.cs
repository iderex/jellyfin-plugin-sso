using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Duende.IdentityModel.OidcClient.Results;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Validates the OpenID Connect id_token per OIDC Core 1.0 section 3.1.3.7. OidcClient 7.x ships no
/// validator of its own: with <c>IdentityTokenValidator</c> unset it falls back to a decode-only
/// stub, so signature, issuer, audience and lifetime all went unchecked. This validator restores the
/// mandatory checks — signature against the discovery JWKS, iss against the discovery issuer,
/// aud/azp against the client id, exp/nbf with the client's clock skew — under an asymmetric-only
/// signature-algorithm allowlist (the posture of the SAML side's <see cref="SamlSignatureAlgorithms"/>).
/// Every failure rejects the login (fail closed).
/// </summary>
internal sealed class OidcIdTokenValidator : IIdentityTokenValidator
{
    // Asymmetric signature algorithms only (RFC 7518): symmetric HS* would accept a token minted by
    // anyone holding the shared client secret, and "none" is unauthenticated by definition — both are
    // rejected regardless of what key material the discovery document advertises.
    private static readonly string[] AllowedSignatureAlgorithms =
    {
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512",
    };

    /// <inheritdoc />
    public async Task<IdentityTokenValidationResult> ValidateAsync(string identityToken, OidcClientOptions options, CancellationToken cancellationToken = default)
    {
        // ECDsa instances built from the JWKS are ours to dispose; RSA keys built from RSAParameters
        // are not disposable. Tracked here so the finally can release the native handles rather than
        // leaving them for the finalizer to reclaim (this runs on every login).
        var ephemeralKeys = new List<IDisposable>();
        try
        {
            var parameters = new TokenValidationParameters
            {
                ValidIssuer = options.ProviderInformation.IssuerName,
                ValidAudience = options.ClientId,
                IssuerSigningKeys = ConvertSigningKeys(options.ProviderInformation.KeySet, ephemeralKeys),
                ValidAlgorithms = AllowedSignatureAlgorithms,
                ClockSkew = options.ClockSkew,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                // The provider-level escape hatch (DoNotValidateIssuerName) exists for IdPs whose issuer
                // legitimately differs from the discovery location; it relaxes ONLY the issuer match.
                // Signature, audience and lifetime validation have no off switch.
                ValidateIssuer = options.Policy.Discovery.ValidateIssuerName,
                // The downstream claim scan compares raw JWT claim names ordinally ("preferred_username",
                // "sub", the configured role-claim path), so the principal must carry the payload names
                // verbatim — these two only name the identity's Name/Role accessors.
                NameClaimType = "name",
                RoleClaimType = "role",
            };

            // MapInboundClaims=false keeps the raw JWT claim types; the default mapping would rename
            // "sub" and friends to SOAP-style URIs and break every ordinal claim comparison downstream.
            var handler = new JsonWebTokenHandler { MapInboundClaims = false };
            var result = await handler.ValidateTokenAsync(identityToken, parameters).ConfigureAwait(false);
            if (!result.IsValid)
            {
                return new IdentityTokenValidationResult { Error = MapError(result.Exception) };
            }

            var token = (JsonWebToken)result.SecurityToken;
            var azp = result.ClaimsIdentity.FindFirst("azp")?.Value;

            // azp (OIDC Core 3.1.3.7 rule 5): optional, but when present it MUST equal this client's id —
            // a token authorized for a different party must not log in here.
            if (azp != null && !string.Equals(azp, options.ClientId, StringComparison.Ordinal))
            {
                return new IdentityTokenValidationResult { Error = "Identity token validation failed: azp mismatch" };
            }

            // rules 3-4: with more than one audience the token MUST carry an azp (already pinned to this
            // client above). A multi-audience token WITHOUT azp is rejected — it may have been minted for
            // a different party that merely lists this client as a co-audience. ValidateAudience only
            // checks that our id is among the audiences, so this closes the "additional audiences" clause.
            if (azp == null && token.Audiences.Count() > 1)
            {
                return new IdentityTokenValidationResult { Error = "Identity token validation failed: multiple audiences without azp" };
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

    // Converts the discovery JWKS into Microsoft.IdentityModel signing keys, mirroring the conversion
    // of Duende's retired validator package: RSA from e/n, EC from crv/x/y, keys marked use!="sig"
    // excluded. A malformed or unsupported advertised key is skipped rather than thrown on — one
    // broken key in the set must not take down logins signed by a good one; if NO usable key remains,
    // validation fails closed with the key-not-found path above.
    private static List<SecurityKey> ConvertSigningKeys(Duende.IdentityModel.Jwk.JsonWebKeySet? keySet, List<IDisposable> ephemeralKeys)
    {
        var keys = new List<SecurityKey>();
        if (keySet?.Keys == null)
        {
            return keys;
        }

        foreach (var webKey in keySet.Keys)
        {
            // A JWKS with a literal null entry (["keys":[null]]) must be skipped, not dereferenced —
            // otherwise the whole login 500s, contradicting the skip-on-malformed contract below.
            if (webKey == null)
            {
                continue;
            }

            if (webKey.Use != null && !string.Equals(webKey.Use, "sig", StringComparison.Ordinal))
            {
                continue;
            }

            try
            {
                if (!string.IsNullOrEmpty(webKey.E) && !string.IsNullOrEmpty(webKey.N))
                {
                    keys.Add(new RsaSecurityKey(new RSAParameters
                    {
                        Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
                        Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
                    })
                    { KeyId = webKey.Kid });
                }
                else if (!string.IsNullOrEmpty(webKey.X) && !string.IsNullOrEmpty(webKey.Y) && TryGetCurve(webKey.Crv, out var curve))
                {
                    var ecdsa = ECDsa.Create(new ECParameters
                    {
                        Curve = curve,
                        Q = new ECPoint
                        {
                            X = Base64UrlEncoder.DecodeBytes(webKey.X),
                            Y = Base64UrlEncoder.DecodeBytes(webKey.Y),
                        },
                    });
                    ephemeralKeys.Add(ecdsa);
                    keys.Add(new ECDsaSecurityKey(ecdsa) { KeyId = webKey.Kid });
                }
            }
            catch (FormatException)
            {
                // Un-decodable key material in one advertised key: skip it, the remaining keys decide.
            }
            catch (CryptographicException)
            {
                // Invalid EC point/curve combination: likewise skip.
            }
        }

        return keys;
    }

    private static bool TryGetCurve(string? crv, out ECCurve curve)
    {
        switch (crv)
        {
            case "P-256":
                curve = ECCurve.NamedCurves.nistP256;
                return true;
            case "P-384":
                curve = ECCurve.NamedCurves.nistP384;
                return true;
            case "P-521":
                curve = ECCurve.NamedCurves.nistP521;
                return true;
            default:
                curve = default;
                return false;
        }
    }
}
