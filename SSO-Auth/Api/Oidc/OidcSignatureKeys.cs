// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Crypto;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The ONE OpenID signature-validation basis, shared by every token the plugin verifies against a
/// provider's discovery JWKS — the id_token (<see cref="OidcIdTokenValidator"/>) and the back-channel
/// <c>logout_token</c> (<see cref="OidcLogoutTokenValidator"/>, #962). Centralising the asymmetric-only
/// algorithm allowlist and the JWK→<see cref="SecurityKey"/> conversion here means there is provably no
/// second, laxer verification path: a token type cannot accidentally accept HS*, <c>none</c>, an
/// under-strength key, or malformed key material that the other type rejects.
/// </summary>
internal static class OidcSignatureKeys
{
    /// <summary>
    /// Gets the asymmetric signature algorithms the plugin accepts (RFC 7518). Symmetric HS* would accept a
    /// token minted by anyone holding the shared client secret, and <c>none</c> is unauthenticated by
    /// definition — both are rejected regardless of what the discovery document advertises.
    /// </summary>
    internal static string[] AllowedSignatureAlgorithms { get; } =
    {
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512",
    };

    /// <summary>
    /// Builds the signature/issuer/audience/lifetime validation parameters every JWT the plugin verifies
    /// against a provider uses — the id_token and the back-channel logout_token share this ONE builder, so
    /// their signature posture cannot drift apart. Signed + expiring tokens are required (fail closed); the
    /// provider-level <c>DoNotValidateIssuerName</c> escape hatch relaxes ONLY the issuer match.
    /// </summary>
    /// <param name="options">The provider's client options (discovery issuer + JWKS, client id, skew, policy).</param>
    /// <param name="ephemeralKeys">Collects disposable ECDsa handles for the caller to release.</param>
    /// <returns>The hardened validation parameters.</returns>
    internal static TokenValidationParameters BuildValidationParameters(OidcClientOptions options, List<IDisposable> ephemeralKeys)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new TokenValidationParameters
        {
            ValidIssuer = options.ProviderInformation.IssuerName,
            ValidAudience = options.ClientId,
            IssuerSigningKeys = Convert(options.ProviderInformation.KeySet, ephemeralKeys),
            ValidAlgorithms = AllowedSignatureAlgorithms,
            ClockSkew = options.ClockSkew,
            RequireSignedTokens = true,
            RequireExpirationTime = true,

            // The provider-level escape hatch (DoNotValidateIssuerName) exists for IdPs whose issuer
            // legitimately differs from the discovery location; it relaxes ONLY the issuer match.
            // Signature, audience and lifetime validation have no off switch.
            ValidateIssuer = options.Policy.Discovery.ValidateIssuerName,

            // The downstream claim scan compares raw JWT claim names ordinally, so the principal must carry
            // the payload names verbatim — these two only name the identity's Name/Role accessors.
            NameClaimType = "name",
            RoleClaimType = "role",
        };
    }

    /// <summary>
    /// Converts the advertised JWKS into usable signing keys, skipping any key that is null, not a signing
    /// key (<c>use != "sig"</c>), under the RSA size floor (#733), or of un-decodable/invalid material — so
    /// one broken key in the set cannot take down verification against a good one. Never throws.
    /// </summary>
    /// <param name="keySet">The advertised JSON Web Key Set (may be null/empty).</param>
    /// <param name="ephemeralKeys">Collects disposable ECDsa handles for the caller to release.</param>
    /// <returns>The usable signing keys (possibly empty).</returns>
    internal static List<SecurityKey> Convert(Duende.IdentityModel.Jwk.JsonWebKeySet? keySet, List<IDisposable> ephemeralKeys)
    {
        ArgumentNullException.ThrowIfNull(ephemeralKeys);
        var keys = new List<SecurityKey>();
        if (keySet?.Keys == null)
        {
            return keys;
        }

        foreach (var webKey in keySet.Keys)
        {
            if (TryConvertSigningKey(webKey, ephemeralKeys, out var key))
            {
                keys.Add(key);
            }
        }

        return keys;
    }

    // Converts one advertised JWK into a usable signing key, or reports that it is unusable (out false).
    // The exclusions and the skip-on-malformed contract live here: a literal null entry (["keys":[null]])
    // must be skipped rather than dereferenced (otherwise the whole verification 500s), a key marked
    // use!="sig" is not a signing key, and un-decodable/invalid key material is caught and skipped so one
    // broken key in the set cannot take down verification signed by a good one. Returns false — never
    // throws — on every reject path so the caller drops the key without aborting the scan.
    private static bool TryConvertSigningKey(Duende.IdentityModel.Jwk.JsonWebKey? webKey, List<IDisposable> ephemeralKeys, [NotNullWhen(true)] out SecurityKey? key)
    {
        key = null;
        if (webKey == null)
        {
            return false;
        }

        if (webKey.Use != null && !string.Equals(webKey.Use, "sig", StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            // RSA (e/n) is tried first; an EC (crv/x/y) key is only attempted when the key is not RSA-shaped,
            // preserving the original else-if precedence. A decode/point failure throws out of the converter
            // and is caught below as a skip.
            key = (SecurityKey?)ConvertRsaSigningKey(webKey) ?? ConvertEcSigningKey(webKey, ephemeralKeys);
        }
        catch (FormatException)
        {
            // Un-decodable key material in one advertised key: skip it, the remaining keys decide.
            return false;
        }
        catch (CryptographicException)
        {
            // Invalid EC point/curve combination: likewise skip.
            return false;
        }

        return key != null;
    }

    // RSA signing key from the JWK e/n pair (RFC 7518). Returns null when the key does not carry both
    // parameters (not RSA-shaped, so the EC conversion is tried instead) OR when the built key is below the
    // minimum size floor (#733) — an under-strength RSA key from the discovery JWKS (or a compromised one) is
    // as forgeable as a weak hash, so it is skipped exactly like a malformed key; the remaining advertised
    // keys decide, and if none is usable verification fails via the key-not-found path. A non-base64url
    // exponent/modulus throws FormatException, surfaced to TryConvertSigningKey's skip path.
    private static RsaSecurityKey? ConvertRsaSigningKey(Duende.IdentityModel.Jwk.JsonWebKey webKey)
    {
        if (string.IsNullOrEmpty(webKey.E) || string.IsNullOrEmpty(webKey.N))
        {
            return null;
        }

        var key = new RsaSecurityKey(new RSAParameters
        {
            Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
            Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
        })
        { KeyId = webKey.Kid };

        return SigningKeyStrength.IsAcceptableRsaKeySize(key.KeySize) ? key : null;
    }

    // EC signing key from the JWK crv/x/y triple. Returns null when a coordinate is absent or the curve is
    // unsupported (TryGetCurve false), so the key is skipped. The ECDsa instance is registered in
    // ephemeralKeys for disposal by the caller. A non-base64url coordinate throws FormatException and an
    // invalid point throws CryptographicException — both surfaced to TryConvertSigningKey's skip path.
    private static ECDsaSecurityKey? ConvertEcSigningKey(Duende.IdentityModel.Jwk.JsonWebKey webKey, List<IDisposable> ephemeralKeys)
    {
        if (string.IsNullOrEmpty(webKey.X) || string.IsNullOrEmpty(webKey.Y) || !TryGetCurve(webKey.Crv, out var curve))
        {
            return null;
        }

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
        return new ECDsaSecurityKey(ecdsa) { KeyId = webKey.Kid };
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
