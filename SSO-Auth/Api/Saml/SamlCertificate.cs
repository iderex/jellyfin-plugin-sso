using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Jellyfin.Plugin.SSO_Auth.Api.Crypto;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Validates the per-provider SAML signing certificate (#206). A non-blank but unloadable
/// <c>SamlCertificate</c> makes the <see cref="SamlResponse"/> constructor throw on every callback
/// (<see cref="FormatException"/> on non-base64, <see cref="CryptographicException"/> on bytes that are
/// not a certificate), which escaped as an unhandled HTTP 500. Rejecting an invalid certificate at every
/// admin write path — and treating it as a parse failure at login — keeps that fail-closed and out of the
/// 500 path.
/// </summary>
internal static class SamlCertificate
{
    /// <summary>
    /// Whether a certificate value is set but is not a loadable X.509 certificate. Blank is valid (a
    /// half-configured provider; the login then fails closed for lack of a certificate rather than being
    /// blocked from saving).
    /// </summary>
    /// <param name="certificateStr">The Base64-encoded (DER) certificate string.</param>
    /// <returns><see langword="true"/> if the value is set but not a loadable certificate.</returns>
    internal static bool IsInvalid(string certificateStr)
    {
        if (string.IsNullOrWhiteSpace(certificateStr))
        {
            return false;
        }

        try
        {
            using var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificateStr));

            // A loadable but under-strength signing key is also invalid (#733): reject an RSA key below the
            // floor or a non-approved EC curve at the admin write path, so an operator gets a clear rejection
            // at save rather than a silent login failure later. The same predicate gates verification.
            return !HasAcceptableSigningKey(certificate);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            return true;
        }
    }

    /// <summary>
    /// Whether the certificate's public key meets the minimum signing-key strength (#733): an RSA key at least
    /// <see cref="SigningKeyStrength.MinimumRsaKeyBits"/> bits, or an EC key on an approved NIST P-curve. A
    /// weaker key — or an unrecognised key algorithm — is not trusted, so the SAML signature it produced is
    /// not accepted (fail-closed). The single floor is shared with the OpenID id_token JWKS path so the two
    /// cannot drift.
    /// </summary>
    /// <param name="certificate">The identity-provider signing certificate.</param>
    /// <returns><see langword="true"/> when the certificate's public key meets the floor.</returns>
    internal static bool HasAcceptableSigningKey(X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            return SigningKeyStrength.IsAcceptableRsaKeySize(rsa.KeySize);
        }

        using var ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            // A named curve exposes its OID; an explicit/unknown curve has none and is not approved.
            var curveOid = ecdsa.ExportParameters(false).Curve.Oid?.Value;
            return SigningKeyStrength.IsApprovedEcCurveOid(curveOid);
        }

        // An unrecognised public-key algorithm (e.g. DSA) is not a signing key this plugin trusts.
        return false;
    }
}
