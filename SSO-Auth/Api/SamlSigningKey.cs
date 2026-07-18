using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Loads this service provider's SAML signing key (#167). The key is supplied by the operator as a
/// Base64-encoded, unencrypted PKCS#12 (PFX) blob carrying the certificate and its private key — an RSA or
/// ECDSA key (#493) — the same keypair whose public certificate the identity provider is configured to
/// trust for "signed AuthnRequest" setups. Loading is fail-closed: a blank value is "no signing key
/// configured" (valid, signing simply stays off), and a set-but-unloadable value is rejected rather than
/// silently ignored, so an operator who turned signing on can never get a silent unsigned downgrade.
/// </summary>
internal static class SamlSigningKey
{
    /// <summary>
    /// Attempts to load the signing certificate (with its private key) from the stored Base64 PKCS#12 blob.
    /// </summary>
    /// <param name="pfxBase64">The stored Base64 PKCS#12 blob, or blank when signing is not configured.</param>
    /// <param name="certificate">The loaded certificate with its private key, or null on failure.</param>
    /// <returns><see langword="true"/> only when a non-blank blob loaded into a usable certificate.</returns>
    internal static bool TryLoad(string pfxBase64, out X509Certificate2 certificate)
    {
        certificate = null;
        if (string.IsNullOrWhiteSpace(pfxBase64))
        {
            return false;
        }

        try
        {
            // EphemeralKeySet keeps the imported private key in memory rather than persisting it to the
            // per-user CNG/CAPI on-disk key store (the Windows default), avoiding SP private-key material
            // at rest and orphaned key containers across repeated loads. It is unsupported on macOS
            // (throws PlatformNotSupportedException), which does not use that on-disk store anyway, so fall
            // back to the default key set there.
            var flags = OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;
            certificate = X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(pfxBase64), null, flags);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            certificate?.Dispose();
            certificate = null;
            return false;
        }
    }

    /// <summary>
    /// Whether a signing-key value is set but is not a loadable PKCS#12 blob, for rejecting it at the admin
    /// write paths (mirrors <see cref="SamlCertificate.IsInvalid"/>). Blank is valid (signing not
    /// configured); a set-but-unloadable value is invalid.
    /// </summary>
    /// <param name="pfxBase64">The Base64 PKCS#12 blob.</param>
    /// <returns><see langword="true"/> if the value is set but not a loadable signing key.</returns>
    internal static bool IsInvalid(string pfxBase64)
    {
        if (string.IsNullOrWhiteSpace(pfxBase64))
        {
            return false;
        }

        if (!TryLoad(pfxBase64, out var certificate))
        {
            return true;
        }

        using (certificate)
        {
            // A PKCS#12 with no usable private key cannot sign, so it is as unusable as a garbage blob:
            // reject it here rather than let it pass validation and then fail closed at every challenge.
            using var privateKey = GetSigningKey(certificate);
            return privateKey is null;
        }
    }

    /// <summary>
    /// Returns the service-provider signing key from the certificate — its RSA or ECDSA private key,
    /// whichever it carries (#493) — or null when it has neither and so cannot sign. The caller owns the
    /// returned key and must dispose it.
    /// </summary>
    /// <param name="certificate">The loaded signing certificate.</param>
    /// <returns>The RSA or ECDSA private key, or null when the certificate cannot sign.</returns>
    internal static AsymmetricAlgorithm GetSigningKey(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        // Prefer RSA (the common case and the byte-identical existing path); fall back to ECDSA. Any other
        // key type returns null, which the callers treat as "unusable" and fail closed on.
        return (AsymmetricAlgorithm)certificate.GetRSAPrivateKey() ?? certificate.GetECDsaPrivateKey();
    }
}
