using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Builds throw-away service-provider signing keys for the outgoing-signing tests (#167): a Base64
/// PKCS#12 (PFX) blob carrying an RSA keypair, the exact shape an operator supplies in
/// <c>SamlSigningKeyPfx</c>, plus its public key for verifying the emitted signature.
/// </summary>
internal static class SamlSigningKeyFactory
{
    /// <summary>Creates a fresh self-signed RSA signing certificate.</summary>
    internal static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Jellyfin SSO Test SP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    /// <summary>Creates a signing key as the Base64 PKCS#12 blob the config stores.</summary>
    internal static string CreatePfxBase64()
    {
        using var certificate = CreateCertificate();
        return Convert.ToBase64String(certificate.Export(X509ContentType.Pfx));
    }

    /// <summary>Creates a signing key and returns both the stored blob and its public key for verification.</summary>
    internal static (string PfxBase64, RSA PublicKey) CreatePair()
    {
        using var certificate = CreateCertificate();
        var pfx = Convert.ToBase64String(certificate.Export(X509ContentType.Pfx));

        // A fresh public-only key so the caller can verify without holding the private cert.
        var publicKey = RSA.Create();
        publicKey.ImportParameters(certificate.GetRSAPublicKey()!.ExportParameters(false));
        return (pfx, publicKey);
    }
}
