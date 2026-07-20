using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlCertificate"/> and the SAML/Add certificate guard (#206): a non-blank but
/// unloadable SAML signing certificate is rejected at the admin write path, so it cannot make every
/// callback throw a CryptographicException 500; blank is valid (a half-configured provider). Also covers
/// the minimum signing-key-strength floor (#733): an under-strength RSA key or a non-approved EC curve is
/// rejected at the admin write path and at signature verification (the shared predicate the OIDC JWKS path
/// also uses), while an RSA key at the floor and an approved NIST P-curve pass.
/// </summary>
public class SamlCertificateTests
{
    [Fact]
    public void IsInvalid_UnderStrengthRsaCertificate_True()
    {
        // #733: an RSA-1024 signing certificate is loadable but below the 2048-bit floor — rejected at the
        // admin write path so the operator gets a clear rejection at save, not a silent login failure later.
        Assert.True(SamlCertificate.IsInvalid(RsaCertificateBase64(1024)));
    }

    [Fact]
    public void IsInvalid_MinimumStrengthRsaCertificate_False()
    {
        // An RSA-2048 certificate sits exactly at the floor and is accepted.
        Assert.False(SamlCertificate.IsInvalid(RsaCertificateBase64(2048)));
    }

    [Fact]
    public void HasAcceptableSigningKey_UnderStrengthRsa_False()
    {
        using var certificate = RsaCertificate(1024);
        Assert.False(SamlCertificate.HasAcceptableSigningKey(certificate));
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    public void HasAcceptableSigningKey_RsaAtOrAboveFloor_True(int keyBits)
    {
        using var certificate = RsaCertificate(keyBits);
        Assert.True(SamlCertificate.HasAcceptableSigningKey(certificate));
    }

    [Fact]
    public void HasAcceptableSigningKey_ApprovedEcCurve_True()
    {
        // #733: an EC certificate on an approved NIST P-curve (P-256) validates.
        using var certificate = EcCertificate(ECCurve.NamedCurves.nistP256);
        Assert.True(SamlCertificate.HasAcceptableSigningKey(certificate));
    }

    [Fact]
    public void HasAcceptableSigningKey_NonApprovedEcCurve_False()
    {
        // secp256k1 is a valid EC curve but not one of the approved NIST P-curves — not a signing key this
        // plugin trusts, so its signatures are not accepted (fail-closed).
        using var ecdsa = ECDsa.Create(ECCurve.CreateFromValue("1.3.132.0.10")); // secp256k1
        var request = new CertificateRequest("CN=Test secp256k1 IdP", ecdsa, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        Assert.False(SamlCertificate.HasAcceptableSigningKey(certificate));
    }

    private static X509Certificate2 RsaCertificate(int keyBits)
    {
        using var rsa = RSA.Create(keyBits);
        var request = new CertificateRequest("CN=Test SAML IdP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 EcCertificate(ECCurve curve)
    {
        using var ecdsa = ECDsa.Create(curve);
        var request = new CertificateRequest("CN=Test EC SAML IdP", ecdsa, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static string RsaCertificateBase64(int keyBits)
    {
        using var certificate = RsaCertificate(keyBits);
        return Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
    }

    [Fact]
    public void IsInvalid_ValidCertificate_False()
    {
        Assert.False(SamlCertificate.IsInvalid(SamlTestFactory.Create().CertificateBase64));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsInvalid_Blank_False(string? certificateStr)
    {
        Assert.False(SamlCertificate.IsInvalid(certificateStr));
    }

    [Theory]
    [InlineData("@@ not base64 @@")] // FormatException
    [InlineData("QUJD")] // valid base64 ("ABC") but not a certificate -> CryptographicException
    public void IsInvalid_SetButUnloadable_True(string certificateStr)
    {
        Assert.True(SamlCertificate.IsInvalid(certificateStr));
    }

    [Fact]
    public void RejectInvalidSamlCertificate_ValidOrBlank_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
        {
            SSOController.RejectInvalidSamlCertificate(SamlTestFactory.Create().CertificateBase64);
            SSOController.RejectInvalidSamlCertificate(null);
            SSOController.RejectInvalidSamlCertificate(string.Empty);
        });

        Assert.Null(exception);
    }

    [Fact]
    public void RejectInvalidSamlCertificate_Garbage_Throws()
    {
        Assert.Throws<System.ArgumentException>(() => SSOController.RejectInvalidSamlCertificate("QUJD"));
    }

    [Fact]
    public void RejectInvalidSamlSecondaryCertificate_ValidOrBlank_DoesNotThrow()
    {
        // The inbound secondary verification certificate (#491) is validated exactly like the primary — a
        // valid or blank value passes the Add-endpoint guard.
        var exception = Record.Exception(() =>
        {
            SSOController.RejectInvalidSamlSecondaryCertificate(SamlTestFactory.Create().CertificateBase64);
            SSOController.RejectInvalidSamlSecondaryCertificate(null);
            SSOController.RejectInvalidSamlSecondaryCertificate(string.Empty);
        });

        Assert.Null(exception);
    }

    [Fact]
    public void RejectInvalidSamlSecondaryCertificate_Garbage_Throws()
    {
        Assert.Throws<System.ArgumentException>(() => SSOController.RejectInvalidSamlSecondaryCertificate("QUJD"));
    }
}
