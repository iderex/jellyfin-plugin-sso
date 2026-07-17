using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlSigningKey"/> (#167): fail-closed loading of the service-provider signing key
/// and the admin-write-path validity check. Blank is "not configured" (valid); a set-but-unloadable or
/// private-key-less blob is rejected, so an operator who turned signing on can never get a silent unsigned
/// downgrade.
/// </summary>
public class SamlSigningKeyTests
{
    [Fact]
    public void TryLoad_ValidPfx_ReturnsCertificateWithPrivateKey()
    {
        Assert.True(SamlSigningKey.TryLoad(SamlSigningKeyFactory.CreatePfxBase64(), out var certificate));
        using (certificate)
        {
            using var privateKey = certificate.GetRSAPrivateKey();
            Assert.NotNull(privateKey);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryLoad_Blank_ReturnsFalse(string? pfx)
    {
        Assert.False(SamlSigningKey.TryLoad(pfx!, out var certificate));
        Assert.Null(certificate);
    }

    [Theory]
    [InlineData("@@ not base64 @@")] // FormatException
    [InlineData("QUJD")] // valid base64 ("ABC") but not a PKCS#12 -> CryptographicException
    public void TryLoad_SetButUnloadable_ReturnsFalse(string pfx)
    {
        Assert.False(SamlSigningKey.TryLoad(pfx, out var certificate));
        Assert.Null(certificate);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsInvalid_Blank_False(string? pfx)
    {
        Assert.False(SamlSigningKey.IsInvalid(pfx!));
    }

    [Fact]
    public void IsInvalid_ValidPfx_False()
    {
        Assert.False(SamlSigningKey.IsInvalid(SamlSigningKeyFactory.CreatePfxBase64()));
    }

    [Theory]
    [InlineData("@@ not base64 @@")]
    [InlineData("QUJD")]
    public void IsInvalid_Garbage_True(string pfx)
    {
        Assert.True(SamlSigningKey.IsInvalid(pfx));
    }

    [Fact]
    public void IsInvalid_CertificateWithoutPrivateKey_True()
    {
        // A public-only PKCS#12 (no private key) cannot sign, so it must be rejected like garbage.
        using var certificate = SamlSigningKeyFactory.CreateCertificate();
        var publicOnlyPfx = Convert.ToBase64String(
            X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert)).Export(X509ContentType.Pkcs12));

        Assert.True(SamlSigningKey.IsInvalid(publicOnlyPfx));
    }
}
