using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlCertificate"/> and the SAML/Add certificate guard (#206): a non-blank but
/// unloadable SAML signing certificate is rejected at the admin write path, so it cannot make every
/// callback throw a CryptographicException 500; blank is valid (a half-configured provider).
/// </summary>
public class SamlCertificateTests
{
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
        SSOController.RejectInvalidSamlCertificate(SamlTestFactory.Create().CertificateBase64);
        SSOController.RejectInvalidSamlCertificate(null);
        SSOController.RejectInvalidSamlCertificate(string.Empty);
    }

    [Fact]
    public void RejectInvalidSamlCertificate_Garbage_Throws()
    {
        Assert.Throws<System.ArgumentException>(() => SSOController.RejectInvalidSamlCertificate("QUJD"));
    }
}
