using System.Security.Cryptography.Xml;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for the malformed-input handling on the SAML callback (#199): <see cref="SamlResponseLoader.TryParse"/>
/// maps the constructor's malformed-input exceptions to a fail-closed <see langword="false"/> (so the
/// endpoints return a clean 4xx rather than an unhandled HTTP 500), and <see cref="SamlResponse.GetSignatureAlgorithm"/>
/// — a failure-log diagnostic — never throws on a malformed signature element.
/// </summary>
public class SamlResponseParsingTests
{
    [Fact]
    public void TryLoad_ValidResponse_ReturnsTrue()
    {
        var fixture = SamlTestFactory.Create();

        Assert.True(SamlResponseLoader.TryParse(fixture.CertificateBase64, fixture.EncodeResponse(), out var response));
        Assert.NotNull(response);
    }

    [Fact]
    public void TryLoad_NonBase64Response_ReturnsFalse()
    {
        // Convert.FromBase64String throws FormatException; TryLoad maps it to a rejection, not a 500.
        var fixture = SamlTestFactory.Create();

        Assert.False(SamlResponseLoader.TryParse(fixture.CertificateBase64, "@@ not base64 @@", out var response));
        Assert.Null(response);
    }

    [Fact]
    public void TryLoad_OversizedResponse_IsRejectedFailClosed_BeforeDecoding()
    {
        // A body longer than the pre-decode cap is an unauthenticated pre-signature DoS attempt (#249/#754):
        // it must be refused fail-closed BEFORE any base64 decode / DOM build, spending no crypto or bulk
        // allocation on the untrusted input. The exact bytes are irrelevant — the length gate fires first —
        // so a plainly over-length string is enough; the result is a clean rejection, never an unmapped throw.
        var fixture = SamlTestFactory.Create();
        var oversized = new string('A', SamlResponseLoader.MaxEncodedResponseLength + 1);

        Assert.False(SamlResponseLoader.TryParse(fixture.CertificateBase64, oversized, out var response));
        Assert.Null(response);
    }

    [Fact]
    public void TryLoad_MalformedXmlBody_ReturnsFalse()
    {
        var fixture = SamlTestFactory.Create();

        Assert.False(SamlResponseLoader.TryParse(fixture.CertificateBase64, SamlFixture.Encode("<unterminated>"), out var response));
        Assert.Null(response);
    }

    [Fact]
    public void TryLoad_DoctypeBody_ReturnsFalse()
    {
        // DtdProcessing.Prohibit (the P2#9 XXE guard) throws XmlException on a DOCTYPE; TryLoad maps that
        // intentional throw to a clean rejection rather than a 500.
        var fixture = SamlTestFactory.Create();
        var body = SamlFixture.Encode("<!DOCTYPE foo [<!ENTITY x \"y\">]><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" />");

        Assert.False(SamlResponseLoader.TryParse(fixture.CertificateBase64, body, out var response));
        Assert.Null(response);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void TryParse_NullOrEmptyResponse_ReturnsFalse(string? responseString)
    {
        // A missing SAMLResponse (absent form field / omitted JSON data) is the most common malformed
        // callback; it must reject cleanly, not raise ArgumentNullException from Convert.FromBase64String.
        var fixture = SamlTestFactory.Create();

        Assert.False(SamlResponseLoader.TryParse(fixture.CertificateBase64, responseString, out var response));
        Assert.Null(response);
    }

    [Fact]
    public void TryParse_OversizedResponse_ReturnsFalse()
    {
        // A body over the length cap is rejected before any base64 decode / DOM parse (#249) — fail
        // closed, with no crypto or bulk allocation spent on an untrusted multi-MB body.
        var fixture = SamlTestFactory.Create();
        var oversized = new string('A', SamlResponseLoader.MaxEncodedResponseLength + 1);

        Assert.False(SamlResponseLoader.TryParse(fixture.CertificateBase64, oversized, out var response));
        Assert.Null(response);
    }

    [Fact]
    public void GetSignatureAlgorithm_ValidResponse_ReturnsTheSignatureMethod()
    {
        var fixture = SamlTestFactory.Create();
        Assert.True(SamlResponseLoader.TryParse(fixture.CertificateBase64, fixture.EncodeResponse(), out var response));

        Assert.Equal(SignedXml.XmlDsigRSASHA256Url, response.GetSignatureAlgorithm());
    }

    [Fact]
    public void GetSignatureAlgorithm_MalformedSignatureElement_ReturnsNullNotThrow()
    {
        // A ds:Signature with no SignedInfo makes SignedXml.LoadXml throw CryptographicException. The
        // diagnostic must swallow it and return null so the caller's clean rejection is not turned into
        // a 500 (#199). The document itself is well-formed, so TryLoad succeeds and the throw would
        // otherwise surface only from GetSignatureAlgorithm.
        const string xml =
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
            "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
            "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
            "<ds:Signature><ds:Garbage /></ds:Signature>" +
            "<saml:Assertion />" +
            "</samlp:Response>";

        Assert.True(SamlResponseLoader.TryParse(SamlFixture.ForeignCertificateBase64(), SamlFixture.Encode(xml), out var response));
        Assert.Null(response.GetSignatureAlgorithm());
    }

    [Fact]
    public void TryParse_GarbageCertificate_ReturnsFalse()
    {
        // A non-loadable configured SamlCertificate (a legacy or hand-edited config) must fail closed to a
        // clean rejection rather than the unhandled CryptographicException 500 it produced before (#206).
        var fixture = SamlTestFactory.Create();

        Assert.False(SamlResponseLoader.TryParse("QUJD", fixture.EncodeResponse(), out var response));
        Assert.Null(response);
    }
}
