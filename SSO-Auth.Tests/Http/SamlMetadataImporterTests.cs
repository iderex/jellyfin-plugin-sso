using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests the input dispatch of <see cref="SamlMetadataImporter"/> (#735): exactly one of a URL or pasted XML,
/// and that the XML path parses without any outbound fetch. The URL-fetch path (SSRF-hardened) is exercised
/// end-to-end through the controller harness; the parsing itself is covered by
/// <see cref="SamlMetadataParserTests"/>.
/// </summary>
public class SamlMetadataImporterTests
{
    private static string ValidMetadata()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test IdP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var cert = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
        return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"https://idp.example.com/e\">" +
               "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
               $"<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" +
               "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.example.com/sso\" />" +
               "</md:IDPSSODescriptor></md:EntityDescriptor>";
    }

    [Fact]
    public async Task ImportAsync_NeitherUrlNorXml_FailsClosed()
    {
        var factory = Substitute.For<IHttpClientFactory>();
        await Assert.ThrowsAsync<SamlMetadataException>(() => SamlMetadataImporter.ImportAsync(factory, null, "  ", CancellationToken.None));
    }

    [Fact]
    public async Task ImportAsync_BothUrlAndXml_FailsClosed()
    {
        var factory = Substitute.For<IHttpClientFactory>();
        await Assert.ThrowsAsync<SamlMetadataException>(() =>
            SamlMetadataImporter.ImportAsync(factory, "https://idp.example.com/metadata", ValidMetadata(), CancellationToken.None));
    }

    [Fact]
    public async Task ImportAsync_Xml_ParsesWithoutFetching()
    {
        var factory = Substitute.For<IHttpClientFactory>();

        var result = await SamlMetadataImporter.ImportAsync(factory, null, ValidMetadata(), CancellationToken.None);

        Assert.Equal("https://idp.example.com/e", result.EntityId);
        Assert.Equal("https://idp.example.com/sso", result.Endpoint);
        factory.DidNotReceive().CreateClient(Arg.Any<string>()); // the XML path never opens an outbound client
    }

    [Fact]
    public async Task ImportAsync_MalformedXml_FailsClosed()
    {
        var factory = Substitute.For<IHttpClientFactory>();
        await Assert.ThrowsAsync<SamlMetadataException>(() =>
            SamlMetadataImporter.ImportAsync(factory, null, "<not-metadata/>", CancellationToken.None));
    }

    [Theory]
    [InlineData("ftp://idp.example.com/metadata")]
    [InlineData("file:///etc/passwd")]
    [InlineData("not-a-url")]
    public async Task ImportAsync_NonHttpUrl_FailsClosedBeforeFetching(string url)
    {
        // The scheme allow-list rejects a non-http(s) URL before any outbound client is created.
        var factory = Substitute.For<IHttpClientFactory>();

        await Assert.ThrowsAsync<SamlMetadataException>(() => SamlMetadataImporter.ImportAsync(factory, url, null, CancellationToken.None));

        factory.DidNotReceive().CreateClient(Arg.Any<string>());
    }
}
