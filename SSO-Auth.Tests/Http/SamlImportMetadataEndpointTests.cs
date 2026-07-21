// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// End-to-end tests of the SAML metadata-import endpoint (#735) through the controller harness: pasted XML
/// and a server-fetched URL both return the parsed values, and invalid input fails closed with a 400. The
/// endpoint's elevation gate is asserted by the controller authorization suite that enumerates every
/// [Authorize(RequiresElevation)] endpoint.
/// </summary>
[Collection("SSOController")]
public class SamlImportMetadataEndpointTests
{
    private const string EntityId = "https://idp.example.com/e";
    private const string Sso = "https://idp.example.com/sso";

    private static string Metadata()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test IdP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var cert = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
        return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"" + EntityId + "\">" +
               "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
               $"<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" +
               $"<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{Sso}\" />" +
               "</md:IDPSSODescriptor></md:EntityDescriptor>";
    }

    [Fact]
    public async Task SamlImportMetadata_PastedXml_ReturnsParsedValues()
    {
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.SamlImportMetadata(new SamlMetadataImportRequest { Xml = Metadata() });

        var import = Assert.IsType<SamlMetadataImport>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(EntityId, import.EntityId);
        Assert.Equal(Sso, import.Endpoint);
        Assert.NotNull(import.PrimaryCertificate);
    }

    [Fact]
    public async Task SamlImportMetadata_FetchedUrl_ReturnsParsedValues()
    {
        var xml = Metadata();
        var harness = new SsoControllerHarness(httpResponder: _ =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(xml) });

        var result = await harness.Controller.SamlImportMetadata(new SamlMetadataImportRequest { Url = "https://idp.example.com/metadata" });

        var import = Assert.IsType<SamlMetadataImport>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(EntityId, import.EntityId);
        Assert.Equal(Sso, import.Endpoint);
    }

    [Fact]
    public async Task SamlImportMetadata_FetchedUtf8BomMetadata_Parses()
    {
        // ADFS serves FederationMetadata.xml UTF-8-with-BOM; the fetch must decode it (BOM stripped) rather
        // than fail the marquee URL-import path.
        var bom = System.Text.Encoding.UTF8.GetPreamble();
        var body = System.Text.Encoding.UTF8.GetBytes(Metadata());
        var withBom = new byte[bom.Length + body.Length];
        Array.Copy(bom, withBom, bom.Length);
        Array.Copy(body, 0, withBom, bom.Length, body.Length);
        var harness = new SsoControllerHarness(httpResponder: _ =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(withBom) });

        var result = await harness.Controller.SamlImportMetadata(new SamlMetadataImportRequest { Url = "https://idp.example.com/FederationMetadata.xml" });

        var import = Assert.IsType<SamlMetadataImport>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(EntityId, import.EntityId);
    }

    [Fact]
    public async Task SamlImportMetadata_MalformedXml_Returns400()
    {
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.SamlImportMetadata(new SamlMetadataImportRequest { Xml = "<not-metadata/>" });

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task SamlImportMetadata_NeitherUrlNorXml_Returns400()
    {
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.SamlImportMetadata(new SamlMetadataImportRequest());

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task SamlImportMetadata_NullBody_Returns400()
    {
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.SamlImportMetadata(null!);

        Assert.IsType<BadRequestObjectResult>(result);
    }
}
