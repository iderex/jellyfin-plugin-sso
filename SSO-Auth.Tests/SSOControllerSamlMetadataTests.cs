using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the SAML SP metadata endpoint (<c>SamlMetadata</c>) via
/// <see cref="SsoControllerHarness"/> (#162). They cover the guard branches (unknown/disabled provider),
/// the anti-spoofing invariant — the published entity id and assertion-consumer URL come from the
/// configured canonical Base URL and NEVER the request host, and the endpoint fails closed when that base
/// URL is unset rather than emitting a spoofable ACS — and the signing-conditional key descriptor, which
/// advertises only the PUBLIC certificate.
/// </summary>
[Collection("SSOController")]
public class SSOControllerSamlMetadataTests
{
    private static readonly XNamespace Md = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static readonly XNamespace Ds = "http://www.w3.org/2000/09/xmldsig#";

    // The harness always serves from this request host; the anti-spoofing tests assert it never appears in
    // the published metadata (only the configured canonical Base URL does).
    private const string RequestHost = "jf.example.com";
    private const string CanonicalBaseUrl = "https://canonical.example.com";

    [Fact]
    public void SamlMetadata_UnknownProvider_RejectsAsUnknownProvider()
    {
        var harness = new SsoControllerHarness();

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("nope"));

        Assert.Equal(400, result.StatusCode);
        Assert.Equal("No matching provider found", result.Content);
    }

    [Fact]
    public void SamlMetadata_DisabledProvider_RejectsAsUnknownProvider()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = false,
            SamlClientId = "https://sp",
            BaseUrlOverride = CanonicalBaseUrl,
        });

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("adfs"));

        // A disabled provider is refused with the uniform unknown-provider body, so this anonymous surface
        // does not expose its entity id / signing certificate either.
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("No matching provider found", result.Content);
    }

    [Fact]
    public void SamlMetadata_NoCanonicalBaseUrl_FailsClosed_NeverDerivingFromTheRequestHost()
    {
        // The anti-spoofing invariant: with no canonical Base URL configured, the endpoint refuses rather
        // than bake the request host (which a forwarded X-Forwarded-Host could influence) into metadata an
        // identity provider consumes. So it never emits an ACS pointing at the request host.
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlClientId = "https://sp",
            BaseUrlOverride = null,
        });

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("adfs"));

        Assert.Equal(409, result.StatusCode);
        Assert.DoesNotContain(RequestHost, result.Content ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public void SamlMetadata_BlankClientId_FailsClosed()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlClientId = "   ",
            BaseUrlOverride = CanonicalBaseUrl,
        });

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("adfs"));

        Assert.Equal(409, result.StatusCode);
    }

    [Fact]
    public void SamlMetadata_SigningOff_UsesTheCanonicalBaseUrl_NotTheRequestHost()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlClientId = "https://sp.example.com/entity",
            BaseUrlOverride = CanonicalBaseUrl,
            SignAuthnRequests = false,
        });

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("adfs"));

        Assert.Equal(200, result.StatusCode);
        Assert.Equal("application/samlmetadata+xml", result.ContentType);

        var document = XDocument.Parse(result.Content!);
        Assert.Equal("https://sp.example.com/entity", (string?)document.Root!.Attribute("entityID"));

        var spDescriptor = document.Root.Element(Md + "SPSSODescriptor");
        Assert.Equal("false", (string?)spDescriptor!.Attribute("AuthnRequestsSigned"));
        Assert.Null(spDescriptor.Element(Md + "KeyDescriptor"));

        var acs = (string?)spDescriptor.Element(Md + "AssertionConsumerService")!.Attribute("Location");
        Assert.Equal(CanonicalBaseUrl + "/sso/SAML/post/adfs", acs);
        // The published ACS is anchored to the canonical Base URL, never the spoofable request host.
        Assert.DoesNotContain(RequestHost, result.Content!, StringComparison.Ordinal);
    }

    [Fact]
    public void SamlMetadata_SigningOn_AdvertisesThePublicCertificate_WithoutThePrivateKey()
    {
        using var certificate = SamlSigningKeyFactory.CreateCertificate();
        var pfxBase64 = Convert.ToBase64String(certificate.Export(X509ContentType.Pfx));
        var expectedPublicBase64 = Convert.ToBase64String(certificate.RawData);

        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlClientId = "https://sp",
            BaseUrlOverride = CanonicalBaseUrl,
            SignAuthnRequests = true,
            SamlSigningKeyPfx = pfxBase64,
        });

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("adfs"));

        Assert.Equal(200, result.StatusCode);
        var document = XDocument.Parse(result.Content!);
        var spDescriptor = document.Root!.Element(Md + "SPSSODescriptor");
        Assert.Equal("true", (string?)spDescriptor!.Attribute("AuthnRequestsSigned"));

        var advertised = spDescriptor
            .Element(Md + "KeyDescriptor")!
            .Element(Ds + "KeyInfo")!
            .Element(Ds + "X509Data")!
            .Element(Ds + "X509Certificate")!.Value;

        // Exactly the public certificate is advertised — not the PFX/private key.
        Assert.Equal(expectedPublicBase64, advertised);
        using var loaded = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(advertised));
        Assert.False(loaded.HasPrivateKey);
        // The stored PFX (which carries the private key) never appears in the response.
        Assert.DoesNotContain(pfxBase64, result.Content!, StringComparison.Ordinal);
    }

    [Fact]
    public void SamlMetadata_SigningOnButKeyUnloadable_FailsClosed()
    {
        // Request signing enabled but the key is garbage: fail closed (mirroring the signed challenge)
        // rather than advertise AuthnRequestsSigned with no usable key.
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlClientId = "https://sp",
            BaseUrlOverride = CanonicalBaseUrl,
            SignAuthnRequests = true,
            SamlSigningKeyPfx = "not-a-valid-pfx",
        });

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("adfs"));

        Assert.Equal(409, result.StatusCode);
    }
}
