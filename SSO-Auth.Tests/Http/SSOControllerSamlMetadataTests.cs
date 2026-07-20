using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
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
    public void SamlMetadata_PublishesBothAcsSpellings_NewDefaultThenLegacy_AnchoredToTheCanonicalBaseUrl()
    {
        // The SP honours either ACS spelling on the way back (SamlAcsUrlBuilder.ExpectedAcsUrls), so the
        // endpoint publishes both (#569): the new-path spelling as the default (index 0), the legacy spelling
        // as a second, non-default endpoint (index 1). Both are anchored to the canonical Base URL, never the
        // spoofable request host.
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlClientId = "https://sp",
            BaseUrlOverride = CanonicalBaseUrl,
            SignAuthnRequests = false,
        });

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("adfs"));

        Assert.Equal(200, result.StatusCode);
        var spDescriptor = XDocument.Parse(result.Content!).Root!.Element(Md + "SPSSODescriptor");
        var acsElements = spDescriptor!.Elements(Md + "AssertionConsumerService").ToList();

        Assert.Equal(2, acsElements.Count);

        Assert.Equal(CanonicalBaseUrl + "/sso/SAML/post/adfs", (string?)acsElements[0].Attribute("Location"));
        Assert.Equal("0", (string?)acsElements[0].Attribute("index"));
        Assert.Equal("true", (string?)acsElements[0].Attribute("isDefault"));

        Assert.Equal(CanonicalBaseUrl + "/sso/SAML/p/adfs", (string?)acsElements[1].Attribute("Location"));
        Assert.Equal("1", (string?)acsElements[1].Attribute("index"));
        Assert.Equal("false", (string?)acsElements[1].Attribute("isDefault"));

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
    public void SamlMetadata_RolloverSet_AdvertisesBothPublicCertificates_AsTwoSigningKeyDescriptors()
    {
        // The overlap window (#491): with a rollover key configured the endpoint publishes BOTH public
        // certificates, so the identity provider trusts either while the admin swaps the SP signing cert.
        using var primary = SamlSigningKeyFactory.CreateCertificate();
        using var rollover = SamlSigningKeyFactory.CreateCertificate();
        var primaryPfx = Convert.ToBase64String(primary.Export(X509ContentType.Pfx));
        var rolloverPfx = Convert.ToBase64String(rollover.Export(X509ContentType.Pfx));
        var expectedPrimaryPublic = Convert.ToBase64String(primary.RawData);
        var expectedRolloverPublic = Convert.ToBase64String(rollover.RawData);

        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlClientId = "https://sp",
            BaseUrlOverride = CanonicalBaseUrl,
            SignAuthnRequests = true,
            SamlSigningKeyPfx = primaryPfx,
            SamlRolloverSigningKeyPfx = rolloverPfx,
        });

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("adfs"));

        Assert.Equal(200, result.StatusCode);
        var spDescriptor = XDocument.Parse(result.Content!).Root!.Element(Md + "SPSSODescriptor");
        var advertised = spDescriptor!
            .Elements(Md + "KeyDescriptor")
            .Select(kd => kd.Element(Ds + "KeyInfo")!.Element(Ds + "X509Data")!.Element(Ds + "X509Certificate")!.Value)
            .ToList();

        Assert.Equal(new[] { expectedPrimaryPublic, expectedRolloverPublic }, advertised);
        // Neither PFX (each carrying a private key) ever appears in the served metadata.
        Assert.DoesNotContain(primaryPfx, result.Content!, StringComparison.Ordinal);
        Assert.DoesNotContain(rolloverPfx, result.Content!, StringComparison.Ordinal);
        foreach (var certificateBase64 in advertised)
        {
            using var loaded = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificateBase64));
            Assert.False(loaded.HasPrivateKey);
        }
    }

    [Fact]
    public void SamlMetadata_RolloverEqualToPrimary_CollapsesToASingleKeyDescriptor()
    {
        // Promoting the rollover into the primary field (both hold the same cert) is the end state of a
        // rotation: the redundant second descriptor is dropped, returning to a single-key document without
        // the admin having to blank the write-only, blank-keeps-stored rollover key.
        using var certificate = SamlSigningKeyFactory.CreateCertificate();
        var pfx = Convert.ToBase64String(certificate.Export(X509ContentType.Pfx));

        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlClientId = "https://sp",
            BaseUrlOverride = CanonicalBaseUrl,
            SignAuthnRequests = true,
            SamlSigningKeyPfx = pfx,
            SamlRolloverSigningKeyPfx = pfx,
        });

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("adfs"));

        Assert.Equal(200, result.StatusCode);
        var spDescriptor = XDocument.Parse(result.Content!).Root!.Element(Md + "SPSSODescriptor");
        Assert.Single(spDescriptor!.Elements(Md + "KeyDescriptor"));
    }

    [Fact]
    public void SamlMetadata_RolloverSetButUnloadable_FailsClosed()
    {
        // A set-but-unloadable rollover key surfaces loudly (409), the same fail-closed posture as the
        // primary — it never emits a broken KeyDescriptor and never silently drops a configured key.
        using var primary = SamlSigningKeyFactory.CreateCertificate();
        var primaryPfx = Convert.ToBase64String(primary.Export(X509ContentType.Pfx));

        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlClientId = "https://sp",
            BaseUrlOverride = CanonicalBaseUrl,
            SignAuthnRequests = true,
            SamlSigningKeyPfx = primaryPfx,
            SamlRolloverSigningKeyPfx = "not-a-valid-pfx",
        });

        var result = Assert.IsType<ContentResult>(harness.Controller.SamlMetadata("adfs"));

        Assert.Equal(409, result.StatusCode);
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
