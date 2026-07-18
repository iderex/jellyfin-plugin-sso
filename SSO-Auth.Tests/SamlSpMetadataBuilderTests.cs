using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for the pure <see cref="SamlSpMetadataBuilder"/> (#162): the emitted document is well-formed SAML
/// 2.0 SP metadata, its entity id and HTTP-POST assertion-consumer URL are the exact values it is handed, a
/// signing <c>KeyDescriptor</c> is present precisely when (and carries exactly) the certificate given, and
/// the builder never invents a spoofable value of its own — it only serializes its inputs.
/// </summary>
public class SamlSpMetadataBuilderTests
{
    private static readonly XNamespace Md = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static readonly XNamespace Ds = "http://www.w3.org/2000/09/xmldsig#";
    private const string ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";
    private const string HttpPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    private const string EntityId = "https://jellyfin.example.com/sso/SAML/adfs";
    private const string AcsUrl = "https://jellyfin.example.com/sso/SAML/post/adfs";

    [Fact]
    public void Build_WithoutSigning_IsWellFormedSpMetadataWithTheGivenEntityIdAndAcs()
    {
        var document = XDocument.Parse(SamlSpMetadataBuilder.Build(EntityId, AcsUrl, signingCertificateBase64: null));

        var entityDescriptor = document.Root;
        Assert.Equal(Md + "EntityDescriptor", entityDescriptor!.Name);
        Assert.Equal(EntityId, (string?)entityDescriptor.Attribute("entityID"));

        var spDescriptor = entityDescriptor.Element(Md + "SPSSODescriptor");
        Assert.NotNull(spDescriptor);
        Assert.Equal(ProtocolNamespace, (string?)spDescriptor.Attribute("protocolSupportEnumeration"));

        var acs = spDescriptor.Element(Md + "AssertionConsumerService");
        Assert.NotNull(acs);
        Assert.Equal(HttpPostBinding, (string?)acs.Attribute("Binding"));
        Assert.Equal(AcsUrl, (string?)acs.Attribute("Location"));
        Assert.Equal("0", (string?)acs.Attribute("index"));
        Assert.Equal("true", (string?)acs.Attribute("isDefault"));
    }

    [Fact]
    public void Build_WithoutSigning_AdvertisesNoSigningKeyAndAuthnRequestsSignedFalse()
    {
        var document = XDocument.Parse(SamlSpMetadataBuilder.Build(EntityId, AcsUrl, signingCertificateBase64: null));
        var spDescriptor = document.Root!.Element(Md + "SPSSODescriptor");

        Assert.Equal("false", (string?)spDescriptor!.Attribute("AuthnRequestsSigned"));
        // Assertions are always signature-checked by this SP, so it truthfully requires them signed.
        Assert.Equal("true", (string?)spDescriptor.Attribute("WantAssertionsSigned"));
        Assert.Null(spDescriptor.Element(Md + "KeyDescriptor"));
    }

    [Fact]
    public void Build_WithSigning_AdvertisesTheSigningCertificateAndAuthnRequestsSignedTrue()
    {
        using var certificate = SamlSigningKeyFactory.CreateCertificate();
        var certificateBase64 = Convert.ToBase64String(certificate.RawData);

        var document = XDocument.Parse(SamlSpMetadataBuilder.Build(EntityId, AcsUrl, certificateBase64));
        var spDescriptor = document.Root!.Element(Md + "SPSSODescriptor");

        Assert.Equal("true", (string?)spDescriptor!.Attribute("AuthnRequestsSigned"));

        var keyDescriptor = spDescriptor.Element(Md + "KeyDescriptor");
        Assert.NotNull(keyDescriptor);
        Assert.Equal("signing", (string?)keyDescriptor.Attribute("use"));

        var x509Certificate = keyDescriptor
            .Element(Ds + "KeyInfo")?
            .Element(Ds + "X509Data")?
            .Element(Ds + "X509Certificate");
        Assert.NotNull(x509Certificate);
        Assert.Equal(certificateBase64, x509Certificate.Value);
    }

    [Fact]
    public void Build_WithSigning_AdvertisedCertificateCarriesNoPrivateKey()
    {
        // The metadata must never leak the private key: the advertised certificate loads as a public-only
        // certificate. (The caller exports certificate.RawData, the public DER; this pins that whatever is
        // advertised is loadable and private-key-free.)
        using var certificate = SamlSigningKeyFactory.CreateCertificate();
        var certificateBase64 = Convert.ToBase64String(certificate.RawData);

        var document = XDocument.Parse(SamlSpMetadataBuilder.Build(EntityId, AcsUrl, certificateBase64));
        var advertised = document.Root!
            .Element(Md + "SPSSODescriptor")!
            .Element(Md + "KeyDescriptor")!
            .Element(Ds + "KeyInfo")!
            .Element(Ds + "X509Data")!
            .Element(Ds + "X509Certificate")!.Value;

        using var loaded = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(advertised));
        Assert.False(loaded.HasPrivateKey);
    }

    [Fact]
    public void Build_DeclaresUtf8Encoding()
    {
        // A StringWriter is UTF-16 internally; the builder reports UTF-8 so the declaration matches the
        // UTF-8 bytes served, rather than mislabeling the document as utf-16.
        var xml = SamlSpMetadataBuilder.Build(EntityId, AcsUrl, signingCertificateBase64: null);
        Assert.Contains("encoding=\"utf-8\"", xml, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_EscapesSpecialCharactersInEntityIdAndAcs()
    {
        // XML-significant characters in the (config-derived) inputs must be escaped so the output stays
        // well-formed and round-trips to the exact input value.
        const string entityId = "https://sp.example.com/meta?a=1&b=2<x>";
        const string acs = "https://sp.example.com/acs?q=\"z\"&r=1";

        var document = XDocument.Parse(SamlSpMetadataBuilder.Build(entityId, acs, signingCertificateBase64: null));

        Assert.Equal(entityId, (string?)document.Root!.Attribute("entityID"));
        Assert.Equal(
            acs,
            (string?)document.Root.Element(Md + "SPSSODescriptor")!.Element(Md + "AssertionConsumerService")!.Attribute("Location"));
    }
}
