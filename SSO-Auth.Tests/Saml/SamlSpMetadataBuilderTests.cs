// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
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
    public void Build_WithRollover_AdvertisesBothSigningCertificates_AsTwoKeyDescriptors()
    {
        // The overlap window (#491): the SP publishes BOTH its primary and its rollover PUBLIC certificate
        // so the identity provider trusts either while the admin swaps the SP's own signing cert.
        using var primary = SamlSigningKeyFactory.CreateCertificate();
        using var rollover = SamlSigningKeyFactory.CreateCertificate();
        var primaryBase64 = Convert.ToBase64String(primary.RawData);
        var rolloverBase64 = Convert.ToBase64String(rollover.RawData);

        var document = XDocument.Parse(SamlSpMetadataBuilder.Build(EntityId, AcsUrl, primaryBase64, rolloverBase64));
        var spDescriptor = document.Root!.Element(Md + "SPSSODescriptor");

        Assert.Equal("true", (string?)spDescriptor!.Attribute("AuthnRequestsSigned"));

        var keyDescriptors = spDescriptor.Elements(Md + "KeyDescriptor").ToList();
        Assert.Equal(2, keyDescriptors.Count);
        Assert.All(keyDescriptors, kd => Assert.Equal("signing", (string?)kd.Attribute("use")));

        var advertised = keyDescriptors
            .Select(kd => kd.Element(Ds + "KeyInfo")!.Element(Ds + "X509Data")!.Element(Ds + "X509Certificate")!.Value)
            .ToList();

        // Both public certificates appear, primary first, in the order they were supplied.
        Assert.Equal(new[] { primaryBase64, rolloverBase64 }, advertised);

        // XSD order: within SPSSODescriptor every KeyDescriptor must precede the AssertionConsumerService
        // element. Pin it against document order so a future edit that emits a descriptor after the ACS
        // (invalid metadata) fails here, not only against a real identity provider.
        var childNames = spDescriptor.Elements().Select(e => e.Name).ToList();
        var lastKeyDescriptorIndex = childNames.FindLastIndex(n => n == Md + "KeyDescriptor");
        var acsIndex = childNames.FindIndex(n => n == Md + "AssertionConsumerService");
        Assert.True(lastKeyDescriptorIndex < acsIndex, "Every KeyDescriptor must precede AssertionConsumerService (SAML metadata XSD order).");
    }

    [Fact]
    public void Build_WithRollover_BothAdvertisedCertificatesCarryNoPrivateKey()
    {
        // Neither the primary nor the rollover descriptor may leak a private key: both load public-only.
        using var primary = SamlSigningKeyFactory.CreateCertificate();
        using var rollover = SamlSigningKeyFactory.CreateCertificate();
        var primaryBase64 = Convert.ToBase64String(primary.RawData);
        var rolloverBase64 = Convert.ToBase64String(rollover.RawData);

        var document = XDocument.Parse(SamlSpMetadataBuilder.Build(EntityId, AcsUrl, primaryBase64, rolloverBase64));

        var advertised = document.Root!
            .Element(Md + "SPSSODescriptor")!
            .Elements(Md + "KeyDescriptor")
            .Select(kd => kd.Element(Ds + "KeyInfo")!.Element(Ds + "X509Data")!.Element(Ds + "X509Certificate")!.Value);

        foreach (var certificateBase64 in advertised)
        {
            using var loaded = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificateBase64));
            Assert.False(loaded.HasPrivateKey);
        }
    }

    [Fact]
    public void Build_RolloverWithoutPrimary_EmitsNoKeyDescriptor()
    {
        // A rollover with no primary is nonsensical (signing is off), so no key is advertised at all — the
        // rollover is only ever meaningful alongside a primary.
        using var rollover = SamlSigningKeyFactory.CreateCertificate();
        var rolloverBase64 = Convert.ToBase64String(rollover.RawData);

        var document = XDocument.Parse(
            SamlSpMetadataBuilder.Build(EntityId, AcsUrl, signingCertificateBase64: null, rolloverSigningCertificateBase64: rolloverBase64));
        var spDescriptor = document.Root!.Element(Md + "SPSSODescriptor");

        Assert.Equal("false", (string?)spDescriptor!.Attribute("AuthnRequestsSigned"));
        Assert.Empty(spDescriptor.Elements(Md + "KeyDescriptor"));
    }

    [Fact]
    public void Build_WithoutRollover_EmitsExactlyOneKeyDescriptor_PreservingSingleKeyBehavior()
    {
        // Rollover unset (the default) is byte-for-byte the pre-#491 single-KeyDescriptor output.
        using var primary = SamlSigningKeyFactory.CreateCertificate();
        var primaryBase64 = Convert.ToBase64String(primary.RawData);

        var withDefault = SamlSpMetadataBuilder.Build(EntityId, AcsUrl, primaryBase64);
        var withExplicitNullRollover = SamlSpMetadataBuilder.Build(EntityId, AcsUrl, primaryBase64, rolloverSigningCertificateBase64: null);

        Assert.Equal(withDefault, withExplicitNullRollover);
        var spDescriptor = XDocument.Parse(withDefault).Root!.Element(Md + "SPSSODescriptor");
        Assert.Single(spDescriptor!.Elements(Md + "KeyDescriptor"));
    }

    [Fact]
    public void Build_WithLegacyAcs_AdvertisesBothAssertionConsumerServices_NewDefaultThenLegacy()
    {
        // The SP accepts either ACS spelling on the way back (SamlAcsUrlBuilder.ExpectedAcsUrls), so the
        // metadata lists both: the new spelling is the default at index 0, the legacy spelling follows as a
        // non-default endpoint at index 1 (#569).
        const string legacyAcs = "https://jellyfin.example.com/sso/SAML/p/adfs";

        var document = XDocument.Parse(
            SamlSpMetadataBuilder.Build(EntityId, AcsUrl, signingCertificateBase64: null, legacyAssertionConsumerServiceUrl: legacyAcs));
        var spDescriptor = document.Root!.Element(Md + "SPSSODescriptor");

        var acsElements = spDescriptor!.Elements(Md + "AssertionConsumerService").ToList();
        Assert.Equal(2, acsElements.Count);
        Assert.All(acsElements, acs => Assert.Equal(HttpPostBinding, (string?)acs.Attribute("Binding")));

        var primary = acsElements[0];
        Assert.Equal(AcsUrl, (string?)primary.Attribute("Location"));
        Assert.Equal("0", (string?)primary.Attribute("index"));
        Assert.Equal("true", (string?)primary.Attribute("isDefault"));

        var legacy = acsElements[1];
        Assert.Equal(legacyAcs, (string?)legacy.Attribute("Location"));
        Assert.Equal("1", (string?)legacy.Attribute("index"));
        Assert.Equal("false", (string?)legacy.Attribute("isDefault"));
    }

    [Fact]
    public void Build_WithoutLegacyAcs_EmitsExactlyOneAssertionConsumerService_PreservingSingleAcsBehavior()
    {
        // Legacy unset (the default) is byte-for-byte the pre-#569 single-ACS output.
        var withDefault = SamlSpMetadataBuilder.Build(EntityId, AcsUrl, signingCertificateBase64: null);
        var withExplicitNullLegacy = SamlSpMetadataBuilder.Build(EntityId, AcsUrl, signingCertificateBase64: null, legacyAssertionConsumerServiceUrl: null);

        Assert.Equal(withDefault, withExplicitNullLegacy);
        var acsElements = XDocument.Parse(withDefault).Root!
            .Element(Md + "SPSSODescriptor")!
            .Elements(Md + "AssertionConsumerService")
            .ToList();
        Assert.Single(acsElements);
        Assert.Equal("0", (string?)acsElements[0].Attribute("index"));
        Assert.Equal("true", (string?)acsElements[0].Attribute("isDefault"));
    }

    [Fact]
    public void Build_LegacyAcsEqualToPrimary_EmitsExactlyOneAssertionConsumerService()
    {
        // A legacy URL identical to the primary is redundant — the SP already advertises that exact endpoint —
        // so the second entry is dropped, leaving the single-ACS output unchanged (#569 dedup).
        var withDuplicateLegacy = SamlSpMetadataBuilder.Build(EntityId, AcsUrl, signingCertificateBase64: null, legacyAssertionConsumerServiceUrl: AcsUrl);
        var withoutLegacy = SamlSpMetadataBuilder.Build(EntityId, AcsUrl, signingCertificateBase64: null);

        Assert.Equal(withoutLegacy, withDuplicateLegacy);
        Assert.Single(
            XDocument.Parse(withDuplicateLegacy).Root!
                .Element(Md + "SPSSODescriptor")!
                .Elements(Md + "AssertionConsumerService"));
    }

    [Fact]
    public void Build_WithRolloverAndLegacyAcs_KeepsBothKeyDescriptorsBeforeBothAssertionConsumerServices()
    {
        // The combined worst case for XSD element order: signing-key rollover (#491) emits TWO KeyDescriptors
        // and the legacy ACS (#569) emits TWO AssertionConsumerService entries in the SAME document. The
        // metadata XSD requires every KeyDescriptor to precede every AssertionConsumerService, so pin that the
        // last KeyDescriptor still comes before the first ACS when both features are on at once — a future edit
        // that interleaves them (invalid for strict IdPs like ADFS/Azure AD) fails here, not only in the field.
        using var primary = SamlSigningKeyFactory.CreateCertificate();
        using var rollover = SamlSigningKeyFactory.CreateCertificate();
        const string legacyAcs = "https://jellyfin.example.com/sso/SAML/p/adfs";

        var spDescriptor = XDocument.Parse(
                SamlSpMetadataBuilder.Build(
                    EntityId,
                    AcsUrl,
                    Convert.ToBase64String(primary.RawData),
                    Convert.ToBase64String(rollover.RawData),
                    legacyAcs))
            .Root!.Element(Md + "SPSSODescriptor")!;

        Assert.Equal(2, spDescriptor.Elements(Md + "KeyDescriptor").Count());
        Assert.Equal(2, spDescriptor.Elements(Md + "AssertionConsumerService").Count());

        var childNames = spDescriptor.Elements().Select(e => e.Name).ToList();
        var lastKeyDescriptorIndex = childNames.FindLastIndex(n => n == Md + "KeyDescriptor");
        var firstAcsIndex = childNames.FindIndex(n => n == Md + "AssertionConsumerService");
        Assert.True(lastKeyDescriptorIndex < firstAcsIndex, "Every KeyDescriptor must precede AssertionConsumerService (SAML metadata XSD order).");
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
