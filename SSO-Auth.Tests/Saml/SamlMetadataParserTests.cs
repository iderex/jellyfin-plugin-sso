using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlMetadataParser"/> (#735): it extracts the IdP entity id, the SSO endpoint, and
/// the signing certificate(s) from SAML metadata, reusing the same fail-closed XML hardening the inbound
/// response parser uses. Every malformed / oversized / incomplete document fails closed with a
/// <see cref="SamlMetadataException"/> and no partial result.
/// </summary>
public class SamlMetadataParserTests
{
    private const string Md = "urn:oasis:names:tc:SAML:2.0:metadata";
    private const string Ds = "http://www.w3.org/2000/09/xmldsig#";
    private const string Redirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    private const string Post = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    private const string EntityId = "https://idp.example.com/entity";
    private const string RedirectSso = "https://idp.example.com/sso/redirect";
    private const string PostSso = "https://idp.example.com/sso/post";

    private static string Cert(int keyBits = 2048)
    {
        using var rsa = RSA.Create(keyBits);
        var request = new CertificateRequest("CN=Test IdP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
    }

    private static string KeyDescriptor(string cert, string? use = "signing")
    {
        var useAttr = use is null ? string.Empty : $" use=\"{use}\"";
        return $"<md:KeyDescriptor{useAttr}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
    }

    private static string Sso(string binding, string location) =>
        $"<md:SingleSignOnService Binding=\"{binding}\" Location=\"{location}\" />";

    private static string Metadata(string keyDescriptors, string ssoServices, string entityId = EntityId) =>
        $"<?xml version=\"1.0\"?><md:EntityDescriptor xmlns:md=\"{Md}\" xmlns:ds=\"{Ds}\" entityID=\"{entityId}\">" +
        $"<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">{keyDescriptors}{ssoServices}</md:IDPSSODescriptor>" +
        "</md:EntityDescriptor>";

    [Fact]
    public void Parse_ValidMetadata_ExtractsEntityIdEndpointAndCertificate()
    {
        var cert = Cert();
        var result = SamlMetadataParser.Parse(Metadata(KeyDescriptor(cert), Sso(Redirect, RedirectSso)));

        Assert.Equal(EntityId, result.EntityId);
        Assert.Equal(RedirectSso, result.Endpoint);
        Assert.Equal(cert, result.PrimaryCertificate);
        Assert.Null(result.SecondaryCertificate);
    }

    [Fact]
    public void Parse_PrefersRedirectBinding_OverPost()
    {
        var result = SamlMetadataParser.Parse(Metadata(
            KeyDescriptor(Cert()),
            Sso(Post, PostSso) + Sso(Redirect, RedirectSso)));

        Assert.Equal(RedirectSso, result.Endpoint); // redirect wins even though POST appears first
    }

    [Fact]
    public void Parse_OnlyPostBinding_UsesThePostLocation()
    {
        var result = SamlMetadataParser.Parse(Metadata(KeyDescriptor(Cert()), Sso(Post, PostSso)));

        Assert.Equal(PostSso, result.Endpoint);
    }

    [Fact]
    public void Parse_TwoSigningCertificates_MapsToPrimaryAndSecondary()
    {
        var first = Cert();
        var second = Cert();
        var result = SamlMetadataParser.Parse(Metadata(
            KeyDescriptor(first) + KeyDescriptor(second),
            Sso(Redirect, RedirectSso)));

        Assert.Equal(first, result.PrimaryCertificate);
        Assert.Equal(second, result.SecondaryCertificate);
    }

    [Fact]
    public void Parse_KeyDescriptorWithNoUseAttribute_IsTreatedAsSigning()
    {
        var cert = Cert();
        var result = SamlMetadataParser.Parse(Metadata(KeyDescriptor(cert, use: null), Sso(Redirect, RedirectSso)));

        Assert.Equal(cert, result.PrimaryCertificate);
    }

    [Fact]
    public void Parse_EncryptionOnlyKeyDescriptor_IsIgnored_ThenNoSigningCert_FailsClosed()
    {
        var ex = Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(Metadata(
            KeyDescriptor(Cert(), use: "encryption"),
            Sso(Redirect, RedirectSso))));
        Assert.Contains("signing certificate", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_WhitespaceWrappedCertificate_IsStripped()
    {
        var cert = Cert();
        var wrapped = "\n        " + cert.Substring(0, 40) + "\n        " + cert.Substring(40) + "\n      ";
        var result = SamlMetadataParser.Parse(Metadata(KeyDescriptor(wrapped), Sso(Redirect, RedirectSso)));

        Assert.Equal(cert, result.PrimaryCertificate); // whitespace removed, loads as a valid cert
    }

    [Fact]
    public void Parse_EntitiesDescriptorAggregate_ResolvesTheIdpEntity()
    {
        var cert = Cert();
        var inner = Metadata(KeyDescriptor(cert), Sso(Redirect, RedirectSso)).Replace("<?xml version=\"1.0\"?>", string.Empty);
        var aggregate = $"<?xml version=\"1.0\"?><md:EntitiesDescriptor xmlns:md=\"{Md}\">{inner}</md:EntitiesDescriptor>";

        var result = SamlMetadataParser.Parse(aggregate);

        Assert.Equal(EntityId, result.EntityId);
        Assert.Equal(cert, result.PrimaryCertificate);
    }

    [Fact]
    public void Parse_LeadingByteOrderMark_IsStripped_AndParses()
    {
        // ADFS serves FederationMetadata.xml UTF-8-with-BOM; a surviving U+FEFF before the XML declaration
        // must be stripped, not rejected as malformed.
        var cert = Cert();
        var withBom = ((char)0xFEFF).ToString() + Metadata(KeyDescriptor(cert), Sso(Redirect, RedirectSso));

        var result = SamlMetadataParser.Parse(withBom);

        Assert.Equal(EntityId, result.EntityId);
        Assert.Equal(cert, result.PrimaryCertificate);
    }

    [Fact]
    public void Parse_PreferredBindingWithEmptyLocation_FallsBackToTheNextUsableBinding()
    {
        // A Redirect SingleSignOnService with a blank Location must not short-circuit the fallback — a usable
        // POST endpoint present in the same document is used.
        var result = SamlMetadataParser.Parse(Metadata(
            KeyDescriptor(Cert()),
            Sso(Redirect, string.Empty) + Sso(Post, PostSso)));

        Assert.Equal(PostSso, result.Endpoint);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Parse_EmptyInput_FailsClosed(string? xml)
        => Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(xml));

    [Fact]
    public void Parse_MalformedXml_FailsClosed()
        => Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse("<md:EntityDescriptor>not closed"));

    [Fact]
    public void Parse_DoctypeDtd_IsRejected_NoXxeNoBillionLaughs()
    {
        // A DOCTYPE/DTD must be refused outright (XXE + entity-expansion DoS), like the inbound response parser.
        var withDtd = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY x \"y\">]>" + Metadata(KeyDescriptor(Cert()), Sso(Redirect, RedirectSso)).Replace("<?xml version=\"1.0\"?>", string.Empty);

        Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(withDtd));
    }

    [Fact]
    public void Parse_OversizedDocument_IsRejected()
    {
        // A document past the character bound must be refused before a multi-megabyte DOM is built.
        var filler = new string('a', SamlMetadataParser.MaxCharactersInDocument + 1024);
        var oversized = Metadata(KeyDescriptor(Cert()), Sso(Redirect, RedirectSso), entityId: EntityId).Replace(
            "</md:IDPSSODescriptor>",
            $"<md:Organization><md:OrganizationName xml:lang=\"en\">{filler}</md:OrganizationName></md:Organization></md:IDPSSODescriptor>");

        Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(oversized));
    }

    [Fact]
    public void Parse_MissingIdpDescriptor_FailsClosed()
    {
        var spOnly = $"<?xml version=\"1.0\"?><md:EntityDescriptor xmlns:md=\"{Md}\" entityID=\"{EntityId}\"><md:SPSSODescriptor protocolSupportEnumeration=\"x\" /></md:EntityDescriptor>";
        var ex = Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(spOnly));
        Assert.Contains("IDPSSODescriptor", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_MissingEntityId_FailsClosed()
    {
        var noEntityId = Metadata(KeyDescriptor(Cert()), Sso(Redirect, RedirectSso)).Replace($" entityID=\"{EntityId}\"", string.Empty);
        var ex = Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(noEntityId));
        Assert.Contains("entityID", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_MissingSsoService_FailsClosed()
    {
        var ex = Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(Metadata(KeyDescriptor(Cert()), string.Empty)));
        Assert.Contains("SingleSignOnService", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_MissingSigningCertificate_FailsClosed()
    {
        var ex = Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(Metadata(string.Empty, Sso(Redirect, RedirectSso))));
        Assert.Contains("signing certificate", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_UnloadableCertificate_FailsClosed()
    {
        // Valid base64 ("ABC") that is not an X.509 certificate — rejected like the config-save cert guard.
        var ex = Assert.Throws<SamlMetadataException>(() => SamlMetadataParser.Parse(Metadata(KeyDescriptor("QUJD"), Sso(Redirect, RedirectSso))));
        Assert.Contains("certificate", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
