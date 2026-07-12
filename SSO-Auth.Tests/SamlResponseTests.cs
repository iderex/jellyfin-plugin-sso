using System.Collections.Generic;
using System.Xml;
using Jellyfin.Plugin.SSO_Auth;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Trust-boundary tests for <see cref="Response"/> — the SAML signature/validation core.
/// These pin the CURRENT behavior of the upstream implementation so the P2 hardening
/// changes (see docs/ROADMAP.md) are deliberate, reviewed flips rather than surprises.
///
/// Tests named "..._KnownFailOpen" / "..._Characterization" document behavior that is
/// insecure by today's standard and is tracked in docs/SECURITY-FINDINGS.md; they will
/// be inverted by the PR that fixes the corresponding finding.
/// </summary>
public class SamlResponseTests
{
    private static Response Load(SamlFixture fixture, string? certificateBase64 = null)
        => new Response(certificateBase64 ?? fixture.CertificateBase64, fixture.EncodeResponse());

    [Fact]
    public void IsValid_ResponseScopeSignature_ReturnsTrue()
    {
        var fixture = SamlTestFactory.Create(scope: SamlTestFactory.SignatureScope.Response);
        Assert.True(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_AssertionScopeSignature_ReturnsTrue()
    {
        var fixture = SamlTestFactory.Create(scope: SamlTestFactory.SignatureScope.Assertion);
        Assert.True(Load(fixture).IsValid());
    }

    [Fact]
    public void GetRecipient_And_GetInResponseTo_ReadFromSignedAssertion()
    {
        // Recipient and InResponseTo live inside the assertion, so they are covered even when only
        // the assertion (not the whole Response) is signed — the #156 endpoint/solicited binding.
        var fixture = SamlTestFactory.Create(
            scope: SamlTestFactory.SignatureScope.Assertion,
            recipient: "https://jellyfin.example/sso/SAML/post/idp",
            inResponseTo: "_req-42");
        var response = Load(fixture);

        Assert.True(response.IsValid());
        Assert.Equal("https://jellyfin.example/sso/SAML/post/idp", response.GetRecipient());
        Assert.Equal("_req-42", response.GetInResponseTo());
    }

    [Fact]
    public void GetRecipient_And_GetInResponseTo_NullWhenAbsent()
    {
        var response = Load(SamlTestFactory.Create());
        Assert.Null(response.GetRecipient());
        Assert.Null(response.GetInResponseTo());
    }

    [Fact]
    public void GetDestination_ReadFromResponseElement_NullWhenAbsent()
    {
        var withDestination = Load(SamlTestFactory.Create(destination: "https://jellyfin.example/sso/SAML/post/idp"));
        Assert.Equal("https://jellyfin.example/sso/SAML/post/idp", withDestination.GetDestination());

        Assert.Null(Load(SamlTestFactory.Create()).GetDestination());
    }

    [Fact]
    public void Constructor_DocumentWithDoctype_IsRejected()
    {
        // Untrusted SAML input must not carry a DTD: XmlResolver=null blocks only external entities,
        // but an internal DTD still expands entities (a billion-laughs style DoS). DtdProcessing is
        // prohibited, so a DOCTYPE is rejected outright at parse time (fail-closed). A well-formed
        // SAML assertion never has one.
        var withDoctype =
            "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE samlp:Response [ <!ENTITY x \"expanded\"> ]>" +
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
                "<saml:Assertion><saml:Subject><saml:NameID>&x;</saml:NameID></saml:Subject></saml:Assertion>" +
            "</samlp:Response>";
        Assert.Throws<XmlException>(() =>
            new Response(SamlFixture.ForeignCertificateBase64(), SamlFixture.Encode(withDoctype)));
    }

    [Fact]
    public void Constructor_BillionLaughsEntityExpansion_IsRejected()
    {
        // The classic nested-entity amplification: it must be rejected at parse time (DTD prohibited)
        // rather than expanded into a memory blow-up.
        var billionLaughs =
            "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE lolz [" +
            "<!ENTITY lol \"lol\">" +
            "<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">" +
            "<!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">" +
            "]>" +
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
                "<saml:Assertion><saml:Subject><saml:NameID>&lol3;</saml:NameID></saml:Subject></saml:Assertion>" +
            "</samlp:Response>";
        Assert.Throws<XmlException>(() =>
            new Response(SamlFixture.ForeignCertificateBase64(), SamlFixture.Encode(billionLaughs)));
    }

    [Fact]
    public void Constructor_ExternalEntityDoctype_IsRejected()
    {
        // The classic XXE/SSRF shape (an external SYSTEM entity). XmlResolver=null already blocks the
        // fetch, but DtdProcessing.Prohibit rejects the DOCTYPE outright — belt and suspenders.
        var xxe =
            "<?xml version=\"1.0\"?>" +
            "<!DOCTYPE samlp:Response [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>" +
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
                "<saml:Assertion><saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject></saml:Assertion>" +
            "</samlp:Response>";
        Assert.Throws<XmlException>(() =>
            new Response(SamlFixture.ForeignCertificateBase64(), SamlFixture.Encode(xxe)));
    }

    [Fact]
    public void Constructor_DoctypePrependedToSignedResponse_IsRejectedBeforeSignatureCheck()
    {
        // A DOCTYPE smuggled in front of an otherwise-valid, correctly-signed response must be
        // rejected at parse time — DTD rejection pre-empts signature acceptance, so an attacker
        // cannot pair a valid signature with a malicious DTD.
        var fixture = SamlTestFactory.Create();
        var signedXml = fixture.Document.OuterXml;
        var declarationEnd = signedXml.IndexOf("?>", System.StringComparison.Ordinal);
        var withDoctype = declarationEnd >= 0
            ? signedXml.Insert(declarationEnd + 2, "<!DOCTYPE samlp:Response [ <!ENTITY x \"y\"> ]>")
            : "<!DOCTYPE samlp:Response [ <!ENTITY x \"y\"> ]>" + signedXml;

        Assert.Throws<XmlException>(() =>
            new Response(fixture.CertificateBase64, SamlFixture.Encode(withDoctype)));
    }

    [Fact]
    public void IsValid_NoSignature_ReturnsFalse()
    {
        // A well-formed but entirely unsigned response must never validate.
        var unsigned =
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r\" Version=\"2.0\">" +
                "<saml:Assertion ID=\"_a\" Version=\"2.0\">" +
                    "<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject>" +
                "</saml:Assertion>" +
            "</samlp:Response>";
        var response = new Response(SamlFixture.ForeignCertificateBase64(), SamlFixture.Encode(unsigned));
        Assert.False(response.IsValid());
    }

    [Fact]
    public void IsValid_ForeignCertificate_ReturnsFalse()
    {
        var fixture = SamlTestFactory.Create();
        Assert.False(Load(fixture, SamlFixture.ForeignCertificateBase64()).IsValid());
    }

    [Fact]
    public void IsValid_TamperedNameIdAfterSigning_ReturnsFalse()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var nameId = fixture.Document.GetElementsByTagName("NameID", "urn:oasis:names:tc:SAML:2.0:assertion")[0]!;
        nameId.InnerText = "attacker";
        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_ExpiredNotOnOrAfter_ReturnsFalse()
    {
        var fixture = SamlTestFactory.Create(notOnOrAfter: System.DateTime.UtcNow.AddMinutes(-10));
        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_SignatureWrappingSecondAssertion_ReturnsFalse()
    {
        // XSW: keep the validly-signed assertion, but inject an unsigned attacker assertion as the
        // FIRST assertion. Attribute/NameID extraction reads Assertion[1] (the evil one); the
        // signature reference resolves to the second (signed) node. The two must not agree.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var evil = doc.CreateElement("saml", "Assertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        evil.SetAttribute("ID", "_evil");
        evil.SetAttribute("Version", "2.0");
        var subject = doc.CreateElement("saml", "Subject", "urn:oasis:names:tc:SAML:2.0:assertion");
        var nameId = doc.CreateElement("saml", "NameID", "urn:oasis:names:tc:SAML:2.0:assertion");
        nameId.InnerText = "attacker";
        subject.AppendChild(nameId);
        evil.AppendChild(subject);
        doc.DocumentElement!.PrependChild(evil);

        Assert.False(Load(fixture).IsValid());
    }

    // --- Signature/digest algorithm allowlist (A-3: reject SHA-1) ---

    [Fact]
    public void IsValid_Sha1SignedResponse_ReturnsFalse()
    {
        // A response signed with RSA-SHA1 and a SHA-1 digest verifies cryptographically against the
        // certificate, but SHA-1 is collision-weak — it must be rejected fail-closed before that check.
        var fixture = SamlTestFactory.Create(signWithSha1: true);
        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_Sha1SignedAssertionScope_ReturnsFalse()
    {
        var fixture = SamlTestFactory.Create(scope: SamlTestFactory.SignatureScope.Assertion, signWithSha1: true);
        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void GetSignatureAlgorithm_Sha256SignedResponse_ReturnsRsaSha256Uri()
    {
        var fixture = SamlTestFactory.Create();
        Assert.Equal("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", Load(fixture).GetSignatureAlgorithm());
    }

    [Fact]
    public void GetSignatureAlgorithm_Sha1SignedResponse_ReturnsRsaSha1Uri()
    {
        // Diagnostic getter reports the rejected weak algorithm so an operator can identify the cause.
        var fixture = SamlTestFactory.Create(signWithSha1: true);
        Assert.Equal("http://www.w3.org/2000/09/xmldsig#rsa-sha1", Load(fixture).GetSignatureAlgorithm());
    }

    [Fact]
    public void GetSignatureAlgorithm_UnsignedResponse_ReturnsNull()
    {
        var unsigned =
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r\" Version=\"2.0\">" +
                "<saml:Assertion ID=\"_a\" Version=\"2.0\"><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>" +
            "</samlp:Response>";
        var response = new Response(SamlFixture.ForeignCertificateBase64(), SamlFixture.Encode(unsigned));
        Assert.Null(response.GetSignatureAlgorithm());
    }

    [Fact]
    public void GetNameID_ValidResponse_ReturnsSignedSubject()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice@example.com");
        Assert.Equal("alice@example.com", Load(fixture).GetNameID());
    }

    [Fact]
    public void GetNameID_MissingNameId_ReturnsNull()
    {
        // An assertion without a NameID must yield null (the callback rejects it as an invalid
        // login), not throw — previously this was an unhandled NRE turning into a 500 (#95).
        var fixture = SamlTestFactory.Create(includeNameId: false);
        Assert.Null(Load(fixture).GetNameID());
    }

    [Fact]
    public void GetCustomAttribute_ValidResponse_ReturnsRole()
    {
        var fixture = SamlTestFactory.Create(role: "jellyfin-admins");
        Assert.Equal("jellyfin-admins", Load(fixture).GetCustomAttribute("Role"));
    }

    [Fact]
    public void GetCustomAttributes_KnownAttribute_ReturnsValues()
    {
        var fixture = SamlTestFactory.Create(role: "jellyfin-users");
        Assert.Equal(new List<string> { "jellyfin-users" }, Load(fixture).GetCustomAttributes("Role"));
    }

    [Fact]
    public void GetCustomAttribute_UnknownAttribute_ReturnsNull()
    {
        var fixture = SamlTestFactory.Create();
        Assert.Null(Load(fixture).GetCustomAttribute("NonExistent"));
    }

    // --- Time-bound validation (fail-closed; F-2 fixed) ---

    [Fact]
    public void IsValid_MissingAnyTimeBound_ReturnsFalse()
    {
        // F-2 fix: an assertion with no NotOnOrAfter anywhere must be rejected, not accepted
        // forever (the previous DateTime.MaxValue fail-open default).
        var fixture = SamlTestFactory.Create(includeNotOnOrAfter: false);
        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_OnlyConditionsUpperBound_ReturnsTrue()
    {
        // An IdP that carries the upper bound only in Conditions (not SubjectConfirmationData)
        // must still authenticate — we require at least one upper bound, not that specific one.
        var fixture = SamlTestFactory.Create(
            includeNotOnOrAfter: false,
            conditionsNotOnOrAfter: System.DateTime.UtcNow.AddMinutes(5));
        Assert.True(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_ConditionsNotBeforeInFuture_ReturnsFalse()
    {
        var fixture = SamlTestFactory.Create(
            conditionsNotBefore: System.DateTime.UtcNow.AddMinutes(30));
        Assert.False(Load(fixture).IsValid());
    }

    // --- Audience binding (IsValid(expectedAudience), fail-closed) ---

    [Fact]
    public void IsValid_MatchingAudience_ReturnsTrue()
    {
        var fixture = SamlTestFactory.Create(audience: "https://jellyfin.example.com/sso");
        Assert.True(Load(fixture).IsValid("https://jellyfin.example.com/sso"));
    }

    [Fact]
    public void IsValid_WrongAudience_ReturnsFalse()
    {
        var fixture = SamlTestFactory.Create(audience: "https://other-sp.example.com");
        Assert.False(Load(fixture).IsValid("https://jellyfin.example.com/sso"));
    }

    [Fact]
    public void IsValid_MissingAudienceWhenExpected_ReturnsFalse()
    {
        var fixture = SamlTestFactory.Create();
        Assert.False(Load(fixture).IsValid("https://jellyfin.example.com/sso"));
    }

    [Fact]
    public void IsValid_EmptyExpectedAudience_ReturnsFalse()
    {
        // Audience validation requested but nothing to check against -> fail closed.
        var fixture = SamlTestFactory.Create(audience: "https://jellyfin.example.com/sso");
        Assert.False(Load(fixture).IsValid(string.Empty));
    }

    [Fact]
    public void IsValid_MultipleAudiences_MatchesAny()
    {
        var fixture = SamlTestFactory.Create(audiences: new[] { "https://other-sp.example.com", "https://jellyfin.example.com/sso" });
        Assert.True(Load(fixture).IsValid("https://jellyfin.example.com/sso"));
        Assert.False(Load(fixture).IsValid("https://not-listed.example.com"));
    }

    // --- Replay-support getters ---

    [Fact]
    public void GetAssertionId_ReturnsSignedAssertionId()
    {
        var fixture = SamlTestFactory.Create();
        Assert.Equal(fixture.AssertionId, Load(fixture).GetAssertionId());
    }

    [Fact]
    public void GetNotOnOrAfter_ReturnsLatestBound()
    {
        // Fixed whole-second UTC instant so the assertion is exact (the factory formats to whole
        // seconds), rather than a wall-clock value with a tolerance.
        var expiry = new System.DateTime(2026, 7, 11, 12, 5, 0, System.DateTimeKind.Utc);
        var fixture = SamlTestFactory.Create(notOnOrAfter: expiry);
        Assert.Equal(expiry, Load(fixture).GetNotOnOrAfter());
    }
}
