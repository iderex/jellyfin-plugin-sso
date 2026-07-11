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

    [Fact]
    public void GetNameID_ValidResponse_ReturnsSignedSubject()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice@example.com");
        Assert.Equal("alice@example.com", Load(fixture).GetNameID());
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
}
