using System;
using System.Xml;
using Jellyfin.Plugin.SSO_Auth;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Trust-boundary tests for the inbound identity-provider verification-certificate rotation (#491): a
/// response is accepted when its signature verifies against EITHER the primary <c>SamlCertificate</c> or
/// an optional secondary certificate, under the SAME fail-closed checks (algorithm allowlist, signature
/// scope, XXE/DOCTYPE reject), and an EXPIRED (or not-yet-valid) certificate never verifies. These pin
/// the "either-cert" acceptance so it can never silently widen into "a cert is configured" and so the
/// existing single-signature/XSW/allowlist invariants stay in force for both certificates.
/// </summary>
public class SamlSecondaryCertificateTests
{
    private static SamlResponse Load(SamlFixture fixture, string primaryCertificateBase64, string? secondaryCertificateBase64)
        => new SamlResponse(primaryCertificateBase64, secondaryCertificateBase64, fixture.EncodeResponse());

    [Fact]
    public void SecondaryUnset_PrimaryOnly_MatchVerifies_MismatchRejected()
    {
        // With no secondary configured the trial narrows to the primary: a within-validity primary that
        // matches verifies, and a non-matching primary is rejected. (The primary is additionally subject to
        // the validity-window gate — see ExpiredPrimary_NoSecondary_Rejects.)
        var fixture = SamlTestFactory.Create();

        Assert.True(Load(fixture, fixture.CertificateBase64, null).IsValid());
        Assert.False(Load(fixture, SamlFixture.ForeignCertificateBase64(), null).IsValid());
    }

    [Fact]
    public void VerifiesAgainstSecondary_WhenPrimaryRotatedOut()
    {
        // The overlap window: the identity provider now signs with the key whose public certificate the
        // administrator has staged in the secondary field, while the primary still holds the old (here,
        // unrelated) certificate. The response must authenticate via the secondary.
        var fixture = SamlTestFactory.Create();

        Assert.True(Load(fixture, SamlFixture.ForeignCertificateBase64(), fixture.CertificateBase64).IsValid());
    }

    [Fact]
    public void VerifiesAgainstSecondary_AssertionScopeSignature()
    {
        // The either-cert trial applies whichever element is signed — an assertion-scope signature must
        // also authenticate via the secondary certificate.
        var fixture = SamlTestFactory.Create(scope: SamlTestFactory.SignatureScope.Assertion);

        Assert.True(Load(fixture, SamlFixture.ForeignCertificateBase64(), fixture.CertificateBase64).IsValid());
    }

    [Fact]
    public void RejectsWhenNeitherCertificateVerifies()
    {
        // Fail closed: two configured certificates that both fail to verify the signature must reject the
        // response — "a certificate is configured" is never acceptance.
        var fixture = SamlTestFactory.Create();

        Assert.False(Load(fixture, SamlFixture.ForeignCertificateBase64(), SamlFixture.ForeignCertificateBase64()).IsValid());
    }

    [Fact]
    public void ExpiredPrimary_ValidSecondary_AcceptsViaSecondary()
    {
        // The common cutover: the primary certificate has expired (the identity provider rolled its key
        // away) while the new certificate — within its validity window — is staged in the secondary. The
        // login must still succeed, against the secondary.
        var expiredPrimary = SamlTestFactory.Create(
            certNotBefore: DateTimeOffset.UtcNow.AddDays(-30),
            certNotAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var validResponse = SamlTestFactory.Create();

        Assert.True(Load(validResponse, expiredPrimary.CertificateBase64, validResponse.CertificateBase64).IsValid());
    }

    [Fact]
    public void BothCertificatesExpired_Rejects()
    {
        // Both configured certificates are outside their validity window: even the one that cryptographically
        // matches the signature is expired and must be skipped, so the response is rejected fail-closed.
        var expiredResponse = SamlTestFactory.Create(
            certNotBefore: DateTimeOffset.UtcNow.AddDays(-30),
            certNotAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var otherExpired = SamlTestFactory.Create(
            certNotBefore: DateTimeOffset.UtcNow.AddDays(-30),
            certNotAfter: DateTimeOffset.UtcNow.AddDays(-1));

        Assert.False(Load(expiredResponse, expiredResponse.CertificateBase64, otherExpired.CertificateBase64).IsValid());
    }

    [Fact]
    public void ExpiredPrimary_NoSecondary_Rejects()
    {
        // The certificate-expiry gate applies to the primary too: an expired primary that still matches the
        // signature must NOT authenticate. This is the property that makes the overlap window terminate — an
        // old key is rejected once it expires rather than working forever.
        var expiredResponse = SamlTestFactory.Create(
            certNotBefore: DateTimeOffset.UtcNow.AddDays(-30),
            certNotAfter: DateTimeOffset.UtcNow.AddDays(-1));

        Assert.False(Load(expiredResponse, expiredResponse.CertificateBase64, null).IsValid());
    }

    [Fact]
    public void NotYetValidSecondary_Skipped_Rejects()
    {
        // A certificate whose NotBefore is in the future is not yet trusted: it must be skipped exactly like
        // an expired one, so a response verifying only against a not-yet-valid secondary is rejected.
        var notYetValid = SamlTestFactory.Create(
            certNotBefore: DateTimeOffset.UtcNow.AddDays(1),
            certNotAfter: DateTimeOffset.UtcNow.AddYears(1));

        Assert.False(Load(notYetValid, SamlFixture.ForeignCertificateBase64(), notYetValid.CertificateBase64).IsValid());
    }

    [Fact]
    public void Sha1Signature_RejectedEvenWhenSecondaryMatches()
    {
        // The algorithm allowlist runs per signature, cert-independently, ABOVE the certificate trial: a
        // SHA-1 signature that verifies cryptographically against the secondary must still be rejected. The
        // multi-cert trial does not open an algorithm-downgrade path.
        var fixture = SamlTestFactory.Create(signWithSha1: true);

        Assert.False(Load(fixture, SamlFixture.ForeignCertificateBase64(), fixture.CertificateBase64).IsValid());
    }

    [Fact]
    public void WrappingSecondAssertion_RejectedEvenWithSecondaryConfigured()
    {
        // XSW is blocked by the single-assertion / bound-signature invariants, which run before and
        // independently of the certificate trial: injecting an unsigned first assertion must still reject,
        // whether the signature would verify against the primary or the secondary.
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

        Assert.False(Load(fixture, SamlFixture.ForeignCertificateBase64(), fixture.CertificateBase64).IsValid());
    }

    [Fact]
    public void DoublySignedWithOneCorruptedSignature_RejectedEvenWithSecondaryConfigured()
    {
        // "Validate all, not first-wins" must hold with a secondary configured: a doubly-signed response
        // whose Response-level signature is corrupted is rejected even though the honest Assertion-level
        // signature verifies against the secondary. A decoy cannot slip because the corrupted signature
        // fails against EVERY candidate certificate, and the loop still requires every position-bound
        // signature to validate.
        const string DsNs = "http://www.w3.org/2000/09/xmldsig#";
        var fixture = SamlTestFactory.CreateDoublySigned();
        var doc = fixture.Document;
        foreach (XmlElement signature in doc.GetElementsByTagName("Signature", DsNs))
        {
            if (signature.ParentNode == doc.DocumentElement)
            {
                var signatureValue = (XmlElement)signature.GetElementsByTagName("SignatureValue", DsNs)[0]!;
                var bytes = Convert.FromBase64String(signatureValue.InnerText.Trim());
                bytes[0] ^= 0xFF;
                signatureValue.InnerText = Convert.ToBase64String(bytes);
                break;
            }
        }

        Assert.False(Load(fixture, SamlFixture.ForeignCertificateBase64(), fixture.CertificateBase64).IsValid());
    }

    [Fact]
    public void DoctypeBody_RejectedAtParse_EvenWithSecondaryConfigured()
    {
        // The XXE/DOCTYPE guard is at parse time, before any certificate is consulted, so a configured
        // secondary cannot reintroduce a DTD-processing path.
        var body =
            "<!DOCTYPE samlp:Response [ <!ENTITY x \"y\"> ]>" +
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
            "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:Assertion /></samlp:Response>";

        Assert.Throws<XmlException>(() =>
            new SamlResponse(SamlFixture.ForeignCertificateBase64(), SamlFixture.ForeignCertificateBase64(), SamlFixture.Encode(body)));
    }

    [Fact]
    public void GarbageSecondaryCertificate_FailsClosedThroughLoader()
    {
        // A configured-but-unloadable secondary is rejected fail-closed at the loader (like a garbage
        // primary, #206) rather than surfacing as an unhandled 500. The admin write paths reject it up
        // front; a hand-edited config is caught here.
        var fixture = SamlTestFactory.Create();

        Assert.False(Jellyfin.Plugin.SSO_Auth.Api.SamlResponseLoader.TryParse(
            fixture.CertificateBase64, "QUJD", fixture.EncodeResponse(), out var response));
        Assert.Null(response);
    }
}
