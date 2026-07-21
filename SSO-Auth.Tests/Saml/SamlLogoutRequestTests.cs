// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests the inbound SAML <c>LogoutRequest</c> parse-and-signature validator (<see cref="SamlLogoutRequest"/>,
/// #727 SLO-3b) against real signed documents from <see cref="SamlLogoutTestFactory"/>. Each fail-closed
/// branch from the SLO-3b threat model has a negative test: unsigned, wrong-key, weak algorithm, signature
/// wrapping, a prohibited DTD, malformed input, and an expired NotOnOrAfter must all fail validation.
/// </summary>
public class SamlLogoutRequestTests
{
    private static SamlLogoutRequest Parse(string certificate, string encodedRequest)
    {
        Assert.True(SamlLogoutRequest.TryParse(certificate, null, encodedRequest, out var request));
        return request;
    }

    [Fact]
    public void ValidSignedRequest_IsValid_AndExposesTheSubjectSessionIndexesAndId()
    {
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice", sessionIndexes: new[] { "idx-1", "idx-2" });

        using var request = Parse(fixture.CertificateBase64, fixture.EncodeRequest());

        Assert.True(request.IsValid());
        Assert.Equal("alice", request.GetNameId());
        Assert.Equal(new[] { "idx-1", "idx-2" }, request.GetSessionIndexes());
        Assert.Equal(fixture.RequestId, request.GetRequestId());
    }

    [Fact]
    public void UnsignedRequest_IsRejected()
    {
        // T-S1 (spoofing): an unsigned LogoutRequest must never validate — THE core defense.
        var fixture = SamlLogoutTestFactory.Create(sign: false);

        using var request = Parse(fixture.CertificateBase64, fixture.EncodeRequest());

        Assert.False(request.IsValid());
    }

    [Fact]
    public void RequestSignedByAnotherCertificate_IsRejected()
    {
        // T-S1: signed by a real key, but the provider trusts a DIFFERENT certificate — the crypto check
        // must reject it (a forged/attacker-signed request).
        var fixture = SamlLogoutTestFactory.Create();

        using var request = Parse(SamlFixture.ForeignCertificateBase64(), fixture.EncodeRequest());

        Assert.False(request.IsValid());
    }

    [Fact]
    public void RequestSignedWithSha1_IsRejected()
    {
        // T-T2 (algorithm downgrade): RSA-SHA1 / SHA-1 digest is off the allowlist even when it verifies.
        var fixture = SamlLogoutTestFactory.Create(signWithSha1: true);

        using var request = Parse(fixture.CertificateBase64, fixture.EncodeRequest());

        Assert.False(request.IsValid());
    }

    [Fact]
    public void WeakSigningKey_IsRejected()
    {
        // A 1024-bit RSA key is below the shared signing-key strength floor (SamlCertificate) — its signature
        // is not accepted even though it verifies.
        var fixture = SamlLogoutTestFactory.Create(signingKeyBits: 1024);

        using var request = Parse(fixture.CertificateBase64, fixture.EncodeRequest());

        Assert.False(request.IsValid());
    }

    [Fact]
    public void SignatureWrappingOverASmuggledSibling_IsRejected()
    {
        // T-T1 (signature wrapping): a cryptographically valid signature whose single reference covers a
        // smuggled sibling — not the LogoutRequest root — must be rejected by the reference-covers-root bind.
        var fixture = SamlLogoutTestFactory.Create(wrapSignature: true);

        using var request = Parse(fixture.CertificateBase64, fixture.EncodeRequest());

        Assert.False(request.IsValid());
    }

    [Fact]
    public void DtdBearingRequest_FailsToParse()
    {
        // T-T3 (XXE / entity bomb): a DOCTYPE is rejected at parse (DtdProcessing.Prohibit), fail-closed.
        var dtd = "<!DOCTYPE foo [<!ENTITY x \"y\">]>" +
            "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r\" Version=\"2.0\">" +
                "<saml:Issuer>https://idp.example.com</saml:Issuer><saml:NameID>alice</saml:NameID>" +
            "</samlp:LogoutRequest>";

        Assert.False(SamlLogoutRequest.TryParse(SamlFixture.ForeignCertificateBase64(), null, SamlLogoutTestFactory.Encode(dtd), out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-base64-!!!")]
    public void MalformedBody_FailsToParse(string? body)
    {
        Assert.False(SamlLogoutRequest.TryParse(SamlFixture.ForeignCertificateBase64(), null, body, out _));
    }

    [Fact]
    public void OversizedBody_FailsToParse()
    {
        var oversized = new string('A', SamlLogoutRequest.MaxEncodedRequestLength + 1);

        Assert.False(SamlLogoutRequest.TryParse(SamlFixture.ForeignCertificateBase64(), null, oversized, out _));
    }

    [Fact]
    public void ExpiredNotOnOrAfter_IsRejected()
    {
        // T-D2 (replay/time): a NotOnOrAfter in the past (beyond the clock skew) is honoured when present —
        // a stale request is rejected even though its signature is valid.
        var fixture = SamlLogoutTestFactory.Create(notOnOrAfter: DateTime.UtcNow.AddHours(-1));

        using var request = Parse(fixture.CertificateBase64, fixture.EncodeRequest());

        Assert.False(request.IsValid());
    }

    [Fact]
    public void FutureNotOnOrAfter_IsAccepted()
    {
        var fixture = SamlLogoutTestFactory.Create(notOnOrAfter: DateTime.UtcNow.AddMinutes(5));

        using var request = Parse(fixture.CertificateBase64, fixture.EncodeRequest());

        Assert.True(request.IsValid());
    }

    [Fact]
    public void ValidSignatureWithoutNameId_IsValidButExposesNoSubject()
    {
        // A signature-valid request with no NameID passes the pure signature check here; the subject-resolution
        // rejection lives in SamlLogoutValidator/the endpoint, not in this parse type.
        var fixture = SamlLogoutTestFactory.Create(includeNameId: false);

        using var request = Parse(fixture.CertificateBase64, fixture.EncodeRequest());

        Assert.True(request.IsValid());
        Assert.True(string.IsNullOrEmpty(request.GetNameId()));
    }

    [Fact]
    public void NoSessionIndex_YieldsAnEmptyList()
    {
        var fixture = SamlLogoutTestFactory.Create(sessionIndexes: null);

        using var request = Parse(fixture.CertificateBase64, fixture.EncodeRequest());

        Assert.Empty(request.GetSessionIndexes());
    }
}
