// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests the SLO-3b orchestrator <see cref="SamlLogoutValidator"/>: it composes the
/// <see cref="SamlLogoutRequest"/> signature/time validation with the one-time-use (replay) consume and
/// returns a FIXED reason code per fail-closed branch. The reason codes are what the audit trail records;
/// the endpoint collapses them all to one uniform 400.
/// </summary>
public class SamlLogoutValidatorTests : IDisposable
{
    public SamlLogoutValidatorTests() => SamlLogoutValidator.ResetReplaysForTests();

    public void Dispose() => SamlLogoutValidator.ResetReplaysForTests();

    private static SamlConfig ProviderTrusting(string certificate) => new SamlConfig
    {
        Enabled = true,
        SamlCertificate = certificate,
    };

    [Fact]
    public void ValidRequest_Succeeds_AndExposesSubjectAndSessionIndexes()
    {
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice", sessionIndexes: new[] { "idx-1" });
        var validator = new SamlLogoutValidator();

        var ok = validator.TryValidate(ProviderTrusting(fixture.CertificateBase64), "adfs", fixture.EncodeRequest(), DateTime.UtcNow, out var nameId, out var sessionIndexes, out var requestId, out var reason);

        Assert.True(ok);
        Assert.Equal("alice", nameId);
        Assert.Equal(new[] { "idx-1" }, sessionIndexes);
        // The validated request ID is exposed so the endpoint can echo it as the LogoutResponse InResponseTo.
        Assert.False(string.IsNullOrEmpty(requestId));
        Assert.Equal(string.Empty, reason);
    }

    [Fact]
    public void ReplayedRequestId_IsRejected()
    {
        // T-D2 (replay): the same request ID cannot be consumed twice — the second presentation fails closed.
        var fixture = SamlLogoutTestFactory.Create(requestId: "_fixed-id");
        var validator = new SamlLogoutValidator();
        var config = ProviderTrusting(fixture.CertificateBase64);
        var encoded = fixture.EncodeRequest();

        Assert.True(validator.TryValidate(config, "adfs", encoded, DateTime.UtcNow, out _, out _, out _, out _));

        var replayed = validator.TryValidate(config, "adfs", encoded, DateTime.UtcNow, out _, out _, out _, out var reason);

        Assert.False(replayed);
        Assert.Equal(SamlLogoutValidator.RejectReason.Replay, reason);
    }

    [Fact]
    public void UnsignedRequest_IsRejected_WithInvalidReason()
    {
        var fixture = SamlLogoutTestFactory.Create(sign: false);
        var validator = new SamlLogoutValidator();

        var ok = validator.TryValidate(ProviderTrusting(fixture.CertificateBase64), "adfs", fixture.EncodeRequest(), DateTime.UtcNow, out _, out _, out _, out var reason);

        Assert.False(ok);
        Assert.Equal(SamlLogoutValidator.RejectReason.Invalid, reason);
    }

    [Fact]
    public void MalformedBody_IsRejected_WithMalformedReason()
    {
        var validator = new SamlLogoutValidator();

        var ok = validator.TryValidate(ProviderTrusting(SamlFixture.ForeignCertificateBase64()), "adfs", "not-base64-!!!", DateTime.UtcNow, out _, out _, out _, out var reason);

        Assert.False(ok);
        Assert.Equal(SamlLogoutValidator.RejectReason.Malformed, reason);
    }

    [Fact]
    public void ValidSignatureButNoNameId_IsRejected_WithoutConsumingReplay()
    {
        // A signature-valid request that resolves no subject is rejected as Invalid — and because the reject
        // happens BEFORE the replay consume, the request ID is NOT burned. Prove it: a corrected request that
        // carries the SAME ID (with a NameID this time) is then accepted, not turned away as a replay.
        const string SharedId = "_no-nameid-id";
        var noName = SamlLogoutTestFactory.Create(includeNameId: false, requestId: SharedId);
        var validator = new SamlLogoutValidator();

        var firstOk = validator.TryValidate(ProviderTrusting(noName.CertificateBase64), "adfs", noName.EncodeRequest(), DateTime.UtcNow, out _, out _, out _, out var reason);

        Assert.False(firstOk);
        Assert.Equal(SamlLogoutValidator.RejectReason.Invalid, reason);

        // Re-present the SAME request ID, now with a NameID: it must succeed — the slot was never consumed, so
        // this is not rejected as a Replay (which would prove the NameID guard ran before TryConsume).
        var corrected = SamlLogoutTestFactory.Create(nameId: "alice", requestId: SharedId);
        var secondOk = validator.TryValidate(ProviderTrusting(corrected.CertificateBase64), "adfs", corrected.EncodeRequest(), DateTime.UtcNow, out var nameId, out _, out _, out var secondReason);

        Assert.True(secondOk);
        Assert.NotEqual(SamlLogoutValidator.RejectReason.Replay, secondReason);
        Assert.Equal("alice", nameId);
    }
}
