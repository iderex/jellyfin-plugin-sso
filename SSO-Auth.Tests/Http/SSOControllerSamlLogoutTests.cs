// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the inbound IdP-initiated SAML LogoutRequest endpoint (#727, SLO-3b) via
/// <see cref="SsoControllerHarness"/>, using <see cref="SamlLogoutTestFactory"/> to produce a real, signed
/// request so the actual signature-validation path runs. They pin the SLO-3b threat-model mitigations: the
/// feature gate, the uniform-400 rejection, the blast-radius bound, SessionIndex scoping, and the fail-safe
/// revoke loop.
/// </summary>
[Collection("SSOController")]
public class SSOControllerSamlLogoutTests
{
    private static readonly Guid UserA = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid UserB = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

    private const string UniformRejectionBody = "SAML logout request could not be processed";

    private static LogoutSession Session(string subject, Guid userId, string? sessionIndex) => new LogoutSession
    {
        Protocol = "SAML",
        Provider = "adfs",
        Subject = subject,
        SessionIndex = sessionIndex,
        UserId = userId,
    };

    [Fact]
    public async Task SamlLogout_FeatureOff_ReturnsUniform400_WithoutTouchingSessions()
    {
        // The whole surface is opt-in: with EnableSingleLogout off, even a perfectly valid signed request is
        // rejected — and no session is revoked.
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = false;
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, SamlCertificate = fixture.CertificateBase64 };
            c.LogoutSessions["a"] = Session("alice", UserA, null);
        });

        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest());

        AssertUniformRejection(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    [Fact]
    public async Task SamlLogout_UnknownProvider_ReturnsUniform400()
    {
        var fixture = SamlLogoutTestFactory.Create();
        var harness = new SsoControllerHarness(c => c.EnableSingleLogout = true);

        var result = await harness.Controller.SamlLogout("nope", fixture.EncodeRequest());

        AssertUniformRejection(result);
    }

    [Fact]
    public async Task SamlLogout_ValidRequestForSubjectA_RevokesA_AndLeavesSubjectBIntact()
    {
        // Blast-radius bound (T-D1): a valid logout for (adfs, alice) revokes only user A and consumes only
        // A's store entry; user B's session and entry are untouched.
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, SamlCertificate = fixture.CertificateBase64 };
            c.LogoutSessions["a"] = Session("alice", UserA, "sA");
            c.LogoutSessions["b"] = Session("bob", UserB, "sB");
        });

        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest());

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(UserB, Arg.Any<string>());
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("b")));
    }

    [Fact]
    public async Task SamlLogout_SessionIndexScoped_RevokesOnlyTheMatchingEntry()
    {
        // A request naming SessionIndex "idx-1" consumes only the idx-1 entry; the subject's idx-2 session
        // survives in the store (revoke is user-scoped, but entry consumption is index-scoped).
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice", sessionIndexes: new[] { "idx-1" });
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, SamlCertificate = fixture.CertificateBase64 };
            c.LogoutSessions["a1"] = Session("alice", UserA, "idx-1");
            c.LogoutSessions["a2"] = Session("alice", UserA, "idx-2");
        });

        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest());

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a1")));
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a2")));
    }

    [Fact]
    public async Task SamlLogout_NoSessionIndex_RevokesAllOfTheSubjectsSessions()
    {
        // A request with no SessionIndex targets every session of the subject (SAML core §3.7).
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, SamlCertificate = fixture.CertificateBase64 };
            c.LogoutSessions["a1"] = Session("alice", UserA, "idx-1");
            c.LogoutSessions["a2"] = Session("alice", UserA, "idx-2");
        });

        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest());

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a1")));
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a2")));
    }

    [Fact]
    public async Task SamlLogout_OneUserRevokeThrows_StillRevokesTheOther_AndKeepsTheFaultedEntry()
    {
        // Availability fail-safe: one matched user's revoke fault must NOT abort the loop for the rest, and the
        // faulted user's store entry is LEFT in place (retry possible) while the succeeded user's is consumed.
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, SamlCertificate = fixture.CertificateBase64 };
            c.LogoutSessions["a"] = Session("alice", UserA, "sA");
            c.LogoutSessions["b"] = Session("alice", UserB, "sB");
        });
        // User A's revoke faults; user B's succeeds (the substitute's default completed Task).
        harness.SessionManager.RevokeUserTokens(UserA, Arg.Any<string>()).Returns(Task.FromException(new InvalidOperationException("boom")));

        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest());

        // A's fault did not abort the loop — B was still revoked, so at least one user logged out → 200.
        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserB, null);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("b")));
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    [Fact]
    public async Task SamlLogout_TheOnlyMatchedUserRevokeThrows_ReturnsUniform400_AndKeepsTheEntry()
    {
        // Fail-closed on the destructive action: sessions matched but the sole revoke faulted, so NOTHING was
        // revoked and the user stays authenticated — the endpoint must NOT report success (no 200), and the
        // entry is left in the store for a retry.
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, SamlCertificate = fixture.CertificateBase64 };
            c.LogoutSessions["a"] = Session("alice", UserA, null);
        });
        harness.SessionManager.RevokeUserTokens(UserA, Arg.Any<string>()).Returns(Task.FromException(new InvalidOperationException("boom")));

        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest());

        AssertUniformRejection(result);
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    [Fact]
    public async Task SamlLogout_ValidRequestForUnknownSubject_ReturnsUniform400()
    {
        // "Unknown subject" (no captured session) is the uniform 400 — indistinguishable from a bad signature.
        var fixture = SamlLogoutTestFactory.Create(nameId: "ghost");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, SamlCertificate = fixture.CertificateBase64 };
            c.LogoutSessions["a"] = Session("alice", UserA, null);
        });

        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest());

        AssertUniformRejection(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    [Fact]
    public async Task SamlLogout_ReplayedRequest_ReturnsUniform400()
    {
        // The second presentation of the same request ID is a replay — rejected, and it does not revoke again.
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice", requestId: "_replay-id");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, SamlCertificate = fixture.CertificateBase64 };
            c.LogoutSessions["a"] = Session("alice", UserA, null);
        });
        var encoded = fixture.EncodeRequest();

        Assert.IsType<OkResult>(await harness.Controller.SamlLogout("adfs", encoded));

        // Re-seed the (now-consumed) entry so the only reason a second run fails is the replay cache, not a
        // missing session.
        SSOPlugin.Instance.MutateConfiguration(c => c.LogoutSessions["a"] = Session("alice", UserA, null));
        var replay = await harness.Controller.SamlLogout("adfs", encoded);

        AssertUniformRejection(replay);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
    }

    [Fact]
    public async Task SamlLogout_TwoDifferentRejectionCauses_ReturnByteIdenticalResponses()
    {
        // Information-disclosure mitigation: an unsigned request and a wrong-certificate request must be
        // indistinguishable on the wire (same status, same body).
        var unsigned = SamlLogoutTestFactory.Create(nameId: "alice", sign: false);
        var wrongCert = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            // Trust a certificate that signs NEITHER request, so both fail signature validation.
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, SamlCertificate = SamlFixture.ForeignCertificateBase64() };
            c.LogoutSessions["a"] = Session("alice", UserA, null);
        });

        var unsignedResult = Assert.IsType<ContentResult>(await harness.Controller.SamlLogout("adfs", unsigned.EncodeRequest()));
        var wrongCertResult = Assert.IsType<ContentResult>(await harness.Controller.SamlLogout("adfs", wrongCert.EncodeRequest()));

        Assert.Equal(unsignedResult.StatusCode, wrongCertResult.StatusCode);
        Assert.Equal(unsignedResult.Content, wrongCertResult.Content);
        Assert.Equal(UniformRejectionBody, unsignedResult.Content);
        Assert.Equal(400, unsignedResult.StatusCode);
    }

    private static void AssertUniformRejection(ActionResult result)
    {
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal(UniformRejectionBody, content.Content);
    }
}
