// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
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
    private const string SloEndpoint = "https://idp.example.com/slo";
    private const string SpEntityId = "jellyfin-sp";
    private const string SuccessStatus = "urn:oasis:names:tc:SAML:2.0:status:Success";

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

    [Fact]
    public async Task SamlLogout_FullyConfigured_RevokesAndRedirectsToSlo_WithSignedSuccessResponse()
    {
        // SLO-3c: with an SLO endpoint AND a signing key configured, a validated request that revokes a session
        // answers the IdP with a SIGNED LogoutResponse redirect (Success, InResponseTo bound to the request).
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice", requestId: "_req-abc");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig
            {
                Enabled = true,
                SamlCertificate = fixture.CertificateBase64, // the IdP cert that validates the inbound request
                SamlClientId = SpEntityId,
                SamlSloEndpoint = SloEndpoint,
                SamlSigningKeyPfx = SamlSigningKeyFactory.CreatePfxBase64(), // OUR SP key that signs the response
            };
            c.LogoutSessions["a"] = Session("alice", UserA, null);
        });

        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest());

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.StartsWith(SloEndpoint + "?SAMLResponse=", redirect.Url, StringComparison.Ordinal);
        Assert.Contains("&SigAlg=", redirect.Url, StringComparison.Ordinal);
        Assert.Contains("&Signature=", redirect.Url, StringComparison.Ordinal);

        // The response binds to the request (InResponseTo) and reports Success, from our SP Issuer.
        var doc = DecodeSamlResponse(redirect.Url);
        var nsmgr = Namespaces(doc);
        Assert.Equal("_req-abc", doc.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal(SpEntityId, doc.SelectSingleNode("/samlp:LogoutResponse/saml:Issuer", nsmgr)!.InnerText);
        Assert.Equal(SuccessStatus, ((XmlElement)doc.SelectSingleNode("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode", nsmgr)!).GetAttribute("Value"));

        // The revocation still happened and the entry was consumed — the signed response is additive.
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    [Fact]
    public async Task SamlLogout_SloEndpointButNoLoadableSigningKey_Returns200Fallback_NeverUnsigned()
    {
        // Fail-safe: an SLO endpoint is set but the signing key does not load. The revocation stands, and the
        // endpoint answers a bare 200 rather than emitting an UNSIGNED response or a 500.
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig
            {
                Enabled = true,
                SamlCertificate = fixture.CertificateBase64,
                SamlClientId = SpEntityId,
                SamlSloEndpoint = SloEndpoint,
                SamlSigningKeyPfx = "not-a-real-pfx", // set but unloadable
            };
            c.LogoutSessions["a"] = Session("alice", UserA, null);
        });

        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest());

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    [Fact]
    public async Task SamlLogout_EchoesInboundRelayState_OnTheSignedResponse()
    {
        // The inbound RelayState is echoed on the signed response so the IdP can correlate its SLO loop.
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig
            {
                Enabled = true,
                SamlCertificate = fixture.CertificateBase64,
                SamlClientId = SpEntityId,
                SamlSloEndpoint = SloEndpoint,
                SamlSigningKeyPfx = SamlSigningKeyFactory.CreatePfxBase64(),
            };
            c.LogoutSessions["a"] = Session("alice", UserA, null);
        });

        const string RelayState = "idp-correlation-99";
        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest(), RelayState);

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("&RelayState=" + Uri.EscapeDataString(RelayState), redirect.Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SamlLogout_OverlongRelayState_IsDropped_NotReflected()
    {
        // A RelayState beyond the 80-byte SAML binding cap is non-conformant and dropped rather than reflected.
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c =>
        {
            c.EnableSingleLogout = true;
            c.SamlConfigs["adfs"] = new SamlConfig
            {
                Enabled = true,
                SamlCertificate = fixture.CertificateBase64,
                SamlClientId = SpEntityId,
                SamlSloEndpoint = SloEndpoint,
                SamlSigningKeyPfx = SamlSigningKeyFactory.CreatePfxBase64(),
            };
            c.LogoutSessions["a"] = Session("alice", UserA, null);
        });

        var overlong = new string('x', 81);
        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest(), overlong);

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.DoesNotContain("&RelayState=", redirect.Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SamlLogout_RelayStateAtExactly80Bytes_IsEchoed()
    {
        // Lower-boundary of the 80-byte cap: exactly 80 bytes is within the limit and MUST be echoed (pins the
        // <= 80 boundary so a <=-to-< mutant is caught).
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = SignedResponseHarness(fixture);

        var relayState = new string('x', 80); // 80 ASCII bytes
        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest(), relayState);

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("&RelayState=" + Uri.EscapeDataString(relayState), redirect.Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SamlLogout_MultibyteRelayStateOver80Bytes_IsDropped()
    {
        // The cap is measured in UTF-8 BYTES, not UTF-16 chars: 41 euro signs are 41 chars but 123 bytes, so
        // they exceed the 80-byte binding limit and are dropped rather than reflected over-cap.
        var fixture = SamlLogoutTestFactory.Create(nameId: "alice");
        var harness = SignedResponseHarness(fixture);

        var multibyte = new string('€', 41); // 41 UTF-16 chars, 123 UTF-8 bytes
        var result = await harness.Controller.SamlLogout("adfs", fixture.EncodeRequest(), multibyte);

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.DoesNotContain("&RelayState=", redirect.Url, StringComparison.Ordinal);
    }

    // A harness fully configured for the signed inbound LogoutResponse: the fixture's IdP cert validates the
    // inbound request, and an SLO endpoint + a loadable SP signing key let the success path sign the response.
    private static SsoControllerHarness SignedResponseHarness(SamlLogoutFixture fixture) => new SsoControllerHarness(c =>
    {
        c.EnableSingleLogout = true;
        c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            SamlClientId = SpEntityId,
            SamlSloEndpoint = SloEndpoint,
            SamlSigningKeyPfx = SamlSigningKeyFactory.CreatePfxBase64(),
        };
        c.LogoutSessions["a"] = Session("alice", UserA, null);
    });

    private static void AssertUniformRejection(ActionResult result)
    {
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal(UniformRejectionBody, content.Content);
    }

    // Extracts and inflates the SAMLResponse query parameter of the redirect URL back into its XML document.
    private static XmlDocument DecodeSamlResponse(string url)
    {
        var query = url[(url.IndexOf('?') + 1)..];
        string? encoded = null;
        foreach (var pair in query.Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq > 0 && pair[..eq] == "SAMLResponse")
            {
                encoded = Uri.UnescapeDataString(pair[(eq + 1)..]);
                break;
            }
        }

        Assert.NotNull(encoded);
        var compressed = Convert.FromBase64String(encoded!);
        using var input = new MemoryStream(compressed);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var reader = new StreamReader(deflate, new UTF8Encoding(false));
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(reader.ReadToEnd());
        return doc;
    }

    private static XmlNamespaceManager Namespaces(XmlDocument doc)
    {
        var nsmgr = new XmlNamespaceManager(doc.NameTable);
        nsmgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
        nsmgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
        return nsmgr;
    }
}
