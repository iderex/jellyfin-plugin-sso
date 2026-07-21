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
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the SP-initiated outbound SAML logout endpoint (#727, SLO-3c) via
/// <see cref="SsoControllerHarness"/>. They pin the fail-safe contract: the local Jellyfin logout always runs,
/// a fully-configured captured SAML session redirects to the SLO endpoint with a signed LogoutRequest naming
/// the caller's OWN NameID, and any missing precondition (feature off, no endpoint, unloadable key, no captured
/// session) degrades to a local (host-independent) redirect — never a 500 or an external redirect. Every action
/// is caller-scoped: a caller can only end their own session and can never build a request naming another user.
/// </summary>
[Collection("SSOController")]
public class SSOControllerSamlSpLogoutTests
{
    private static readonly Guid Caller = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static readonly Guid OtherUser = Guid.Parse("66666666-6666-6666-6666-666666666666");
    private const string SloEndpoint = "https://idp.example.com/slo";
    private const string CallerNameId = "caller-subject";

    private static SsoControllerHarness ForCaller(string token, Action<PluginConfiguration> configure)
    {
        var harness = new SsoControllerHarness(configure);
        var user = TestUsers.Named("caller", Caller);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = user, Token = token }));
        return harness;
    }

    // A SAML provider fully configured for SP-initiated SLO: SLO endpoint + a loadable signing key.
    private static SamlConfig FullyConfiguredProvider() => new SamlConfig
    {
        Enabled = true,
        SamlClientId = "jellyfin-sp",
        SamlSloEndpoint = SloEndpoint,
        SignAuthnRequests = true,
        // A plaintext PFX round-trips through Reveal unchanged, so the signing key loads at runtime.
        SamlSigningKeyPfx = SamlSigningKeyFactory.CreatePfxBase64(),
    };

    private static LogoutSession CapturedSaml(Guid userId, string subject, string? sessionIndex) => new LogoutSession
    {
        Protocol = "SAML",
        Provider = "idp",
        Subject = subject,
        SessionIndex = sessionIndex,
        UserId = userId,
    };

    [Fact]
    public async Task SamlSpLogout_FullyConfigured_EndsLocalSession_AndRedirectsToSloWithSignedRequest()
    {
        var harness = ForCaller("caller-token", config =>
        {
            config.EnableSingleLogout = true;
            config.SamlConfigs["idp"] = FullyConfiguredProvider();
            config.LogoutSessions["saml-session-1"] = CapturedSaml(Caller, CallerNameId, "session-index-xyz");
        });

        var result = await harness.Controller.SamlSpLogout("idp");

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.StartsWith(SloEndpoint + "?SAMLRequest=", redirect.Url, StringComparison.Ordinal);
        Assert.Contains("&SigAlg=", redirect.Url, StringComparison.Ordinal);
        Assert.Contains("&Signature=", redirect.Url, StringComparison.Ordinal);

        // Caller-scoped: the LogoutRequest names the CALLER's own NameID and captured SessionIndex.
        var doc = DecodeSamlRequest(redirect.Url);
        var nsmgr = Namespaces(doc);
        Assert.Equal(CallerNameId, doc.SelectSingleNode("/samlp:LogoutRequest/saml:NameID", nsmgr)!.InnerText);
        Assert.Equal("session-index-xyz", doc.SelectSingleNode("/samlp:LogoutRequest/samlp:SessionIndex", nsmgr)!.InnerText);
        Assert.Equal("jellyfin-sp", doc.SelectSingleNode("/samlp:LogoutRequest/saml:Issuer", nsmgr)!.InnerText);

        // The caller's local session was ended and the consumed entry removed.
        await harness.SessionManager.Received(1).Logout("caller-token");
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("saml-session-1")));
    }

    [Fact]
    public async Task SamlSpLogout_FeatureOff_StillLogsOutLocally_AndRedirectsLocally()
    {
        // EnableSingleLogout off: even with an endpoint/key configured, the SLO redirect is gated off.
        var harness = ForCaller("caller-token", config =>
        {
            config.EnableSingleLogout = false;
            config.SamlConfigs["idp"] = FullyConfiguredProvider();
            config.LogoutSessions["saml-session-1"] = CapturedSaml(Caller, CallerNameId, "s-1");
        });

        var result = await harness.Controller.SamlSpLogout("idp");

        Assert.IsType<LocalRedirectResult>(result);
        await harness.SessionManager.Received(1).Logout("caller-token");
    }

    [Fact]
    public async Task SamlSpLogout_NoSloEndpoint_StillLogsOutLocally_AndRedirectsLocally()
    {
        var harness = ForCaller("caller-token", config =>
        {
            config.EnableSingleLogout = true;
            var provider = FullyConfiguredProvider();
            provider.SamlSloEndpoint = string.Empty; // no SLO endpoint configured
            config.SamlConfigs["idp"] = provider;
            config.LogoutSessions["saml-session-1"] = CapturedSaml(Caller, CallerNameId, "s-1");
        });

        var result = await harness.Controller.SamlSpLogout("idp");

        Assert.IsType<LocalRedirectResult>(result);
        await harness.SessionManager.Received(1).Logout("caller-token");
        // The captured session was still consumed (the local logout terminated it).
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("saml-session-1")));
    }

    [Fact]
    public async Task SamlSpLogout_UnloadableSigningKey_StillLogsOutLocally_AndRedirectsLocally()
    {
        var harness = ForCaller("caller-token", config =>
        {
            config.EnableSingleLogout = true;
            var provider = FullyConfiguredProvider();
            provider.SamlSigningKeyPfx = "not-a-real-pfx"; // set but unloadable -> fail-safe to local-only, never unsigned
            config.SamlConfigs["idp"] = provider;
            config.LogoutSessions["saml-session-1"] = CapturedSaml(Caller, CallerNameId, "s-1");
        });

        var result = await harness.Controller.SamlSpLogout("idp");

        Assert.IsType<LocalRedirectResult>(result);
        await harness.SessionManager.Received(1).Logout("caller-token");
    }

    [Fact]
    public async Task SamlSpLogout_NoCapturedSession_StillLogsOutLocally_AndRedirectsLocally()
    {
        var harness = ForCaller("caller-token", config =>
        {
            config.EnableSingleLogout = true;
            config.SamlConfigs["idp"] = FullyConfiguredProvider();
            // No captured session for the caller.
        });

        var result = await harness.Controller.SamlSpLogout("idp");

        Assert.IsType<LocalRedirectResult>(result);
        await harness.SessionManager.Received(1).Logout("caller-token");
    }

    [Fact]
    public async Task SamlSpLogout_OnlyOtherUserHasASession_DoesNotBuildARequestForThem_AndRedirectsLocally()
    {
        // Caller-scoping: a session belonging to ANOTHER user must never be selected, so the caller (who has no
        // session of their own) degrades to a local-only logout rather than logging the other user out.
        var harness = ForCaller("caller-token", config =>
        {
            config.EnableSingleLogout = true;
            config.SamlConfigs["idp"] = FullyConfiguredProvider();
            config.LogoutSessions["other-session"] = CapturedSaml(OtherUser, "other-subject", "other-index");
        });

        var result = await harness.Controller.SamlSpLogout("idp");

        Assert.IsType<LocalRedirectResult>(result);
        await harness.SessionManager.Received(1).Logout("caller-token");
        // The other user's session is untouched — the caller can only end their own.
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("other-session")));
    }

    [Fact]
    public async Task SamlSpLogout_IgnoresOpenIdCaptureForTheSameProvider()
    {
        // A capture for the same provider but a DIFFERENT protocol (OpenID) must not be selected by the SAML
        // logout path — the Protocol filter keeps the two flows apart.
        var harness = ForCaller("caller-token", config =>
        {
            config.EnableSingleLogout = true;
            config.SamlConfigs["idp"] = FullyConfiguredProvider();
            config.LogoutSessions["oid-session"] = new LogoutSession
            {
                Protocol = "OpenID",
                Provider = "idp",
                Subject = "caller-subject",
                IdToken = "raw.id.token",
                UserId = Caller,
            };
        });

        var result = await harness.Controller.SamlSpLogout("idp");

        Assert.IsType<LocalRedirectResult>(result);
        await harness.SessionManager.Received(1).Logout("caller-token");
        // The OpenID capture is left in place — the SAML SP-logout path did not consume it.
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("oid-session")));
    }

    [Fact]
    public async Task SamlSpLogout_NoSessionIndexCaptured_StillRedirectsToSlo_WithoutASessionIndex()
    {
        var harness = ForCaller("caller-token", config =>
        {
            config.EnableSingleLogout = true;
            config.SamlConfigs["idp"] = FullyConfiguredProvider();
            config.LogoutSessions["saml-session-1"] = CapturedSaml(Caller, CallerNameId, sessionIndex: null);
        });

        var result = await harness.Controller.SamlSpLogout("idp");

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.StartsWith(SloEndpoint + "?SAMLRequest=", redirect.Url, StringComparison.Ordinal);

        var doc = DecodeSamlRequest(redirect.Url);
        var nsmgr = Namespaces(doc);
        Assert.Equal(CallerNameId, doc.SelectSingleNode("/samlp:LogoutRequest/saml:NameID", nsmgr)!.InnerText);
        Assert.Null(doc.SelectSingleNode("/samlp:LogoutRequest/samlp:SessionIndex", nsmgr));
    }

    // Extracts and inflates the SAMLRequest query parameter of the redirect URL back into its XML document.
    private static XmlDocument DecodeSamlRequest(string url)
    {
        var query = url[(url.IndexOf('?') + 1)..];
        string? encoded = null;
        foreach (var pair in query.Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq > 0 && pair[..eq] == "SAMLRequest")
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
