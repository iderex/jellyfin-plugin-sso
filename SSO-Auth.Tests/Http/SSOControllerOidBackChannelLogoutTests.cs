// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the anonymous OpenID back-channel logout endpoint (#962), driving a real signed
/// logout_token against discovery + JWKS served in-process by <see cref="OidcTokenFixture"/>. They pin the
/// fail-closed contract: the feature and per-provider opt-in gate reject WITHOUT reading the token; a valid
/// token revokes only the matched user's OpenID sessions for that provider (never cross-provider, never a
/// SAML capture); and every rejection is the uniform 400 with no subject oracle.
/// </summary>
[Collection("SSOController")]
public sealed class SSOControllerOidBackChannelLogoutTests : IDisposable
{
    private const string Authority = "https://idp-bcl.example.test";
    private static readonly Guid UserA = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid UserB = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

    private readonly OidcTokenFixture _fixture = new(Authority, "jf");

    public SSOControllerOidBackChannelLogoutTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    public void Dispose()
    {
        _fixture.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    public async Task ValidLogoutToken_RevokesTheMatchedUser_AndReturns200()
    {
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
        });

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    [Fact]
    public async Task FeatureDisabled_RejectsWithoutReadingTheToken()
    {
        // EnableSingleLogout off: the endpoint must NOT reach the validator (no discovery fetch), just reject.
        var harness = Harness(c => c.OidConfigs["kc"] = Provider(backChannel: true), withResponder: false);

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1"));

        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    [Fact]
    public async Task PerProviderOptInOff_Rejects()
    {
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: false);
            c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
        }, withResponder: false);

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1"));

        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    [Fact]
    public async Task UnknownProvider_Rejects_NoOracle()
    {
        var harness = Harness(c => c.EnableSingleLogout = true, withResponder: false);

        AssertUniform400(await harness.Controller.OidBackChannelLogout("nope", _fixture.LogoutToken("sub-1")));
    }

    [Fact]
    public async Task ForgedToken_Rejects_MintsNoRevoke()
    {
        using var attacker = new OidcTokenFixture(Authority, "jf");
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
        });

        // Signed by a DIFFERENT key than the served JWKS.
        var result = await harness.Controller.OidBackChannelLogout("kc", attacker.LogoutToken("sub-1", "sess-9"));

        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    [Fact]
    public async Task NeverRevokesASamlCaptureWithTheSameSubject()
    {
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            // A SAML capture for the SAME provider name + subject must be untouched by an OpenID logout.
            c.LogoutSessions["saml"] = new LogoutSession { Protocol = "SAML", Provider = "kc", Subject = "sub-1", SessionIndex = "sess-9", UserId = UserB };
        });

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        // No OpenID capture matched -> uniform 400, and the SAML user is never revoked.
        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(UserB, Arg.Any<string>());
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("saml")));
    }

    [Fact]
    public async Task SubOnlyToken_RevokesEveryOpenIdSessionOfThatSubjectForThisProvider()
    {
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            c.LogoutSessions["a1"] = Session("sub-1", "sess-1", UserA);
            c.LogoutSessions["a2"] = Session("sub-1", "sess-2", UserA);
            c.LogoutSessions["other"] = Session("sub-2", "sess-3", UserB);
        });

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1"));

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(UserB, Arg.Any<string>());
    }

    private static void AssertUniform400(ActionResult result)
    {
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Logout token could not be processed", content.Content);
    }

    private OidConfig Provider(bool backChannel) => new OidConfig
    {
        Enabled = true,
        OidEndpoint = Authority,
        OidClientId = "jf",
        EnableBackChannelLogout = backChannel,
    };

    private static LogoutSession Session(string subject, string sessionIndex, Guid userId) => new LogoutSession
    {
        Protocol = "OpenID",
        Provider = "kc",
        Subject = subject,
        SessionIndex = sessionIndex,
        UserId = userId,
        IdToken = "raw.id.token",
    };

    private SsoControllerHarness Harness(Action<PluginConfiguration> configure, bool withResponder = true)
        => new SsoControllerHarness(configure, httpResponder: withResponder ? Responder : null);

    // Serves this fixture's discovery document and JWKS; any other URL 404s so an unexpected call is visible.
    private HttpResponseMessage Responder(HttpRequestMessage request)
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url == _fixture.DiscoveryUrl)
        {
            return Json(_fixture.Discovery());
        }

        if (url == _fixture.JwksUrl)
        {
            return Json(_fixture.Jwks());
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json(string body) => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };
}
