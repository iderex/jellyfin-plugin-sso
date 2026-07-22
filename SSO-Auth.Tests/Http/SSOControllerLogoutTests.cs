// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the RP-initiated OpenID logout endpoint (#727, SLO-2) via
/// <see cref="SsoControllerHarness"/>. They pin the fail-safe contract: the local Jellyfin logout always
/// runs, a captured session redirects to the issuer-host-bound end_session URL, and the absence of a
/// captured session degrades to a local (host-independent) redirect — never a 500 or an external redirect.
/// </summary>
[Collection("SSOController")]
public class SSOControllerLogoutTests
{
    private static readonly Guid Caller = Guid.Parse("77777777-7777-7777-7777-777777777777");

    private static SsoControllerHarness ForCaller(string token, Action<PluginConfiguration> configure)
    {
        var harness = new SsoControllerHarness(configure);
        var user = TestUsers.Named("caller", Caller);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(System.Threading.Tasks.Task.FromResult(new AuthorizationInfo { User = user, Token = token }));
        return harness;
    }

    [Fact]
    public async Task OidLogout_WithACapturedSession_EndsTheLocalSessionAndRedirectsToTheIssuer()
    {
        var harness = ForCaller("caller-token", config =>
        {
            config.EnableSingleLogout = true;
            config.OidConfigs["kc"] = new OidConfig { Enabled = true, OidClientId = "client-kc" };
            config.LogoutSessions["session-1"] = new LogoutSession
            {
                Protocol = "OpenID",
                Provider = "kc",
                Subject = "sub-1",
                Issuer = "https://idp.example",
                EndSessionEndpoint = "https://idp.example/logout",
                IdToken = "raw.id.token", // plaintext round-trips through Reveal unchanged
                UserId = Caller,
            };
        });

        var result = await harness.Controller.OidLogout("kc");

        // Redirected to the issuer-host-bound end_session URL with the hint + client id.
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.StartsWith("https://idp.example/logout?", redirect.Url, StringComparison.Ordinal);
        Assert.Contains("id_token_hint=raw.id.token", redirect.Url, StringComparison.Ordinal);
        Assert.Contains("client_id=client-kc", redirect.Url, StringComparison.Ordinal);

        // The caller's local session was ended, and the consumed entry removed so the id_token is not retained.
        await harness.SessionManager.Received(1).Logout("caller-token");
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("session-1")));
    }

    [Fact]
    public async Task OidLogout_NoCapturedSession_StillLogsOutLocally_AndRedirectsLocally()
    {
        // Feature off / nothing captured: the endpoint must still end the local session and degrade to a
        // LOCAL redirect (never a 500, never an external host).
        var harness = ForCaller("caller-token", config => config.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = await harness.Controller.OidLogout("kc");

        Assert.IsType<LocalRedirectResult>(result);
        await harness.SessionManager.Received(1).Logout("caller-token");
    }

    [Fact]
    public async Task OidLogout_EndSessionBuildThrows_LocalLogoutStands_AndDegradesToALocalRedirect()
    {
        // The fail-safe catch (#928 U6, previously untested): a captured session whose stored id_token
        // cannot be revealed (an ssoenc envelope with no at-rest key — the harness's plugin data dir is a
        // fresh temp, so no key exists) makes the end-session URL build throw. The contract: the local
        // logout already ran and STANDS, the browser degrades to a LOCAL redirect, never a 500 and never
        // a half-built external redirect.
        var harness = ForCaller("caller-token", config =>
        {
            config.EnableSingleLogout = true;
            config.OidConfigs["kc"] = new OidConfig { Enabled = true, OidClientId = "client-kc" };
            config.LogoutSessions["session-1"] = new LogoutSession
            {
                Protocol = "OpenID",
                Provider = "kc",
                Subject = "sub-1",
                Issuer = "https://idp.example",
                EndSessionEndpoint = "https://idp.example/logout",
                IdToken = "ssoenc:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // envelope, no key -> Reveal throws
                UserId = Caller,
            };
        });

        var result = await harness.Controller.OidLogout("kc");

        Assert.IsType<LocalRedirectResult>(result);
        await harness.SessionManager.Received(1).Logout("caller-token");
    }
}
