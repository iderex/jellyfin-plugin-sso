// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the OpenID challenge via <see cref="SsoControllerHarness"/>. They cover the
/// PKCE-discovery gate (#141, RFC 9700 §2.1.1) — when a provider is marked <c>RequirePkce</c>, the
/// challenge must fail closed unless the authorization server's discovery document advertises PKCE
/// (S256), so a document without S256 or one that cannot be read is refused with a 400 — and the
/// enabled-provider happy path, where a served discovery document yields a redirect to the authorization
/// endpoint. The discovery document is served in-process through the harness's stub HTTP responder; the
/// harness resets the shared authorize-state store between tests (#289).
/// </summary>
[Collection("SSOController")]
public class SSOControllerOidChallengeTests
{
    [Fact]
    public async Task OidChallenge_DisabledProvider_RejectsAsUnknownProvider()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = false });

        // A disabled provider shares the unknown provider's uniform in-process 400, so the two cannot
        // be told apart (no enumeration oracle) — fail-closed either way (#318).
        var content = Assert.IsType<ContentResult>(await harness.Controller.OidChallenge("kc"));
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("No matching provider found", content.Content);
    }

    [Fact]
    public async Task OidChallenge_RequirePkceButProviderDoesNotAdvertiseS256_Returns400()
    {
        var requested = new List<string>();
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = "https://idp-no-s256.example.com",
                OidClientId = "jf",
                RequirePkce = true,
            },
            // Discovery is served but omits code_challenge_methods_supported, so S256 is not advertised.
            httpResponder: request =>
            {
                requested.Add(request.RequestUri!.AbsoluteUri);
                return Json("{\"issuer\":\"https://idp-no-s256.example.com\"}");
            });

        var result = await harness.Controller.OidChallenge("kc");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
        // The 400 must come from the PKCE gate, which only fires after the discovery document is fetched
        // and found to lack S256 — so the discovery endpoint must actually have been contacted.
        Assert.Contains("https://idp-no-s256.example.com/.well-known/openid-configuration", requested);
    }

    [Fact]
    public async Task OidChallenge_RequirePkceButDiscoveryUnreadable_Returns400()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            OidEndpoint = "https://idp-unreachable.example.com",
            OidClientId = "jf",
            RequirePkce = true,
        });
        // No httpResponder: the discovery fetch fails, so PKCE (S256) support cannot be confirmed.

        var result = await harness.Controller.OidChallenge("kc");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task OidChallenge_EnabledProviderWithDiscovery_RedirectsToAuthorizeEndpoint()
    {
        const string authority = "https://idp-full.example.com";
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
            },
            httpResponder: request =>
            {
                var url = request.RequestUri!.AbsoluteUri;
                if (url == authority + "/.well-known/openid-configuration")
                {
                    return Json(Discovery(authority));
                }

                if (url == authority + "/jwks")
                {
                    return Json("{\"keys\":[]}");
                }

                // A challenge should only fetch discovery and its JWKS; any other URL is unexpected and
                // fails the request so a regression that reaches, e.g., the token endpoint is caught.
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        var result = await harness.Controller.OidChallenge("kc");

        // A served discovery document lets OidcClient build the authorization redirect; the harness's
        // per-test reset of the static state store (#289) keeps the added authorize state from leaking.
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.StartsWith(authority + "/authorize", redirect.Url);
    }

    private static string Discovery(string authority) =>
        $"{{\"issuer\":\"{authority}\","
        + $"\"authorization_endpoint\":\"{authority}/authorize\","
        + $"\"token_endpoint\":\"{authority}/token\","
        + $"\"jwks_uri\":\"{authority}/jwks\","
        + $"\"userinfo_endpoint\":\"{authority}/userinfo\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
        + "\"grant_types_supported\":[\"authorization_code\"],"
        + "\"code_challenge_methods_supported\":[\"S256\"]}";

    [Fact]
    public async Task OidChallenge_ReadsDiscoveryExactlyOnce()
    {
        // #450: the challenge sources the PKCE-S256 (#141) and RFC 9207 response-iss (#210) facts from the
        // SAME discovery response it feeds the login, so it must fetch the discovery document ONCE — not the
        // pre-#450 pair of a best-effort probe plus OidcClient's own internal discovery. JWKS may be fetched
        // separately; only the well-known document is counted.
        const string authority = "https://idp-once.example.com";
        var discoveryFetches = 0;
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
            },
            httpResponder: request =>
            {
                var url = request.RequestUri!.AbsoluteUri;
                if (url == authority + "/.well-known/openid-configuration")
                {
                    discoveryFetches++;
                    return Json(Discovery(authority));
                }

                return url == authority + "/jwks"
                    ? Json("{\"keys\":[]}")
                    : new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        var result = await harness.Controller.OidChallenge("kc");

        Assert.IsType<RedirectResult>(result);
        Assert.Equal(1, discoveryFetches); // one discovery read, not two (the separate probe is gone)
    }

    [Fact]
    public async Task OidChallenge_DiscoveryUnreadable_FailsClosed_EvenWithoutRequirePkce()
    {
        // #450 fail-closed: when the discovery document cannot be read there is no authoritative source for
        // the iss-required / PKCE facts and no metadata to build the authorize request from, so the login is
        // refused — NOT silently proceeded on a tolerant default. This holds even when RequirePkce is not
        // set, matching the pre-#450 net behaviour (PrepareLoginAsync could not build the redirect either).
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            OidEndpoint = "https://idp-down.example.com",
            OidClientId = "jf",
            // RequirePkce deliberately left false.
        });
        // No httpResponder: the discovery fetch fails.

        var result = await harness.Controller.OidChallenge("kc");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task OidChallenge_StartPath_RecordsNewPathAsServerState()
    {
        const string authority = "https://idp-newpath.example.com";
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
            },
            httpResponder: request => request.RequestUri!.AbsoluteUri == authority + "/jwks"
                ? Json("{\"keys\":[]}")
                : Json(Discovery(authority)));
        // A login that arrives on the descriptive `.../start/...` route must record NewPath as
        // server-managed runtime state, so a later linking flow reuses the same redirect-path spelling.
        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";

        await harness.Controller.OidChallenge("kc");

        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["kc"].NewPath));
    }

    [Fact]
    public async Task OidChallenge_NewPathChanges_PersistsThroughTheConfigStore()
    {
        // #412: the derived spelling must be recorded through MutateConfiguration (which persists),
        // not a bare field write on a config object read outside the lock — that write bypassed the
        // store entirely and never reached the persist delegate. Starting the provider on the legacy
        // spelling and hitting the descriptive route forces an actual change, so this proves the write
        // now reaches SerializeToFile instead of being a purely in-memory mutation.
        const string authority = "https://idp-newpath-persist.example.com";
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
                NewPath = false,
            },
            httpResponder: request => request.RequestUri!.AbsoluteUri == authority + "/jwks"
                ? Json("{\"keys\":[]}")
                : Json(Discovery(authority)));
        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";

        await harness.Controller.OidChallenge("kc");

        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["kc"].NewPath));
        harness.Xml.Received(1).SerializeToFile(Arg.Any<object>(), Arg.Any<string>());
    }

    [Fact]
    public async Task OidChallenge_NewPathAlreadyCurrent_SkipsTheRedundantPersist()
    {
        // The common case — every login after the first on a given route — must not pay a config
        // persist on every challenge: the derived spelling already matches what is stored, so the
        // atomic write path (#412) is a locked comparison only, mirroring
        // CanonicalLinkService.ResolveOrCreateAsync's read-first, persist-only-on-change shape.
        const string authority = "https://idp-newpath-noop.example.com";
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
                NewPath = true,
            },
            httpResponder: request => request.RequestUri!.AbsoluteUri == authority + "/jwks"
                ? Json("{\"keys\":[]}")
                : Json(Discovery(authority)));
        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";

        await harness.Controller.OidChallenge("kc");

        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["kc"].NewPath));
        harness.Xml.DidNotReceive().SerializeToFile(Arg.Any<object>(), Arg.Any<string>());
    }

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
