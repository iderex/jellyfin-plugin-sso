// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the OpenID redirect callback's token-exchange path (<c>OidPost</c>) via
/// <see cref="SsoControllerHarness"/> and <see cref="OidcTokenFixture"/>, which serves discovery, a JWKS,
/// and a token endpoint returning a real signed id_token, so the actual code exchange and id_token
/// validation run. A valid callback renders the auth page; an authorization-response issuer that does not
/// match the id_token issuer is refused (RFC 9207 mix-up check, #125). The guard branches (unknown
/// provider, missing/invalid/expired state, disabled, rate-limit) are covered in
/// <see cref="SSOControllerEndpointTests"/> / <see cref="SSOControllerAdminTests"/>.
///
/// Two of the tests characterize the callback end-to-end against the OAuth 2.0 Security BCP update
/// (draft-ietf-oauth-security-topics-update, rev -03 dated 2026-07-06) threat classes that apply to
/// this RP (#176):
/// Cross-toolkit OAuth Account Takeover (COAT) — a state minted in one named provider's context cannot
/// complete against another configured provider's callback — and cross-user session fixation — a state
/// token observed by a party in a different browser cannot complete the flow. The store-level mechanisms
/// these rely on are pinned in <see cref="OidcStateStoreTests"/> (provider-scoped peek/redeem, the
/// browser-binding gate, and the one-time atomic claim); the mint-path one-time-consume is pinned in
/// <see cref="SSOControllerOidAuthTests"/>.
/// </summary>
[Collection("SSOController")]
public class SSOControllerOidPostTests
{
    private const string Authority = "https://idp-oidpost.example.com";

    // The browser-binding id (#326) the challenge would have recorded on the state and handed to the
    // browser as a cookie; the callback must present the same value or the state is refused.
    private const string Binding = "oidpost-browser-binding";

    [Fact]
    public async Task OidPost_ValidCallback_RendersTheAuthPage()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1");

        var result = await harness.Controller.OidCallback("kc", "state-1");

        // Reaching the intermediate HTML auth page (text/html) rather than a plain-text error proves the
        // token exchange, id_token signature validation, and sub resolution all succeeded.
        var page = Assert.IsType<ContentResult>(result);
        Assert.Equal("text/html", page.ContentType);
        Assert.False(string.IsNullOrEmpty(page.Content));
    }

    [Fact]
    public async Task OidPost_FullLogin_StampsTheRealIdTokenIssuerOntoTheCanonicalLink()
    {
        // End-to-end empirical proof (#186): a full callback + authenticate over a REAL signed id_token must
        // capture that token's `iss` and stamp it onto the freshly created canonical link. This is what
        // proves the issuer binding is sourced from the validated token (not reasoned about) — the whole
        // chain OidcIdTokenValidator -> claims -> OidcAuthorizeStateBuilder -> VerifiedIdentity ->
        // LoginCompletionService -> CanonicalLinkService runs against the fixture's actual token here.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1");
        var user = TestUsers.Named("alice", Guid.Parse("55555555-5555-5555-5555-555555555555"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        // The callback promotes the state to a redeemable Ready built from the real id_token's claims.
        Assert.Equal("text/html", Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", "state-1")).ContentType);

        // The authenticate leg redeems it and mints, resolving/creating the account and stamping the link.
        var authed = await harness.Controller.OidAuth("kc", new AuthResponse
        {
            Data = "state-1",
            DeviceID = "device-1",
            DeviceName = "Test Device",
            AppName = "Jellyfin Web",
            AppVersion = "1.0",
        });
        Assert.IsType<OkObjectResult>(authed);

        // The link is bound to the token's actual issuer (the fixture's Authority), read from the real
        // validated id_token — not a value hand-fed by the test.
        var issuers = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["kc"].CanonicalLinkIssuers);
        Assert.Equal(Authority, issuers["sub-1"]);
    }

    [Fact]
    public async Task OidPost_MissingBindingCookie_RejectsAsInvalidState()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // #326: the state was started in another browser (no matching binding cookie is presented), so the
        // callback is refused before any token exchange — the forced-login / session-fixation defense. The
        // body is the uniform invalid-state message, so a wrong-browser hit is indistinguishable from an
        // expiry.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", bindingCookie: null);

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal("Invalid or expired state", Assert.IsType<BadRequestObjectResult>(result).Value);
    }

    [Fact]
    public async Task OidPost_StateMintedForAnotherProvider_RejectedOnThisProvidersCallback()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // COAT (OAuth 2.0 Security BCP update, draft-ietf-oauth-security-topics-update, #176): this
        // plugin is a multi-provider OAuth client (OidConfigs is a dict of named providers), so a response minted in
        // one provider's context must not complete against another's callback. The state is keyed by its
        // token, so the lookup FINDS it under "kc2" — but PeekCurrent rejects it because the route
        // provider does not match the provider recorded on the state, before any token exchange. Both
        // providers are enabled, so this isolates the provider-context binding from the unknown/disabled
        // guard.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", secondProvider: "kc2");

        var crossContext = await harness.Controller.OidCallback("kc2", "state-1");
        Assert.Equal("Invalid or expired state", Assert.IsType<BadRequestObjectResult>(crossContext).Value);

        // Positive control: PeekCurrent does not consume, so the same state still completes on the
        // provider it WAS minted for — proving the rejection above is the provider-context binding, not an
        // unrelated failure of the shared fixture.
        var sameContext = await harness.Controller.OidCallback("kc", "state-1");
        Assert.Equal("text/html", Assert.IsType<ContentResult>(sameContext).ContentType);
    }

    [Fact]
    public async Task OidPost_StateTokenPresentedFromADifferentBrowser_RejectedAsInvalidState()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // Cross-user session fixation (same BCP update, #176): an attacker who observes/fixates the state
        // token still cannot complete the flow from their own browser. The callback requires the
        // browser-binding cookie the challenge recorded (#326); the attacker's browser carries a DIFFERENT
        // value, not the victim's. A present-but-mismatched cookie (not merely an absent one, covered by
        // OidPost_MissingBindingCookie) is refused, proving the binding check requires equality, not mere
        // presence. Once the victim completes, the one-time atomic claim prevents replay/handoff (pinned
        // end-to-end by OidAuth_ValidState_ProvisionsAccountReturnsOk_AndIsSingleUse).
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", bindingCookie: "attacker-other-browser-binding");

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal("Invalid or expired state", Assert.IsType<BadRequestObjectResult>(result).Value);
    }

    [Fact]
    public async Task OidPost_ResponseIssuerMismatch_Returns400()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // RFC 9207 (#125, hardened #210): the authorization-response `iss` names a different issuer than
        // the authorization server's discovery issuer, which is an authorization-server mix-up and must be
        // rejected even though the token itself is valid.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1&iss=https://attacker.example.com");

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task OidPost_TemplatedIssuerUnderDoNotValidateIssuerName_ResponseIssMatchesIdToken_RendersTheAuthPage()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // Availability regression guard (#210 review): with DoNotValidateIssuerName the id_token issuer
        // legitimately differs from the discovery issuer (templated / multi-tenant). The RFC 9207 response
        // `iss` equals the concrete id_token issuer, NOT the templated discovery issuer — comparing to the
        // discovery issuer alone would lock this supported config out, so the id_token issuer is an
        // accepted anchor and the login must proceed.
        const string concreteIssuer = Authority + "/tenant-42";
        var harness = ArrangeCallback(
            fixture,
            query: $"?code=test-code&state=state-1&iss={concreteIssuer}",
            idToken: fixture.IdToken(subject: "sub-1", username: "alice", issuer: concreteIssuer),
            doNotValidateIssuerName: true);

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal("text/html", Assert.IsType<ContentResult>(result).ContentType);
    }

    [Fact]
    public async Task OidPost_ResponseIssuerRequiredButAbsent_Returns400()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // RFC 9207 §2.4 (#210): the challenge saw the AS advertise the response-iss parameter, so a
        // callback that omits `iss` is a downgrade and must be rejected — even though the id_token is valid.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", responseIssuerRequired: true);

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task OidPost_ResponseIssuerRequiredAndPresentMatchingDiscovery_RendersTheAuthPage()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // The complement of the downgrade case: when the AS advertised the parameter AND the response
        // carries an `iss` equal to the discovery issuer, the login proceeds. Proves the requirement is
        // satisfied by a correct value, not merely by the flag being set.
        var harness = ArrangeCallback(fixture, query: $"?code=test-code&state=state-1&iss={Authority}", responseIssuerRequired: true);

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal("text/html", Assert.IsType<ContentResult>(result).ContentType);
    }

    [Fact]
    public async Task OidPost_ResponseIssuerNotAdvertisedAndAbsent_RendersTheAuthPage()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // No lockout of older IdPs (#210): a provider whose discovery did not advertise the parameter
        // (ResponseIssuerRequired defaults false) and that omits `iss` must still log in — the tolerant
        // path RFC 9207 §2.4 preserves.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1");

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal("text/html", Assert.IsType<ContentResult>(result).ContentType);
    }

    [Fact]
    public async Task OidPost_TokenExchangeFails_Returns400()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // The authorization-code exchange fails at the token endpoint, so ProcessResponseAsync errors and
        // the callback is refused rather than minting a login.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", tokenEndpointFails: true);

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task OidPost_IdpErrorRedirect_DoesNotReflectAttackerText_ReturnsGenericMessage()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // #708: the authorization server returns an error redirect, whose error / error_description are
        // parsed from the callback query and are therefore attacker-controllable via a crafted callback URL.
        // The callback must NOT echo that text into the browser-navigated page (a content-spoofing primitive
        // that, on the on-brand error page, would display attacker-chosen text). The body is the fixed
        // generic message; neither the error code nor the attacker-planted description marker appears.
        const string attackerMarker = "PHISHED-CONTENT-MARKER-708";
        var harness = ArrangeCallback(fixture, query: $"?error=access_denied&error_description={attackerMarker}&state=state-1");

        var result = await harness.Controller.OidCallback("kc", "state-1");

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("text/plain", content.ContentType);
        Assert.Equal("Error logging in.", content.Content);
        Assert.DoesNotContain(attackerMarker, content.Content, StringComparison.Ordinal);
        Assert.DoesNotContain("access_denied", content.Content, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OidPost_IdTokenWithoutSub_Returns401()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // Fail closed (#155): a validated id_token carrying no `sub` claim resolves no stable subject to
        // key the account link on, so the login is refused.
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", idToken: fixture.IdToken(subject: null, username: "alice"));

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal(401, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task OidPost_RoleDeniedWithDeprovisionOn_DisablesTheLinkedNonAdmin()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // #831 end-to-end: with an allow-list the id_token cannot satisfy (no matching role claim), the login
        // is denied — and with the opt-in on, the account already linked under this subject is disabled so a
        // user whose roles were revoked at the identity provider cannot keep logging in. The subject key is
        // resolved on the denied path (it is derived independent of validity), so the linked account is found.
        var linked = Guid.Parse("77777777-7777-7777-7777-777777777777");
        var user = TestUsers.Named("alice", linked);
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", tuneProvider: p =>
        {
            p.Roles = new[] { "only-admins" };
            p.DisableAccountOnRoleDenied = true;
            p.CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = linked };
        });
        harness.UserManager.GetUserById(linked).Returns(user);

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal(401, Assert.IsType<ContentResult>(result).StatusCode); // still a clean denial
        Assert.True(user.HasPermission(PermissionKind.IsDisabled)); // the revoked account is deprovisioned
        await harness.UserManager.Received(1).UpdateUserAsync(user);
    }

    [Fact]
    public async Task OidPost_RoleDeniedWithDeprovisionOff_LeavesTheLinkedAccountEnabled()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // The default (opt-in off): the same denied login must NOT disable the linked account — deprovisioning
        // is strictly opt-in, so an existing deployment sees no behavior change and a transient IdP role glitch
        // cannot silently lock users out.
        var linked = Guid.Parse("77777777-7777-7777-7777-777777777777");
        var user = TestUsers.Named("alice", linked);
        var harness = ArrangeCallback(fixture, query: "?code=test-code&state=state-1", tuneProvider: p =>
        {
            p.Roles = new[] { "only-admins" };
            p.CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = linked };
        });
        harness.UserManager.GetUserById(linked).Returns(user);

        var result = await harness.Controller.OidCallback("kc", "state-1");

        Assert.Equal(401, Assert.IsType<ContentResult>(result).StatusCode);
        Assert.False(user.HasPermission(PermissionKind.IsDisabled)); // untouched by default
        await harness.UserManager.DidNotReceive().UpdateUserAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task OidChallengeToCallback_ResponseIssuerAdvertisedThenAbsent_Returns400()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // End-to-end (#210): a real challenge whose discovery advertises the RFC 9207 response-iss
        // parameter must capture the requirement onto the authorize state, so the callback that omits
        // `iss` is rejected — pinning the challenge-side capture the seeded callback tests above assume.
        var (harness, state) = await DriveAdvertisedChallenge(fixture);
        harness.Controller.HttpContext.Request.QueryString = new QueryString($"?code=test-code&state={state}");

        var result = await harness.Controller.OidCallback("kc", state);

        // Pin the 400 to the RFC 9207 reject specifically, not the shared token-exchange-error 400: assert
        // the SsoResponseInvalid body so a 400 from a different source cannot satisfy this test.
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("SSO response validation failed", content.Content);
    }

    [Fact]
    public async Task OidChallengeToCallback_ResponseIssuerAdvertisedThenPresent_RendersTheAuthPage()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // The positive end-to-end: with the same advertised challenge, a callback carrying `iss` equal to
        // the discovery issuer satisfies the captured requirement and the login proceeds.
        var (harness, state) = await DriveAdvertisedChallenge(fixture);
        harness.Controller.HttpContext.Request.QueryString = new QueryString($"?code=test-code&state={state}&iss={Authority}");

        var result = await harness.Controller.OidCallback("kc", state);

        Assert.Equal("text/html", Assert.IsType<ContentResult>(result).ContentType);
    }

    // Drives a real OidChallenge whose served discovery advertises the RFC 9207 response-iss parameter, so
    // the challenge captures the requirement onto its authorize state; returns the harness (its context
    // re-pointed at the callback route, browser-binding cookie attached) plus the state token the callback
    // must present. The token endpoint returns a valid signed id_token, leaving the response-iss
    // requirement as the only thing left to decide at the callback.
    private static async Task<(SsoControllerHarness Harness, string State)> DriveAdvertisedChallenge(OidcTokenFixture fixture)
    {
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice");
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = Authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
                DoNotLoadProfile = true,
            },
            httpResponder: request =>
            {
                var url = request.RequestUri!.AbsoluteUri;
                if (url == fixture.DiscoveryUrl)
                {
                    return Json(fixture.Discovery(advertiseResponseIssuer: true));
                }

                if (url == fixture.JwksUrl)
                {
                    return Json(fixture.Jwks());
                }

                if (url == fixture.TokenUrl)
                {
                    return Json(fixture.TokenEndpointJson(idToken));
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));

        var state = QueryValue(challenge.Url, "state");
        Assert.False(string.IsNullOrEmpty(state));
        var binding = BindingCookie(harness.Controller.Response);
        Assert.False(string.IsNullOrEmpty(binding));

        // Re-point the same context at the callback route the IdP returns to, carrying the browser-binding
        // cookie the challenge set (#326) so the state's binding gate is satisfied.
        harness.Controller.HttpContext.Request.Path = "/sso/OID/redirect/kc";
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={binding}";
        return (harness, state);
    }

    // Reads a single query-parameter value out of the challenge's authorization redirect URL.
    private static string QueryValue(string url, string key)
    {
        foreach (var pair in new Uri(url).Query.TrimStart('?').Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2 && kv[0] == key)
            {
                return Uri.UnescapeDataString(kv[1]);
            }
        }

        return string.Empty;
    }

    // Extracts the browser-binding cookie value the challenge wrote to the response's Set-Cookie header.
    private static string BindingCookie(Microsoft.AspNetCore.Http.HttpResponse response)
    {
        var prefix = AuthorizeStateBinding.CookieName + "=";
        foreach (var header in response.Headers.SetCookie)
        {
            if (header is not null && header.StartsWith(prefix, StringComparison.Ordinal))
            {
                var value = header.Substring(prefix.Length);
                var end = value.IndexOf(';');
                return end >= 0 ? value.Substring(0, end) : value;
            }
        }

        return string.Empty;
    }

    // Builds a harness whose HTTP responder serves the fixture's discovery/JWKS/token endpoints, seeds the
    // matching authorize state, and sets the callback request path and query. The token endpoint returns
    // <paramref name="idToken"/> (a valid signed token by default), or a 400 when
    // <paramref name="tokenEndpointFails"/> is set.
    private static SsoControllerHarness ArrangeCallback(
        OidcTokenFixture fixture,
        string query,
        string? idToken = null,
        bool tokenEndpointFails = false,
        string? bindingCookie = Binding,
        string? secondProvider = null,
        bool responseIssuerRequired = false,
        bool doNotValidateIssuerName = false,
        Action<OidConfig>? tuneProvider = null)
    {
        idToken ??= fixture.IdToken(subject: "sub-1", username: "alice");

        OidConfig NewProvider() => new()
        {
            Enabled = true,
            OidEndpoint = Authority,
            OidClientId = "jf",
            OidScopes = Array.Empty<string>(),
            DisablePushedAuthorization = true,
            DoNotLoadProfile = true, // the id_token carries sub + preferred_username; skip the userinfo fetch
            DoNotValidateIssuerName = doNotValidateIssuerName,
        };

        var harness = new SsoControllerHarness(
            c =>
            {
                var primary = NewProvider();
                tuneProvider?.Invoke(primary); // e.g. an allow-list + a pre-existing canonical link (#831)
                c.OidConfigs["kc"] = primary;

                // A second enabled provider so a COAT test can hit its callback with a state minted for
                // "kc" and isolate the provider-context binding from the unknown/disabled-provider guard.
                if (secondProvider is not null)
                {
                    c.OidConfigs[secondProvider] = NewProvider();
                }
            },
            httpResponder: request =>
            {
                var url = request.RequestUri!.AbsoluteUri;
                if (url == fixture.DiscoveryUrl)
                {
                    return Json(fixture.Discovery());
                }

                if (url == fixture.JwksUrl)
                {
                    return Json(fixture.Jwks());
                }

                if (url == fixture.TokenUrl)
                {
                    return tokenEndpointFails
                        ? new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("{\"error\":\"invalid_grant\"}", Encoding.UTF8, "application/json") }
                        : Json(fixture.TokenEndpointJson(idToken));
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        harness.Controller.HttpContext.Request.Path = "/sso/OID/redirect/kc";
        harness.Controller.HttpContext.Request.QueryString = new QueryString(query);

        // The browser-binding cookie the challenge leg set (#326). Populating the Cookie header is how a
        // DefaultHttpContext exposes Request.Cookies; a null bindingCookie models a callback arriving in a
        // different browser (no cookie), which the binding gate must refuse.
        if (bindingCookie is not null)
        {
            harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={bindingCookie}";
        }

        // The authorize state the redirect leg would have created. The code flow is protected by the PKCE
        // code_verifier here; OidcClient 7.x carries no nonce on the AuthorizeState. BindingId is the id the
        // challenge recorded and the cookie above presents.
        var authState = new AuthorizeState
        {
            State = "state-1",
            CodeVerifier = "test-code-verifier",
            RedirectUri = "https://jf.example.com/sso/OID/redirect/kc",
        };
        // ResponseIssuerRequired models a challenge whose discovery advertised the RFC 9207 response-iss
        // parameter (#210), so the callback must require iss; false is the tolerant default (the challenge
        // capture path itself is pinned end-to-end by OidChallengeToCallback_* below). Seeded as a Pending:
        // the callback derives the login and promotes it to a Ready (#341).
        OidcLoginService.SeedOidStateForTests("state-1", new AuthorizeSession.Pending(authState, "kc", isLinking: false, DateTime.UtcNow, Binding, clientKey: null, providerInformation: null!, responseIssuerRequired: responseIssuerRequired));

        return harness;
    }

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
