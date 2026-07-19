using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// End-to-end OpenID round-trip tests (#192, layer 3) that drive the FULL plugin login flow —
/// <c>OidChallenge</c> → <c>OidCallback</c> → <c>OidAuth</c> — against a self-consistent in-test identity
/// provider, with NO test-seeded state. Unlike <see cref="SSOControllerOidAuthTests"/> (which seeds a
/// Ready state directly) and <see cref="SSOControllerOidPostTests"/> (whose callback tests seed the
/// Pending state via <c>ArrangeCallback</c>), here the state token, the PKCE <c>code_verifier</c>, and the
/// browser-binding cookie are all minted by the real challenge leg and carried through the redeem — so the
/// test proves those three legs agree on the exact values that pass between them, browser aside.
///
/// The fake IdP is the existing <see cref="OidcTokenFixture"/> (discovery document + JWKS + token endpoint
/// returning a real signed id_token), served in-process through <see cref="SsoControllerHarness"/>'s stub
/// HTTP responder — no new provider fake is introduced, since that fixture already IS a complete,
/// self-consistent OIDC provider surface.
///
/// The happy path asserts a valid signed id_token yields a logged-in outcome (an <see cref="OkObjectResult"/>
/// with the account provisioned exactly once). The negative round-trip signs the id_token with a key that
/// does NOT match the JWKS the same IdP advertises, so the real <see cref="OidcIdTokenValidator"/> rejects
/// it on signature — the callback fails closed with a 400 and the state is never promoted, so the redeem
/// mints nothing.
/// </summary>
[Collection("SSOController")]
public class OidcRoundTripTests
{
    private const string Authority = "https://idp-roundtrip.example.com";

    [Fact]
    public async Task ChallengeToCallbackToAuth_ValidSignedIdToken_YieldsLoggedInOutcome()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // A valid id_token signed by the IdP's own key, carrying the sub + preferred_username the login keys
        // the account on (DoNotLoadProfile skips the userinfo fetch, so these claims are the whole identity).
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice");
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, idToken));

        // Provision hooks the completion tail drives for a first-time login of "alice".
        var user = new User("alice", "SSO-Auth", "Default") { Id = Guid.Parse("19999999-1111-1111-1111-111111111111") };
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await DriveChallenge(harness);

        // Callback: OidcClient exchanges the code at the fake token endpoint and the real OidcIdTokenValidator
        // verifies the id_token signature against the fixture's advertised JWKS. Reaching the text/html auth
        // page (rather than a plain-text error) proves the exchange + signature + sub resolution all passed.
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal("text/html", callback.ContentType);

        // Authenticate: the browser-bound state minted by the challenge is redeemed once and the account is
        // provisioned. An OkObjectResult is the logged-in outcome the client completes the session from.
        var authed = await harness.Controller.OidAuth("kc", Redeem(state));
        Assert.IsType<OkObjectResult>(authed);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task ChallengeToCallback_IdTokenSignedByWrongKey_RejectedOnSignature_MintsNothing()
    {
        using var idp = new OidcTokenFixture(Authority, "jf");
        // A SECOND fixture with its own throw-away RSA key. Its id_token carries byte-for-byte valid claims
        // (same issuer, audience, lifetime) but is signed by a key the IdP does not advertise in its JWKS —
        // so only the signature is wrong. This is the real signature check under test, isolated from every
        // other validation (iss/aud/exp all match), exercising OidcIdTokenValidator against a self-consistent
        // fake IdP whose token was minted by a foreign key.
        using var foreignSigner = new OidcTokenFixture(Authority, "jf");
        var forgedToken = foreignSigner.IdToken(subject: "sub-1", username: "alice");
        var harness = BuildHarness(idp, request => ServeIdp(idp, request, forgedToken));

        var (state, binding) = await DriveChallenge(harness);

        // The callback must fail closed: the signature does not verify against the advertised JWKS, so the
        // real validator rejects and CallbackAsync returns the plain-text 400 login error (never the
        // text/html auth page). The body is the fixed generic message — the library's error detail
        // (invalid_signature) is logged server-side, not reflected into the browser page (#708) — so this
        // asserts the generic body and that the detail is absent rather than pinning on the reflected reason.
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal(400, callback.StatusCode);
        Assert.Equal("text/plain", callback.ContentType);
        Assert.Equal("Error logging in.", callback.Content);
        Assert.DoesNotContain("invalid_signature", callback.Content);

        // End-to-end fail-closed: because the callback never promoted the state to a redeemable Ready, the
        // authenticate leg finds no state to redeem and provisions nothing — no login is minted from a token
        // the IdP's own key did not sign.
        var authed = await harness.Controller.OidAuth("kc", Redeem(state));
        var content = Assert.IsType<ContentResult>(authed);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Invalid or expired state", content.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    // Builds a harness with a single enabled provider "kc" pointed at the fixture's authority, served by the
    // supplied responder. DisablePushedAuthorization keeps the challenge to a plain redirect; DoNotLoadProfile
    // makes the id_token claims the whole identity (no userinfo fetch); EnableAuthorization/AllowExistingAccountLink
    // are off to keep the redeem on the first-time-provision path these round-trips assert.
    private static SsoControllerHarness BuildHarness(OidcTokenFixture fixture, Func<HttpRequestMessage, HttpResponseMessage> responder) =>
        new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = fixture.Issuer,
                OidClientId = fixture.ClientId,
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
                DoNotLoadProfile = true,
                EnableAuthorization = false,
                AllowExistingAccountLink = false,
            },
            httpResponder: responder);

    // Serves the fixture's discovery, JWKS, and token endpoints; any other URL 404s so a regression that
    // reaches an unexpected endpoint is caught. The token endpoint returns the supplied id_token.
    private static HttpResponseMessage ServeIdp(OidcTokenFixture fixture, HttpRequestMessage request, string idToken)
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

        return url == fixture.TokenUrl
            ? Json(fixture.TokenEndpointJson(idToken))
            : new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    // Drives a real OidChallenge on the descriptive start route and returns the state token + browser-binding
    // cookie value it minted — the exact pair the callback and redeem legs must present.
    private static async Task<(string State, string Binding)> DriveChallenge(SsoControllerHarness harness)
    {
        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));
        Assert.StartsWith(Authority + "/authorize", challenge.Url);

        var state = QueryValue(challenge.Url, "state");
        Assert.False(string.IsNullOrEmpty(state));
        var binding = BindingCookie(harness.Controller.Response);
        Assert.False(string.IsNullOrEmpty(binding));
        return (state, binding);
    }

    // Re-points the same context at the callback route the IdP redirects back to, carrying the browser-binding
    // cookie the challenge set (#326) so the state's binding gate is satisfied, and sets the callback query.
    private static void RepointToCallback(SsoControllerHarness harness, string state, string binding, string query)
    {
        harness.Controller.HttpContext.Request.Path = "/sso/OID/redirect/kc";
        harness.Controller.HttpContext.Request.QueryString = new QueryString(query);
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={binding}";
    }

    // A fully-populated redeem request for the given state token.
    private static AuthResponse Redeem(string state) => new AuthResponse
    {
        Data = state,
        DeviceID = "device-1",
        DeviceName = "Test Device",
        AppName = "Jellyfin Web",
        AppVersion = "1.0",
    };

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
    private static string BindingCookie(HttpResponse response)
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

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
