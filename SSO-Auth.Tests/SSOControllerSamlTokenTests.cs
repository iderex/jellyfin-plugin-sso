using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// End-to-end tests of the SAML one-time login-outcome token (#251): the assertion-consumer callback
/// validates the signed assertion ONCE and renders the intermediate page carrying only an opaque token
/// (never the assertion); posting that token to SAML/Auth redeems the already-verified outcome and mints
/// the session without re-parsing or re-validating the assertion. They pin the token is single-use, an
/// unknown/expired token is refused, the one-time replay guard fires exactly once (at the callback), the
/// browser binding still gates a solicited login on the token path, and the pre-#251 deprecation shape
/// (the full assertion posted to SAML/Auth) still fully validates and logs in during the window.
/// </summary>
[Collection("SSOController")]
public class SSOControllerSamlTokenTests
{
    private static readonly Guid UserId = Guid.Parse("77777777-7777-7777-7777-777777777777");

    // Extracts the one-time token the auth page carries: WebResponse renders it as `var data = "<hex>";`.
    private static string ExtractToken(ActionResult callbackResult)
    {
        var page = Assert.IsType<ContentResult>(callbackResult);
        var match = Regex.Match(page.Content!, "var data = \"([0-9A-F]{64})\"");
        Assert.True(match.Success, "the login auth page must carry a 64-hex one-time token, not the assertion");
        return match.Groups[1].Value;
    }

    private static SsoControllerHarness ProvisioningHarness(SamlFixture fixture, out User user)
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
        });
        var provisioned = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        harness.UserManager.CreateUserAsync("alice").Returns(provisioned);
        harness.UserManager.GetUserById(UserId).Returns(provisioned);
        user = provisioned;
        return harness;
    }

    [Fact]
    public async Task LoginRoundTrip_CallbackRendersToken_TokenMintsSession()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = ProvisioningHarness(fixture, out _);

        // The callback validates the assertion once and hands the page a token, not the base64 assertion.
        var token = ExtractToken(harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse()));

        // Posting the token (never the assertion) mints the session — no re-parse, no second validation.
        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token });

        Assert.IsType<OkObjectResult>(result);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task Token_IsSingleUse_ReplayRejectsWithoutSecondMint()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = ProvisioningHarness(fixture, out _);
        var token = ExtractToken(harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse()));

        Assert.IsType<OkObjectResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));

        // The atomic redeem removed the outcome, so a replay of the token finds nothing and is refused —
        // a client-caused 400 in the uniform SAML body, and no second session is minted.
        var replay = Assert.IsType<ContentResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));
        Assert.Equal(400, replay.StatusCode);
        Assert.Equal("SAML response validation failed", replay.Content);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task UnknownToken_Rejects()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = ProvisioningHarness(fixture, out _);

        // A token that was never issued misses the store and falls through to the deprecation validation,
        // which fails closed: its decoded bytes are not a SAML response, so the XML parse rejects it — a
        // clean fail-closed 400, nothing minted.
        var result = Assert.IsType<ContentResult>(
            await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = SamlOutcomeStore.NewToken() }));
        Assert.Equal(400, result.StatusCode);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task ExpiredToken_Rejects()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = ProvisioningHarness(fixture, out _);

        // Seed an outcome whose lifetime has already elapsed (Created well in the past): the redeem rejects
        // it as out of its window, so it cannot mint even though its token is otherwise well-formed.
        var identity = VerifiedIdentity.FromValidatedSaml("adfs", "alice", SamlAuthorizeStateBuilder.Build(new System.Collections.Generic.List<string>(), new SamlConfig()));
        var token = SamlOutcomeStore.NewToken();
        SamlLoginService.SeedSamlOutcomeForTests(new SamlLoginOutcome(token, "adfs", identity, string.Empty, null, DateTime.UtcNow.AddHours(-1)));

        var result = Assert.IsType<ContentResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));
        Assert.Equal(400, result.StatusCode);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task ReplayGuard_FiresExactlyOnce_AtTheCallback()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = ProvisioningHarness(fixture, out _);
        var assertion = fixture.EncodeResponse();

        // The first callback validates and consumes the assertion's one-time id, minting a token.
        var token = ExtractToken(harness.Controller.SamlCallback("adfs", formSamlResponse: assertion));

        // Re-posting the SAME assertion to the callback is refused by the replay guard (its id was already
        // consumed at the first callback) — the token round-trip did not skip the one-time-use control.
        var replayCallback = Assert.IsType<ContentResult>(harness.Controller.SamlCallback("adfs", formSamlResponse: assertion));
        Assert.Equal(400, replayCallback.StatusCode);

        // The token from the first, valid callback still mints exactly once.
        Assert.IsType<OkObjectResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task DeprecationWindow_FullAssertionPostedToAuth_StillValidatesAndLogsIn()
    {
        // The pre-#251 intermediate page embeds the full assertion and posts it straight to SAML/Auth. For
        // the deprecation window that legacy shape must still FULLY validate and mint, so an admin upgrading
        // mid-login does not break a user's in-flight login. (No prior callback ran, so nothing consumed the
        // assertion's one-time id — the deprecation branch validates and consumes it here.)
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = ProvisioningHarness(fixture, out _);

        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = fixture.EncodeResponse() });

        Assert.IsType<OkObjectResult>(result);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task CallbackRefusedAtOutcomeStoreCap_DoesNotBurnTheAssertion_RetrySucceeds_ReplayStillRejected()
    {
        // #539: in the token flow the ACS callback consumes the assertion's one-time replay id and then stores
        // the outcome. If the store refused AFTER the consume, a cap refusal would burn the assertion for a
        // login that never completed and permanently lock out the legitimate user. Reserving the store slot
        // BEFORE the consume fixes that: a cap refusal leaves the assertion untouched and the login retryable,
        // while a genuine replay is still rejected.
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = ProvisioningHarness(fixture, out _);
        var assertion = fixture.EncodeResponse();

        // Install a cap-1 outcome store (the production 100k ceiling is unreachable in a unit test) and fill
        // its single global slot with an unrelated in-flight outcome, so the next callback's reservation is
        // refused. The filler uses a null (exempt) client key so it occupies the GLOBAL slot.
        var store = new SamlOutcomeStore(1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(1));
        SamlLoginService.SetSamlOutcomeStoreForTests(store);
        var filler = SamlOutcomeStore.NewToken();
        var fillerIdentity = VerifiedIdentity.FromValidatedSaml("adfs", "filler", SamlAuthorizeStateBuilder.Build(new System.Collections.Generic.List<string>(), new SamlConfig()));
        Assert.True(store.TryAdd(new SamlLoginOutcome(filler, "adfs", fillerIdentity, string.Empty, null, DateTime.UtcNow), out _));

        // The callback is refused at the store cap — a fail-closed 500 — and the assertion's one-time replay
        // id is NOT consumed, because the reservation is checked ahead of the consume.
        var refused = Assert.IsType<ContentResult>(harness.Controller.SamlCallback("adfs", formSamlResponse: assertion));
        Assert.Equal(500, refused.StatusCode);

        // Drain the store (redeem the filler), then re-POST the SAME assertion. Because it was never burned,
        // the retry now validates, consumes the id, and renders a real token — the login was not lost.
        Assert.NotNull(store.TryRedeem(filler, "adfs", DateTime.UtcNow));
        var token = ExtractToken(harness.Controller.SamlCallback("adfs", formSamlResponse: assertion));
        Assert.IsType<OkObjectResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));
        await harness.UserManager.Received(1).CreateUserAsync("alice");

        // Replay protection is intact: re-POSTing the same assertion a third time (the store now has room) is
        // refused by the one-time replay guard, since the retry above consumed the id.
        var replay = Assert.IsType<ContentResult>(harness.Controller.SamlCallback("adfs", formSamlResponse: assertion));
        Assert.Equal(400, replay.StatusCode);
    }

    private const string AuthnRequestId = "_authnreq-251";
    private const string Binding = "251251251251251251251251251251251251251251251251251251251251251A";

    [Fact]
    public async Task SolicitedTokenFlow_MatchingBindingCookie_Mints()
    {
        // A solicited login (the assertion carries an InResponseTo for a request this server issued): the
        // browser binding still gates the token path, and it is enforced at SAML/Auth — the same-origin leg
        // where the cookie is sent — not at the cross-site callback. The stored outcome carries the
        // InResponseTo so the mint leg can correlate it without the assertion.
        var fixture = SamlTestFactory.Create(nameId: "alice", inResponseTo: AuthnRequestId);
        var harness = ProvisioningHarness(fixture, out _);
        SamlLoginService.SeedSamlRequestForTests("adfs", AuthnRequestId, Binding, DateTime.UtcNow.AddMinutes(15));

        var token = ExtractToken(harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse()));
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.SamlCookieName}={Binding}";

        Assert.IsType<OkObjectResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task SolicitedTokenFlow_MissingBindingCookie_RejectsWithoutMint()
    {
        // The forced-login shape on the token path: the token is redeemed in a browser that never started
        // the flow, so it carries no binding cookie. Fail closed; nothing is minted.
        var fixture = SamlTestFactory.Create(nameId: "alice", inResponseTo: AuthnRequestId);
        var harness = ProvisioningHarness(fixture, out _);
        SamlLoginService.SeedSamlRequestForTests("adfs", AuthnRequestId, Binding, DateTime.UtcNow.AddMinutes(15));

        var token = ExtractToken(harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse()));
        // No binding cookie set.

        var result = Assert.IsType<ContentResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("SAML response validation failed", result.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }
}
