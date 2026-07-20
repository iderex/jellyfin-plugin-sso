using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the SAML session-minting leg (<c>SamlAuth</c>) via <see cref="SsoControllerHarness"/>.
/// Since #251 that leg redeems the one-time login-outcome token the ACS callback minted, and since #528 it
/// accepts ONLY that token — the assertion is validated once at the callback (covered by
/// <see cref="SSOControllerSamlPostTests"/> and the validator suites) and never re-parsed here. These tests
/// therefore drive the mint leg through the real token flow (callback renders a token, the token posts to
/// SamlAuth) and pin the fail-closed browser-binding / correlation branches of <c>CorrelateAndBind</c> that
/// are NOT exercised by the happy-path token tests in <see cref="SSOControllerSamlTokenTests"/>: a solicited
/// login whose token is redeemed with the wrong binding cookie, a lost solicited correlation, and an
/// unsolicited response under the solicited-only mode. The top-level disabled-provider guard (which precedes
/// any redeem) is checked directly.
/// </summary>
[Collection("SSOController")]
public class SSOControllerSamlAuthTests
{
    private static readonly Guid UserId = Guid.Parse("88888888-8888-8888-8888-888888888888");
    private const string AuthnRequestId = "_authnreq-415";
    private const string Binding = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788";

    // Extracts the one-time token the callback's auth page carries: WebResponse renders it as
    // `var data = "<hex>";`. Mirrors SSOControllerSamlTokenTests.ExtractToken.
    private static string ExtractToken(ActionResult callbackResult)
    {
        var page = Assert.IsType<ContentResult>(callbackResult);
        var match = Regex.Match(page.Content!, "var data = \"([0-9A-F]{64})\"");
        Assert.True(match.Success, "the login auth page must carry a 64-hex one-time token, not the assertion");
        return match.Groups[1].Value;
    }

    // Builds a harness whose "adfs" provider provisions "alice"; ValidateInResponseTo toggles the
    // solicited-only mode the unsolicited-rejection test needs.
    private static SsoControllerHarness ProvisioningHarness(SamlFixture fixture, bool validateInResponseTo = false)
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
            ValidateInResponseTo = validateInResponseTo,
        });
        var user = TestUsers.Named("alice", UserId);
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(UserId).Returns(user);
        return harness;
    }

    private static void SetSamlBindingCookie(SsoControllerHarness harness, string value) =>
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.SamlCookieName}={value}";

    [Fact]
    public async Task SamlAuth_DisabledProvider_RejectsAsUnknownProvider()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = false });

        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = "irrelevant" });

        // The disabled-provider guard precedes the token redeem, so a disabled provider is a client-caused 400
        // byte-identical to the unknown-provider case, not a 500, so neither can be probed apart (#318).
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("No matching provider found", content.Content);
    }

    [Fact]
    public async Task SamlAuth_SolicitedTokenRedeemedWithWrongBindingCookie_RejectsWithoutProvisioning()
    {
        // #415 on the token path: a solicited login's token is redeemed by a browser presenting a DIFFERENT
        // browser's binding id. The mint leg consumes the outstanding request, finds the binding mismatch, and
        // fails closed — nothing is provisioned.
        var fixture = SamlTestFactory.Create(nameId: "alice", inResponseTo: AuthnRequestId);
        var harness = ProvisioningHarness(fixture);
        SamlLoginService.SeedSamlRequestForTests("adfs", AuthnRequestId, Binding, DateTime.UtcNow.AddMinutes(15));

        var token = ExtractToken(harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse()));
        SetSamlBindingCookie(harness, "a-different-browsers-binding-id");

        var result = Assert.IsType<ContentResult>(
            await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));

        Assert.Equal(400, result.StatusCode);
        Assert.Equal("SAML response validation failed", result.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task SamlAuth_TokenCarriesInResponseToButNoOutstandingRequest_RejectsEvenWithValidateOff()
    {
        // The lost-correlation bypass the binding closes: the redeemed outcome carries an InResponseTo (so it
        // claims to be solicited) but the outstanding entry is gone — expired, evicted, lost to a restart or a
        // non-sticky multi-node hop. With no entry there is no binding to check, so it MUST fail closed even
        // when ValidateInResponseTo is off (the default); otherwise a response replayed past its 15-minute
        // window would defeat the binding.
        var fixture = SamlTestFactory.Create(nameId: "alice", inResponseTo: "_authnreq-expired");
        var harness = ProvisioningHarness(fixture); // ValidateInResponseTo off (default)
        // No SeedSamlRequestForTests: the outstanding entry does not exist.

        var token = ExtractToken(harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse()));

        var result = Assert.IsType<ContentResult>(
            await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));

        Assert.Equal(400, result.StatusCode);
        Assert.Equal("SAML response validation failed", result.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task SamlAuth_UnsolicitedTokenUnderSolicitedOnlyMode_RejectsWithoutProvisioning()
    {
        // With ValidateInResponseTo on and no AuthnRequest issued, the callback still renders a token (it does
        // not gate on InResponseTo), but the redeemed outcome carries no InResponseTo, so the mint leg refuses
        // it under the opt-in solicited-only mode — a client-caused 400 in the uniform SAML body, nothing
        // provisioned.
        var fixture = SamlTestFactory.Create(nameId: "alice"); // no InResponseTo
        var harness = ProvisioningHarness(fixture, validateInResponseTo: true);

        var token = ExtractToken(harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse()));

        var result = Assert.IsType<ContentResult>(
            await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = token }));

        Assert.Equal(400, result.StatusCode);
        Assert.Equal("SAML response validation failed", result.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }
}
