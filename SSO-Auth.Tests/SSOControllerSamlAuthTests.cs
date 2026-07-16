using System;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the SAML auth callback (<c>SamlAuth</c>) via <see cref="SsoControllerHarness"/>,
/// using <see cref="SamlTestFactory"/> to produce a real, cryptographically-signed response so the
/// actual signature-validation path runs. They cover the guard branches (disabled provider, invalid
/// signature, role not allowed) and the happy path, where a valid signed assertion provisions the
/// account and mints a session.
/// </summary>
[Collection("SSOController")]
public class SSOControllerSamlAuthTests
{
    private static readonly Guid UserId = Guid.Parse("88888888-8888-8888-8888-888888888888");

    [Fact]
    public async Task SamlAuth_DisabledProvider_RejectsAsUnknownProvider()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = false });

        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = "irrelevant" });

        // A disabled provider is a client-caused 400 byte-identical to the unknown-provider case, not a
        // 500, so neither can be probed apart (#318).
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("No matching provider found", content.Content);
    }

    [Fact]
    public async Task SamlAuth_ReplayedAssertion_RejectsAsInvalidWithoutDisclosingTheReplay()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
        });
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(UserId).Returns(user);
        var payload = fixture.EncodeResponse();

        Assert.IsType<OkObjectResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = payload }));

        // The replay is refused by the one-time-use cache, now as a client-caused 400 in the uniform
        // SAML body (never a 500) that does not disclose the replay cache to the attacker who replayed.
        var replay = Assert.IsType<ContentResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = payload }));
        Assert.Equal(400, replay.StatusCode);
        Assert.Equal("SAML response validation failed", replay.Content);
    }

    [Fact]
    public async Task SamlAuth_UnsolicitedResponse_RejectsInTheUniformBody()
    {
        // With ValidateInResponseTo on and no AuthnRequest issued, the response carries no correlated
        // InResponseTo and is refused — a client-caused 400 in the uniform SAML body, not a 500, and it
        // no longer discloses the InResponseTo correlation to the submitter.
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            ValidateInResponseTo = true,
        });

        var result = Assert.IsType<ContentResult>(await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = fixture.EncodeResponse() }));
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("SAML response validation failed", result.Content);
    }

    [Fact]
    public async Task SamlAuth_SignedByAnotherCertificate_Returns400()
    {
        var fixture = SamlTestFactory.Create();
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            // The provider trusts a DIFFERENT certificate, so the real signature check must reject it.
            SamlCertificate = SamlFixture.ForeignCertificateBase64(),
        });

        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = fixture.EncodeResponse() });

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task SamlAuth_RoleNotAllowed_Returns401()
    {
        var fixture = SamlTestFactory.Create(role: "jellyfin-users");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true, // audience validation is covered separately; exercise the role gate here
            // A non-empty allow-list the assertion's role is not in, so login is refused after the
            // signature validates.
            Roles = new[] { "only-admins" },
        });

        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = fixture.EncodeResponse() });

        Assert.Equal(401, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task SamlAuth_ValidSignedResponse_ProvisionsAccount_ReturnsOk()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true, // audience validation is covered separately; exercise the callback here
            EnableAuthorization = false, // skip permission application; not under test here
            AllowExistingAccountLink = false,
        });

        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(UserId).Returns(user);

        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse
        {
            Data = fixture.EncodeResponse(),
            DeviceID = "device-1",
            DeviceName = "Test Device",
            AppName = "Jellyfin Web",
            AppVersion = "1.0",
        });

        Assert.IsType<OkObjectResult>(result);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    private const string AuthnRequestId = "_authnreq-415";
    private const string Binding = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788";

    // Builds a harness whose "adfs" provider will provision "alice", and seeds an outstanding SAML
    // AuthnRequest for it carrying the given binding id — the state SamlChallenge would have set (#415).
    private static SsoControllerHarness SolicitedHarness(SamlFixture fixture, string bindingId)
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
        });
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(UserId).Returns(user);
        SSOController.SeedSamlRequestForTests("adfs", AuthnRequestId, bindingId, DateTime.UtcNow.AddMinutes(15));
        return harness;
    }

    private static void SetSamlBindingCookie(SsoControllerHarness harness, string value) =>
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.SamlCookieName}={value}";

    [Fact]
    public async Task SamlAuth_SolicitedResponse_MatchingBindingCookie_ProvisionsAccount()
    {
        // #415: a solicited response whose InResponseTo matches an outstanding request completes only
        // when the request carries the binding cookie the challenge set — the initiating browser.
        var fixture = SamlTestFactory.Create(nameId: "alice", inResponseTo: AuthnRequestId);
        var harness = SolicitedHarness(fixture, Binding);
        SetSamlBindingCookie(harness, Binding);

        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = fixture.EncodeResponse() });

        Assert.IsType<OkObjectResult>(result);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task SamlAuth_SolicitedResponse_MissingBindingCookie_RejectsWithoutProvisioning()
    {
        // The forced-login shape: the response is lured into a browser that never started the flow, so
        // it carries no binding cookie. Fail closed with the uniform SAML body; nothing is provisioned.
        var fixture = SamlTestFactory.Create(nameId: "alice", inResponseTo: AuthnRequestId);
        var harness = SolicitedHarness(fixture, Binding);
        // No binding cookie set.

        var result = Assert.IsType<ContentResult>(
            await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = fixture.EncodeResponse() }));

        Assert.Equal(400, result.StatusCode);
        Assert.Equal("SAML response validation failed", result.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task SamlAuth_SolicitedResponse_WrongBindingCookie_RejectsWithoutProvisioning()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice", inResponseTo: AuthnRequestId);
        var harness = SolicitedHarness(fixture, Binding);
        SetSamlBindingCookie(harness, "a-different-browsers-binding-id");

        var result = Assert.IsType<ContentResult>(
            await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = fixture.EncodeResponse() }));

        Assert.Equal(400, result.StatusCode);
        Assert.Equal("SAML response validation failed", result.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task SamlAuth_InResponseToPresentButNoOutstandingRequest_RejectsEvenWithValidateOff()
    {
        // The bypass this fix closes: a response that DOES carry an InResponseTo (so it claims to be
        // solicited) but whose outstanding entry is gone — expired, evicted, lost to a restart or a
        // non-sticky multi-node hop — must NOT be treated as unsolicited and waved through. Without an
        // entry there is no binding to check, so a lost correlation fails closed even when
        // ValidateInResponseTo is off (the default). Otherwise an attacker could defeat the binding by
        // submitting a signature-valid response after its 15-minute window elapsed.
        var fixture = SamlTestFactory.Create(nameId: "alice", inResponseTo: "_authnreq-expired");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
            // ValidateInResponseTo deliberately left off (the default) — the reject must not depend on it.
        });
        // No SeedSamlRequestForTests: the outstanding entry does not exist.

        var result = Assert.IsType<ContentResult>(
            await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = fixture.EncodeResponse() }));

        Assert.Equal(400, result.StatusCode);
        Assert.Equal("SAML response validation failed", result.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task SamlAuth_UnsolicitedResponse_NoBindingRequired_StillProvisions()
    {
        // IdP-initiated / unsolicited: no matching outstanding request, so browser binding imposes no
        // requirement and (with ValidateInResponseTo off, the default) the login proceeds — the change
        // does not break IdP-initiated deployments. No cookie is present, proving binding did not fire.
        var fixture = SamlTestFactory.Create(nameId: "alice"); // no InResponseTo
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            EnableAuthorization = false,
            AllowExistingAccountLink = false,
        });
        var user = new User("alice", "SSO-Auth", "Default") { Id = UserId };
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(UserId).Returns(user);

        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = fixture.EncodeResponse() });

        Assert.IsType<OkObjectResult>(result);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }
}
