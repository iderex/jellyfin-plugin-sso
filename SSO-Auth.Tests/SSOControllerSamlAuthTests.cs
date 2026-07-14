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
}
