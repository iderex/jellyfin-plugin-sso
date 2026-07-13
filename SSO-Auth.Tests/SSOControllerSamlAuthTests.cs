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
    public async Task SamlAuth_DisabledProvider_ReturnsProblem()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = false });

        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse { Data = "irrelevant" });

        Assert.Equal(500, Assert.IsType<ObjectResult>(result).StatusCode);
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
