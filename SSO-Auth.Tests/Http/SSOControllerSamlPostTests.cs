// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the SAML assertion-consumer callback (<c>SamlPost</c>) via
/// <see cref="SsoControllerHarness"/>, using <see cref="SamlTestFactory"/> to produce a real, signed
/// response so the actual signature-validation path runs. They cover the guard branches (disabled
/// provider, invalid signature, role not allowed) and the happy path, where a valid signed assertion
/// renders the intermediate auth page (an HTML <see cref="ContentResult"/> that later posts to SamlAuth).
/// </summary>
[Collection("SSOController")]
public class SSOControllerSamlPostTests
{
    [Fact]
    public void SamlPost_DisabledProvider_Returns400()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = false });

        var result = harness.Controller.SamlCallback("adfs", formSamlResponse: "irrelevant");

        // Shares the unknown-provider body now (the unique "No active providers found" wording is
        // retired), so a disabled provider cannot be told apart from an unknown one (#318).
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("No matching provider found", content.Content);
    }

    [Fact]
    public void SamlPost_SignedByAnotherCertificate_Returns400()
    {
        var fixture = SamlTestFactory.Create();
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            // The provider trusts a different certificate, so the real signature check must reject it.
            SamlCertificate = SamlFixture.ForeignCertificateBase64(),
        });

        var result = harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse());

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public void SamlPost_RoleNotAllowed_Returns401()
    {
        var fixture = SamlTestFactory.Create(role: "jellyfin-users");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true, // audience validation is covered separately
            Roles = new[] { "only-admins" },
        });

        var result = harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse());

        Assert.Equal(401, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public void SamlPost_ValidSignedResponse_RendersTheAuthPage()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
        });

        var result = harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse());

        // A valid assertion renders the intermediate HTML auth page (which then posts to SamlAuth).
        var page = Assert.IsType<ContentResult>(result);
        Assert.Equal("text/html", page.ContentType);
        Assert.False(string.IsNullOrEmpty(page.Content));
        // The page is served with the hardened CSP the auth page sets.
        Assert.True(harness.Controller.Response.Headers.ContainsKey("Content-Security-Policy"));
    }
}
