using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the enabled-provider SAML challenge, the Unregister guard, and the admin
/// provider-list endpoints via <see cref="SsoControllerHarness"/>.
/// </summary>
[Collection("SSOController")]
public class SSOControllerChallengeTests
{
    [Fact]
    public void SamlChallenge_EnabledProvider_RedirectsToTheIdentityProvider()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlEndpoint = "https://idp.example.com/sso",
            SamlClientId = "jellyfin-sp",
        });

        var result = Assert.IsType<RedirectResult>(harness.Controller.SamlChallenge("adfs"));

        Assert.StartsWith("https://idp.example.com/sso", result.Url);
    }

    [Fact]
    public async Task Unregister_UnknownUser_ReturnsNotFound()
    {
        // The mocked IUserManager returns null for any name, so the guard short-circuits.
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.Unregister("nobody", "Jellyfin");

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public void OidProviders_ReturnsOkSnapshot()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig());

        Assert.IsType<OkObjectResult>(harness.Controller.OidProviders());
    }

    [Fact]
    public void SamlProviders_ReturnsOkSnapshot()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig());

        Assert.IsType<OkObjectResult>(harness.Controller.SamlProviders());
    }
}
