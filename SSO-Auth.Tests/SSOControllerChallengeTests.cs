using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
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
        // The redirect carries the deflated+encoded AuthnRequest, so it must be a real SAML redirect.
        Assert.Contains("SAMLRequest=", result.Url);
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
    public void OidProviders_ReturnsOkSnapshotContainingTheProvider()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig());

        var ok = Assert.IsType<OkObjectResult>(harness.Controller.OidProviders());
        var snapshot = Assert.IsType<SerializableDictionary<string, OidConfig>>(ok.Value);
        Assert.True(snapshot.ContainsKey("keycloak"));
    }

    [Fact]
    public void SamlProviders_ReturnsOkSnapshotContainingTheProvider()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig());

        var ok = Assert.IsType<OkObjectResult>(harness.Controller.SamlProviders());
        var snapshot = Assert.IsType<SerializableDictionary<string, SamlConfig>>(ok.Value);
        Assert.True(snapshot.ContainsKey("adfs"));
    }
}
