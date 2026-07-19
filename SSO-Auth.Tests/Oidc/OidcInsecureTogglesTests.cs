using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcInsecureToggles"/> — the helper that names the enabled RFC 9700
/// escape-hatch options on a provider (#140), so a save with any of them set can be audit-logged.
/// </summary>
public class OidcInsecureTogglesTests
{
    [Fact]
    public void Enabled_FullyValidatedProvider_ReturnsEmpty()
    {
        Assert.Empty(OidcInsecureToggles.Enabled(new OidConfig()));
    }

    [Fact]
    public void Enabled_NullConfig_ReturnsEmpty()
    {
        Assert.Empty(OidcInsecureToggles.Enabled(null));
    }

    [Fact]
    public void Enabled_DisableHttps_ReportsIt()
    {
        Assert.Equal(new[] { "DisableHttps" }, OidcInsecureToggles.Enabled(new OidConfig { DisableHttps = true }));
    }

    [Fact]
    public void Enabled_DoNotValidateIssuerName_ReportsIt()
    {
        Assert.Equal(new[] { "DoNotValidateIssuerName" }, OidcInsecureToggles.Enabled(new OidConfig { DoNotValidateIssuerName = true }));
    }

    [Fact]
    public void Enabled_DoNotValidateEndpoints_ReportsIt()
    {
        Assert.Equal(new[] { "DoNotValidateEndpoints" }, OidcInsecureToggles.Enabled(new OidConfig { DoNotValidateEndpoints = true }));
    }

    [Fact]
    public void Enabled_DoNotValidateResponseIssuer_ReportsIt()
    {
        Assert.Equal(new[] { "DoNotValidateResponseIssuer" }, OidcInsecureToggles.Enabled(new OidConfig { DoNotValidateResponseIssuer = true }));
    }

    [Fact]
    public void Enabled_AllFour_ReportsAll_MostSevereFirst()
    {
        var config = new OidConfig
        {
            DisableHttps = true,
            DoNotValidateIssuerName = true,
            DoNotValidateEndpoints = true,
            DoNotValidateResponseIssuer = true,
        };
        Assert.Equal(
            new[] { "DisableHttps", "DoNotValidateIssuerName", "DoNotValidateEndpoints", "DoNotValidateResponseIssuer" },
            OidcInsecureToggles.Enabled(config));
    }

    [Fact]
    public void Enabled_UnrelatedOptions_AreNotReported()
    {
        // These are not RFC 9700 discovery/transport escape hatches, so they are out of scope here.
        var config = new OidConfig { DisablePushedAuthorization = true, DoNotLoadProfile = true };
        Assert.Empty(OidcInsecureToggles.Enabled(config));
    }
}
