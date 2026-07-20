using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="LoginButtonBuilder"/> — the pure selection rule that turns the configuration into the
/// ordered login buttons (#722): management must be on, only enabled + non-hidden providers get a button,
/// OpenID before SAML, and the label falls back from <c>LoginButtonText</c> to the provider name.
/// </summary>
public class LoginButtonBuilderTests
{
    private static PluginConfiguration Config(bool manage)
    {
        var config = new PluginConfiguration { ManageLoginPageButtons = manage };
        return config;
    }

    [Fact]
    public void Build_ManagementOff_IsEmptyEvenWithEnabledProviders()
    {
        var config = Config(manage: false);
        config.OidConfigs["keycloak"] = new OidConfig { Enabled = true };

        Assert.Empty(LoginButtonBuilder.Build(config));
    }

    [Fact]
    public void Build_ExcludesDisabledAndHiddenProviders()
    {
        var config = Config(manage: true);
        config.OidConfigs["on"] = new OidConfig { Enabled = true };
        config.OidConfigs["off"] = new OidConfig { Enabled = false };
        config.OidConfigs["hidden"] = new OidConfig { Enabled = true, HideLoginButton = true };

        var names = LoginButtonBuilder.Build(config).Select(b => b.Name).ToList();

        Assert.Contains("on", names);
        Assert.DoesNotContain("off", names);
        Assert.DoesNotContain("hidden", names);
    }

    [Fact]
    public void Build_LabelFallsBackFromTextToName()
    {
        var config = Config(manage: true);
        config.OidConfigs["withText"] = new OidConfig { Enabled = true, LoginButtonText = "Sign in with Corp" };
        config.OidConfigs["noText"] = new OidConfig { Enabled = true };
        config.OidConfigs["blankText"] = new OidConfig { Enabled = true, LoginButtonText = "   " };

        var byName = LoginButtonBuilder.Build(config).ToDictionary(b => b.Name, b => b.Text);

        Assert.Equal("Sign in with Corp", byName["withText"]);
        Assert.Equal("noText", byName["noText"]);
        // Whitespace-only text falls back to the name too.
        Assert.Equal("blankText", byName["blankText"]);
    }

    [Fact]
    public void Build_OrdersOpenIdBeforeSaml_WithCorrectProtocol()
    {
        var config = Config(manage: true);
        config.OidConfigs["oidc1"] = new OidConfig { Enabled = true };
        config.SamlConfigs["saml1"] = new SamlConfig { Enabled = true };

        var buttons = LoginButtonBuilder.Build(config);

        Assert.Equal(2, buttons.Count);
        Assert.Equal(LoginButtonProtocol.Oidc, buttons[0].Protocol);
        Assert.Equal("oidc1", buttons[0].Name);
        Assert.Equal(LoginButtonProtocol.Saml, buttons[1].Protocol);
        Assert.Equal("saml1", buttons[1].Name);
    }
}
