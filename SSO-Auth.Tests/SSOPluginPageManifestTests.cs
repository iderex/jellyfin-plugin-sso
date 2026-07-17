using System.IO;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins the <see cref="PluginPageInfo"/> set <see cref="SSOPlugin.GetPages"/> and
/// <see cref="SSOPlugin.GetViews"/> emit — the (name, embedded resource) contract Jellyfin resolves
/// static assets by — so the #458 factory-collapse refactor stays behavior-preserving.
/// </summary>
[Collection("SSOController")]
public class SSOPluginPageManifestTests
{
    private static SSOPlugin CreatePlugin()
    {
        var appPaths = Substitute.For<IApplicationPaths>();
        appPaths.PluginConfigurationsPath.Returns(Path.Combine(Path.GetTempPath(), "sso-test-" + System.Guid.NewGuid()));
        var xml = Substitute.For<IXmlSerializer>();
        return new SSOPlugin(appPaths, xml, Substitute.For<ILogger<SSOPlugin>>());
    }

    [Fact]
    public void GetPages_EmitsTheExpectedNameAndResourcePairsInOrder()
    {
        var plugin = CreatePlugin();
        const string ns = "Jellyfin.Plugin.SSO_Auth";

        var actual = plugin.GetPages().Select(p => (p.Name, p.EmbeddedResourcePath)).ToArray();

        Assert.Equal(
            new[]
            {
                ("SSO-Auth", $"{ns}.Config.configPage.html"),
                ("SSO-Auth.js", $"{ns}.Config.config.js"),
                ("SSO-Auth.css", $"{ns}.Config.style.css"),
                ("SSO-Auth-linking", $"{ns}.Config.linking.html"),
                ("SSO-Auth-linking.js", $"{ns}.Config.linking.js"),
            },
            actual);
    }

    [Fact]
    public void GetViews_EmitsTheExpectedNameAndResourcePairsInOrder()
    {
        var plugin = CreatePlugin();
        const string ns = "Jellyfin.Plugin.SSO_Auth";

        var actual = plugin.GetViews().Select(p => (p.Name, p.EmbeddedResourcePath)).ToArray();

        Assert.Equal(
            new[]
            {
                ("style.css", $"{ns}.Config.style.css"),
                ("linking", $"{ns}.Config.linking.html"),
                ("linking.js", $"{ns}.Config.linking.js"),
                ("ApiClient.js", $"{ns}.Views.apiClient.js"),
                ("emby-restyle.css", $"{ns}.Views.emby-restyle.css"),
                ("jellyfin-apiClient.esm.min.js", $"{ns}.Views.jellyfin-apiClient.esm.min.js"),
            },
            actual);
    }
}
