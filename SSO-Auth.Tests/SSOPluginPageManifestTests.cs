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
/// static assets by — so the #458 factory-collapse refactor stays behavior-preserving, and asserts every
/// emitted resource path actually resolves to an embedded resource so a moved or renamed asset (#869) is
/// caught here as a build-time failure instead of a runtime 404.
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
                ("SSO-Auth", $"{ns}.Web.configPage.html"),
                ("SSO-Auth.js", $"{ns}.Web.config.js"),
                ("SSO-Auth.css", $"{ns}.Web.style.css"),
                ("SSO-Auth-linking", $"{ns}.Web.linking.html"),
                ("SSO-Auth-linking.js", $"{ns}.Web.linking.js"),
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
                ("style.css", $"{ns}.Web.style.css"),
                ("linking", $"{ns}.Web.linking.html"),
                ("linking.js", $"{ns}.Web.linking.js"),
                ("ApiClient.js", $"{ns}.Web.ApiClient.js"),
                ("emby-restyle.css", $"{ns}.Web.emby-restyle.css"),
                ("jellyfin-apiClient.esm.min.js", $"{ns}.Web.jellyfin-apiClient.esm.min.js"),
            },
            actual);
    }

    [Fact]
    public void EveryManifestResourcePath_ResolvesToAnEmbeddedResource()
    {
        var plugin = CreatePlugin();
        var assembly = typeof(SSOPlugin).Assembly;

        var paths = plugin.GetPages().Concat(plugin.GetViews())
            .Select(p => p.EmbeddedResourcePath)
            .Distinct();

        foreach (var path in paths)
        {
            using var stream = assembly.GetManifestResourceStream(path);
            Assert.True(stream is not null, $"Embedded resource does not resolve (a moved or renamed asset would 404 at runtime): {path}");
        }
    }
}
