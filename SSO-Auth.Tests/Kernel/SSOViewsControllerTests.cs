using System.IO;
using Jellyfin.Plugin.SSO_Auth.Views;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SSOViewsController.GetView"/> — the endpoint that serves the plugin's embedded
/// view assets (the linking page, its stylesheet and scripts). The action itself resolves the requested
/// name against <see cref="SSOPlugin.GetViews"/>, streams the matching embedded resource, and tags the
/// response with the version-derived <c>AssetETag</c> so clients can 304-revalidate (#253). These tests
/// pin exactly that action-level behavior: an unknown name 404s, a known name streams the resource with
/// the content type derived from the embedded resource path and the version ETag. The conditional
/// <c>If-None-Match</c> → 304 negotiation is ASP.NET middleware, not this action, so it is out of scope.
///
/// Constructing an <see cref="SSOPlugin"/> sets the static <see cref="SSOPlugin.Instance"/> the
/// controller reads, so these run in the non-parallel <c>SSOController</c> collection.
/// </summary>
[Collection("SSOController")]
public class SSOViewsControllerTests
{
    private static SSOViewsController CreateController()
    {
        var appPaths = Substitute.For<IApplicationPaths>();
        appPaths.PluginConfigurationsPath.Returns(Path.Combine(Path.GetTempPath(), "sso-test-" + System.Guid.NewGuid()));
        appPaths.PluginsPath.Returns(Path.Combine(Path.GetTempPath(), "sso-test-plugins-" + System.Guid.NewGuid()));
        var xml = Substitute.For<IXmlSerializer>();
        // Constructing the plugin sets the static SSOPlugin.Instance the controller reads for GetViews().
        _ = new SSOPlugin(appPaths, xml, Substitute.For<ILogger<SSOPlugin>>());
        return new SSOViewsController(Substitute.For<ILogger<SSOViewsController>>());
    }

    // The version-derived ETag the action stamps on every asset, recomputed here from the same source the
    // controller uses (the SSO-Auth assembly's FILE version) so the assertions catch a regression to a
    // null, weak, or lastModified-only tag.
    private static string ExpectedAssetETag()
    {
        var fileVersion = System.Diagnostics.FileVersionInfo.GetVersionInfo(
            typeof(SSOPlugin).Assembly.Location).FileVersion;
        return "\"" + fileVersion + "\"";
    }

    [Fact]
    public void GetView_UnknownViewName_ReturnsNotFound()
    {
        var controller = CreateController();

        var result = controller.GetView("does-not-exist");

        var notFound = Assert.IsType<NotFoundObjectResult>(result);
        Assert.Equal("No matching view found", notFound.Value);
    }

    [Fact]
    public void GetView_KnownHtmlView_StreamsResourceWithHtmlTypeAndVersionETag()
    {
        var controller = CreateController();

        // "linking" is registered without a ".html" suffix, but its embedded resource is Config.linking.html;
        // asserting text/html therefore also pins that the content type is derived from the resource PATH,
        // not the (extensionless) requested name.
        var result = controller.GetView("linking");

        var file = Assert.IsType<FileStreamResult>(result);
        Assert.NotNull(file.FileStream);
        Assert.True(file.FileStream.CanRead);
        Assert.Equal("text/html", file.ContentType);

        Assert.NotNull(file.EntityTag);
        Assert.False(file.EntityTag!.IsWeak);
        Assert.Equal(ExpectedAssetETag(), file.EntityTag.Tag.ToString());
    }

    [Fact]
    public void GetView_KnownCssView_StreamsResourceWithCssTypeAndVersionETag()
    {
        var controller = CreateController();

        var result = controller.GetView("style.css");

        var file = Assert.IsType<FileStreamResult>(result);
        Assert.NotNull(file.FileStream);
        Assert.Equal("text/css", file.ContentType);

        Assert.NotNull(file.EntityTag);
        Assert.False(file.EntityTag!.IsWeak);
        Assert.Equal(ExpectedAssetETag(), file.EntityTag.Tag.ToString());
    }

    [Fact]
    public void GetView_MultiDotScriptView_DerivesJavascriptTypeFromResourcePath()
    {
        var controller = CreateController();

        // The ".esm.min.js" name exercises multi-dot extension parsing; the mapped type differs across
        // Jellyfin versions (text/javascript vs application/javascript), so pin the stable substring.
        var result = controller.GetView("jellyfin-apiClient.esm.min.js");

        var file = Assert.IsType<FileStreamResult>(result);
        Assert.NotNull(file.FileStream);
        Assert.Contains("javascript", file.ContentType, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetView_ServesTheSameVersionETagAcrossDifferentAssets()
    {
        var controller = CreateController();

        // The comment on AssetETag documents that one tag for every asset is intentional: a client sends
        // back the tag it cached for a given URL and the server compares it against that URL's tag.
        var html = Assert.IsType<FileStreamResult>(controller.GetView("linking"));
        var css = Assert.IsType<FileStreamResult>(controller.GetView("style.css"));

        Assert.Equal(html.EntityTag!.Tag.ToString(), css.EntityTag!.Tag.ToString());
    }
}
