using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MediaBrowser.Model;
using MediaBrowser.Model.Plugins;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Jellyfin.Plugin.SSO_Auth.Views;

/// <summary>
/// The sso views controller.
/// </summary>
[ApiController]
[Route("[controller]")]
public class SSOViewsController : ControllerBase
{
    // The embedded view assets only change with the plugin version, so a version-derived ETag lets clients
    // 304-revalidate instead of re-downloading jellyfin-apiClient.esm.min.js (~79 KB) + emby-restyle.css on
    // every linking-page load (#253). Derived from the FILE version (set per release by the build), not the
    // AssemblyVersion (which can stay static across releases and would then serve stale assets after an
    // update). The same tag across assets is correct: a client sends the ETag it cached for a given URL, and
    // the server compares it against that URL's current tag.
    private static readonly EntityTagHeaderValue AssetETag = new EntityTagHeaderValue(
        "\"" + System.Diagnostics.FileVersionInfo.GetVersionInfo(
            typeof(SSOViewsController).Assembly.Location).FileVersion + "\"");

    private readonly ILogger<SSOViewsController> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOViewsController"/> class.
    /// </summary>
    /// <param name="logger">Instance of the <see cref="ILogger{SSOViewsController}"/> interface.</param>
    public SSOViewsController(ILogger<SSOViewsController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Gets an HTML view.
    /// </summary>
    /// <param name="viewName">The name of the view / asset to fetch.</param>
    /// <returns>The HTML view with the specified name.</returns>
    [HttpGet("{viewName}")]
    public ActionResult GetView([FromRoute] string viewName)
    {
        return ServeView(viewName);
    }

    private ActionResult ServeView(string viewName)
    {
        if (SSOPlugin.Instance == null)
        {
            return BadRequest("No plugin instance found");
        }

        IEnumerable<PluginPageInfo> pages = SSOPlugin.Instance.GetViews();

        if (pages == null)
        {
            return NotFound("Pages is null or empty");
        }

        var view = pages.FirstOrDefault(pageInfo => string.Equals(pageInfo.Name, viewName, StringComparison.Ordinal), null);

        if (view == null)
        {
            return NotFound("No matching view found");
        }
#nullable enable
        Stream? stream = SSOPlugin.Instance.GetType().Assembly.GetManifestResourceStream(view.EmbeddedResourcePath);

        if (stream == null)
        {
            _logger.LogError("Failed to get resource {Resource}", view.EmbeddedResourcePath);
            return NotFound();
        }
#nullable disable
        return File(stream, MimeTypes.GetMimeType(view.EmbeddedResourcePath), lastModified: null, entityTag: AssetETag);
    }
}
