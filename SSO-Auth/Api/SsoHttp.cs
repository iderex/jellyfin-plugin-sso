using System.Diagnostics;
using System.Net.Http;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The one home for the plugin's outbound HTTP policy: the User-Agent value and the factory-client
/// creation it is applied to, so every server-to-provider call (OpenID discovery, the PKCE-support
/// probe) is identifiable and configured in one place. The SSRF-guarded avatar fetch builds its own
/// hardened handler and does not go through <see cref="CreateClient"/>, but consumes
/// <see cref="UserAgent"/> so the identity stays single-sourced. Enforced by the opengrep rule
/// no-raw-outbound-httpclient.
/// </summary>
internal static class SsoHttp
{
    /// <summary>
    /// The plugin's outbound User-Agent: product token, assembly file version, and project URL.
    /// </summary>
    internal static readonly string UserAgent =
        $"Jellyfin-Plugin-SSO-Auth +{FileVersionInfo.GetVersionInfo(typeof(SsoHttp).Assembly.Location).FileVersion} (https://github.com/iderex/jellyfin-plugin-sso)";

    /// <summary>
    /// Returns a factory client (over the factory's pooled handler stack) with <see cref="UserAgent"/> applied.
    /// </summary>
    /// <param name="factory">The shared HTTP client factory.</param>
    /// <returns>A client with the plugin User-Agent applied.</returns>
    internal static HttpClient CreateClient(IHttpClientFactory factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return client;
    }
}
