using System.Net.Http;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Creates the plugin's outbound HTTP clients from the shared <see cref="IHttpClientFactory"/> with the
/// plugin's User-Agent applied, so every server-to-provider call (OpenID discovery, the PKCE-support
/// probe) is identifiable and configured in one place. The SSRF-guarded avatar fetch uses its own
/// hardened handler and does not go through here.
/// </summary>
internal static class SsoHttp
{
    /// <summary>
    /// Returns a pooled <see cref="HttpClient"/> from the factory with the plugin User-Agent set.
    /// </summary>
    /// <param name="factory">The shared HTTP client factory.</param>
    /// <param name="userAgent">The plugin User-Agent header value.</param>
    /// <returns>A client with the User-Agent applied.</returns>
    internal static HttpClient CreateClient(IHttpClientFactory factory, string userAgent)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
        return client;
    }
}
