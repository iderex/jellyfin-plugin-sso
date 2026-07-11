using System;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Derives the r/redirect path segment for rebuilding the callback's redirect URI. The token
/// request's redirect_uri must match the authorization request's (RFC 6749 section 4.1.3), and the
/// IdP delivers the callback on exactly the route the authorization request advertised — so the
/// segment is read off the callback's own path. The previous expression tested for "/start/", a
/// challenge-route segment that never occurs on callback routes, so the new-path flow sent a
/// mismatched redirect_uri that spec-enforcing IdPs reject (#98).
/// </summary>
internal static class OidcCallbackPath
{
    /// <summary>
    /// Returns the redirect-path segment ("redirect" or "r") matching the callback route in the given path.
    /// </summary>
    /// <param name="path">The callback request path, e.g. <c>/sso/OID/redirect/{provider}</c>.</param>
    /// <returns>"redirect" when the route segment (the element after "OID") is "redirect", otherwise "r".</returns>
    internal static string RedirectSegment(string? path)
    {
        // Match the route segment exactly (the element after "OID"), not by substring: a provider
        // literally named "redirect" must never flip the classic route, regardless of trailing
        // slashes or where "redirect" appears in the provider name.
        var segments = path?.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments is not null)
        {
            for (var i = 0; i + 1 < segments.Length; i++)
            {
                if (string.Equals(segments[i], "OID", StringComparison.OrdinalIgnoreCase))
                {
                    return string.Equals(segments[i + 1], "redirect", StringComparison.OrdinalIgnoreCase) ? "redirect" : "r";
                }
            }
        }

        return "r";
    }
}
