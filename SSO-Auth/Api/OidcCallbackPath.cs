using System;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Derives the r/redirect path segment for rebuilding the callback's redirect URI. The token
/// request's redirect_uri must match the authorization request's (RFC 6749 section 4.1.3), and the
/// IdP delivers the callback on exactly the route the authorization request advertised — so the
/// segment is read off the callback's own path. The previous expression tested for "/start/", a
/// challenge-route segment that never occurs on callback routes, so the new-path flow sent a
/// mismatched redirect_uri that spec-enforcing IdPs reject (#98). The route is now read off its
/// <c>{protocol}/{path-kind}/{provider}</c> suffix — the same robust form as
/// <see cref="ChallengePath.IsNewPath"/> — so a protocol-like reverse-proxy prefix cannot decide
/// the spelling (#411).
/// </summary>
internal static class OidcCallbackPath
{
    /// <summary>
    /// Returns the redirect-path segment ("redirect" or "r") matching the callback route in the given path.
    /// </summary>
    /// <param name="path">The callback request path, e.g. <c>/sso/OID/redirect/{provider}</c>.</param>
    /// <returns>"redirect" when the route's <c>OID/{path-kind}/{provider}</c> suffix names the "redirect" path-kind, otherwise "r".</returns>
    internal static string RedirectSegment(string? path)
    {
        // The callback route always ends in {protocol}/{path-kind}/{provider}, so anchor to that
        // three-segment suffix rather than the first "OID" token found anywhere in the path: a
        // protocol-like reverse-proxy prefix (e.g. /OID/redirect/proxy/...) must not decide the
        // spelling. Trim only boundary slashes so an internal empty segment (a doubled slash) shifts
        // the suffix and fails to match rather than being silently collapsed into a valid route.
        // Same suffix-anchored form as ChallengePath.IsNewPath (#411).
        var segments = path?.Trim('/').Split('/');
        if (segments is null || segments.Length < 3)
        {
            return "r";
        }

        var protocol = segments[^3];
        var pathKind = segments[^2];
        return string.Equals(protocol, "OID", StringComparison.OrdinalIgnoreCase)
            && string.Equals(pathKind, "redirect", StringComparison.OrdinalIgnoreCase)
                ? "redirect"
                : "r";
    }
}
