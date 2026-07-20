using System;
using Jellyfin.Plugin.SSO_Auth.Api.Routing;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Derives the r/redirect path segment for rebuilding the callback's redirect URI. The token
/// request's redirect_uri must match the authorization request's (RFC 6749 section 4.1.3), and the
/// IdP delivers the callback on exactly the route the authorization request advertised — so the
/// segment is read off the callback's own path. The previous expression tested for "/start/", a
/// challenge-route segment that never occurs on callback routes, so the new-path flow sent a
/// mismatched redirect_uri that spec-enforcing IdPs reject (#98). The route is now read off its
/// <c>{protocol}/{path-kind}/{provider}</c> suffix through the shared <see cref="RouteSuffix"/> reader —
/// the same robust form as <see cref="ChallengePath.IsNewPath"/> — so a protocol-like reverse-proxy
/// prefix cannot decide the spelling (#411, #509).
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
        if (!RouteSuffix.TryRead(path, out var suffix))
        {
            return "r";
        }

        return string.Equals(suffix.Protocol, "OID", StringComparison.OrdinalIgnoreCase)
            && string.Equals(suffix.PathKind, "redirect", StringComparison.OrdinalIgnoreCase)
                ? "redirect"
                : "r";
    }
}
