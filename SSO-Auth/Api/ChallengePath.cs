using System;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Decides whether a challenge arrived on the "new", descriptive route
/// (<c>.../OID/start/{provider}</c> or <c>.../SAML/start/{provider}</c>) rather than the legacy route.
/// The spelling drives the authorization request's redirect_uri, which the token request must later
/// match (RFC 6749 section 4.1.3), so it has to be read off the route exactly — not by a
/// <c>Contains("/start/")</c> substring test, which a provider literally named <c>start</c> on the
/// legacy route (<c>.../OID/p/start/</c>) would trip, flipping the spelling and breaking the login at
/// the IdP's redirect_uri check (#337). Same fix family as <see cref="OidcCallbackPath.RedirectSegment"/>
/// (#98); that one still scans for the first protocol token and should be moved to the same
/// suffix-anchored form (#411).
/// </summary>
internal static class ChallengePath
{
    /// <summary>
    /// Returns true when the route's <c>{protocol}/{path-kind}/{provider}</c> suffix is a
    /// <c>OID|SAML</c> protocol followed by the <c>start</c> path-kind.
    /// </summary>
    /// <param name="path">The challenge request path, e.g. <c>/sso/OID/start/{provider}</c>.</param>
    /// <returns>True for the new "start" route, false for the legacy route.</returns>
    internal static bool IsNewPath(string? path)
    {
        // The challenge route always ends in {protocol}/{path-kind}/{provider}, so anchor to that
        // three-segment suffix rather than the first protocol token found anywhere in the path: a
        // protocol-like reverse-proxy prefix (e.g. /OID/start/proxy/...) must not decide the spelling.
        // Trim only boundary slashes so an internal empty segment (a doubled slash) shifts the suffix
        // and fails to match rather than being silently collapsed into a valid route.
        var segments = path?.Trim('/').Split('/');
        if (segments is null || segments.Length < 3)
        {
            return false;
        }

        var protocol = segments[^3];
        var pathKind = segments[^2];
        var isProtocol = string.Equals(protocol, "OID", StringComparison.OrdinalIgnoreCase)
            || string.Equals(protocol, "SAML", StringComparison.OrdinalIgnoreCase);
        return isProtocol && string.Equals(pathKind, "start", StringComparison.OrdinalIgnoreCase);
    }
}
