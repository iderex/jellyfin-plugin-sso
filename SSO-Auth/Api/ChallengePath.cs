using System;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Decides whether a challenge arrived on the "new", descriptive route
/// (<c>.../OID/start/{provider}</c> or <c>.../SAML/start/{provider}</c>) rather than the legacy route.
/// The spelling drives the authorization request's redirect_uri, which the token request must later
/// match (RFC 6749 section 4.1.3), so it has to be read off the route segment exactly — not by a
/// <c>Contains("/start/")</c> substring test, which a provider literally named <c>start</c> on the
/// legacy route (<c>.../OID/p/start/</c>) would trip, flipping the spelling and breaking the login at
/// the IdP's redirect_uri check (#337). Mirrors <see cref="OidcCallbackPath.RedirectSegment"/> (#98).
/// </summary>
internal static class ChallengePath
{
    /// <summary>
    /// Returns true when the route segment after the protocol (<c>OID</c>/<c>SAML</c>) is <c>start</c>.
    /// </summary>
    /// <param name="path">The challenge request path, e.g. <c>/sso/OID/start/{provider}</c>.</param>
    /// <returns>True for the new "start" route, false for the legacy route.</returns>
    internal static bool IsNewPath(string? path)
    {
        var segments = path?.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments is not null)
        {
            for (var i = 0; i + 1 < segments.Length; i++)
            {
                if (string.Equals(segments[i], "OID", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(segments[i], "SAML", StringComparison.OrdinalIgnoreCase))
                {
                    return string.Equals(segments[i + 1], "start", StringComparison.OrdinalIgnoreCase);
                }
            }
        }

        return false;
    }
}
