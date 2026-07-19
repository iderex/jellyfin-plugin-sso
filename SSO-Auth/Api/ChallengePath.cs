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
/// the IdP's redirect_uri check (#337). Same fix family as <see cref="Jellyfin.Plugin.SSO_Auth.Api.Oidc.OidcCallbackPath.RedirectSegment"/>
/// (#98); both now read the suffix through the shared <see cref="RouteSuffix"/> reader (#411, #509) and
/// keep only their own terminal comparison and default.
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
        if (!RouteSuffix.TryRead(path, out var suffix))
        {
            return false;
        }

        var isProtocol = string.Equals(suffix.Protocol, "OID", StringComparison.OrdinalIgnoreCase)
            || string.Equals(suffix.Protocol, "SAML", StringComparison.OrdinalIgnoreCase);
        return isProtocol && string.Equals(suffix.PathKind, "start", StringComparison.OrdinalIgnoreCase);
    }
}
