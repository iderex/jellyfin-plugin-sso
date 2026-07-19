#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The trailing <c>{protocol}/{path-kind}/{provider}</c> suffix that both <see cref="ChallengePath"/>
/// and <see cref="Jellyfin.Plugin.SSO_Auth.Api.Oidc.OidcCallbackPath"/> anchor their new-vs-legacy route classification to (#411). Anchoring
/// to the suffix — rather than the first protocol-like token found anywhere in the path — keeps a
/// protocol-like reverse-proxy prefix (e.g. <c>/OID/start/proxy/...</c>) from deciding the spelling (#337).
/// Each caller keeps its own terminal comparison (which protocol/path-kind values it accepts) and its own
/// default for a missing suffix; only the trim/split/anchor mechanics live here (#509).
/// </summary>
/// <param name="Protocol">The suffix segment three places from the end, e.g. <c>OID</c> or <c>SAML</c>.</param>
/// <param name="PathKind">The suffix segment two places from the end, e.g. <c>start</c> or <c>redirect</c>.</param>
internal readonly record struct RouteSuffix(string Protocol, string PathKind)
{
    /// <summary>
    /// Reads the <c>{protocol}/{path-kind}/{provider}</c> suffix off <paramref name="path"/>. Trims only
    /// boundary slashes, so an internal doubled slash shifts the suffix and fails to match rather than
    /// being silently collapsed into a valid route.
    /// </summary>
    /// <param name="path">The request path, e.g. <c>/sso/OID/start/{provider}</c>.</param>
    /// <param name="suffix">The parsed suffix when the path has at least three segments; default otherwise.</param>
    /// <returns>False when <paramref name="path"/> is null or has fewer than three <c>/</c>-separated segments.</returns>
    internal static bool TryRead(string? path, out RouteSuffix suffix)
    {
        var segments = path?.Trim('/').Split('/');
        if (segments is null || segments.Length < 3)
        {
            suffix = default;
            return false;
        }

        suffix = new RouteSuffix(segments[^3], segments[^2]);
        return true;
    }
}
