using System;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Normalizes the per-provider canonical external base-URL override (#139). When an admin pins the
/// external base URL, <c>GetRequestBase</c> returns it verbatim instead of deriving the redirect_uri
/// and SAML base from the request <c>Host</c> header — which a reverse proxy forwarding an unfiltered
/// <c>X-Forwarded-Host</c> lets an attacker influence, poisoning the authorization response's target
/// (RFC 9700 sect. 4.1). Only a well-formed absolute http/https authority is accepted; anything else
/// is rejected so a malformed override is caught at every admin write path (the config-page save and
/// the OID/SAML Add endpoints) and cannot be persisted, rather than silently falling back to the
/// untrusted host at login.
/// </summary>
internal static class CanonicalBaseUrl
{
    /// <summary>
    /// Tries to normalize a configured base-URL override to an absolute origin (scheme + host + optional
    /// port + optional path base), with any trailing slash trimmed so it concatenates cleanly with the
    /// <c>/sso/...</c> paths. A blank value is not an override (the caller keeps the request-host
    /// behavior) and returns <see langword="false"/>.
    /// </summary>
    /// <param name="raw">The configured override value.</param>
    /// <param name="normalized">The normalized base URL when the value is a valid override.</param>
    /// <returns><see langword="true"/> if <paramref name="raw"/> is a valid absolute http/https base URL.</returns>
    internal static bool TryNormalize(string raw, out string normalized)
    {
        normalized = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }

        // Only http/https, and only a bare origin: a query or fragment on a base URL is a misconfiguration
        // that would corrupt every derived redirect_uri, and a userinfo component (user:pass@host) has no
        // place in a public base URL and can mask the real host.
        if ((!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || string.IsNullOrEmpty(uri.Host))
        {
            return false;
        }

        normalized = uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        return true;
    }

    /// <summary>
    /// Whether a non-blank override value is invalid, i.e. an admin set something but it is not a usable
    /// base URL. Used at save time to reject the configuration fail-closed. A blank value is valid (the
    /// feature is simply off).
    /// </summary>
    /// <param name="raw">The configured override value.</param>
    /// <returns><see langword="true"/> if the value is set but not a valid base URL.</returns>
    internal static bool IsInvalidOverride(string raw)
        => !string.IsNullOrWhiteSpace(raw) && !TryNormalize(raw, out _);
}
