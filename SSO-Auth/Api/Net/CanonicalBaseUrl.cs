using System;
using System.Diagnostics.CodeAnalysis;

namespace Jellyfin.Plugin.SSO_Auth.Api.Net;

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
    internal static bool TryNormalize(string? raw, [NotNullWhen(true)] out string? normalized)
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
    internal static bool IsInvalidOverride(string? raw)
        => !string.IsNullOrWhiteSpace(raw) && !TryNormalize(raw, out _);

    /// <summary>
    /// Resolves the external base URL that every derived <c>redirect_uri</c> and SAML base is built on.
    /// A configured <paramref name="baseUrlOverride"/> is authoritative (#139) — it removes the
    /// dependency on the spoofable request <c>Host</c>. A malformed override is rejected at every admin
    /// write path, so it should never reach here; if one does (a hand-edited or restored config), this
    /// fails closed rather than silently reverting to the untrusted request host. Only a blank override
    /// uses the request-derived fallback: the default port (80 on http, 443 on https) is elided, only a
    /// literal <c>"http"</c>/<c>"https"</c> scheme override is honored (anything else falls back to the
    /// request scheme), and the trailing slash is trimmed so the result concatenates cleanly with
    /// <c>/sso/...</c>.
    /// </summary>
    /// <param name="baseUrlOverride">The configured canonical base URL, or blank to use the request.</param>
    /// <param name="scheme">The request scheme.</param>
    /// <param name="host">The request host (no port).</param>
    /// <param name="port">The request port, or null.</param>
    /// <param name="pathBase">The request path base.</param>
    /// <param name="schemeOverride">The per-provider scheme override, or null.</param>
    /// <param name="portOverride">The per-provider port override, or null.</param>
    /// <returns>The external base URL, without a trailing slash.</returns>
    internal static string Resolve(string? baseUrlOverride, string scheme, string host, int? port, string pathBase, string? schemeOverride, int? portOverride)
    {
        if (!string.IsNullOrWhiteSpace(baseUrlOverride))
        {
            if (TryNormalize(baseUrlOverride, out var canonical))
            {
                return canonical;
            }

            throw new InvalidOperationException("The configured Base URL override is not a valid absolute http(s) URL.");
        }

        // Only a literal http/https scheme override is honored; anything else falls back to the request
        // scheme. Resolve the effective scheme FIRST so the default-port elision below decides against the
        // scheme that will actually appear in the URL (#272).
        if (!string.Equals(schemeOverride, "http", StringComparison.Ordinal) && !string.Equals(schemeOverride, "https", StringComparison.Ordinal))
        {
            schemeOverride = null;
        }

        var effectiveScheme = schemeOverride ?? scheme;
        var requestPort = portOverride ?? port ?? -1;

        // Elide the default port for the EFFECTIVE scheme, so a TLS-terminating proxy (http request +
        // schemeOverride=https + port 443) yields the canonical https://host, not https://host:443.
        if ((requestPort == 80 && string.Equals(effectiveScheme, "http", StringComparison.OrdinalIgnoreCase))
            || (requestPort == 443 && string.Equals(effectiveScheme, "https", StringComparison.OrdinalIgnoreCase)))
        {
            requestPort = -1;
        }

        return new UriBuilder
        {
            Scheme = effectiveScheme,
            Host = host,
            Port = requestPort,
            Path = pathBase,
        }.ToString().TrimEnd('/');
    }
}
