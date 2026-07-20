#nullable enable

using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Net;

namespace Jellyfin.Plugin.SSO_Auth.Api.Avatar;

/// <summary>
/// Validation helpers that constrain the server-side avatar fetch to public http(s) targets,
/// mitigating server-side request forgery via IdP-supplied avatar URLs/claims. The address-range
/// classification itself lives in <see cref="IpAddressClassifier"/> (#370), shared with the login
/// rate limiter's client-key derivation, so both cannot disagree on what a public address is.
/// </summary>
internal static class AvatarUrlValidator
{
    /// <summary>
    /// Checks that the URL is an absolute http/https URL that does not obviously target a
    /// loopback/private/link-local address or localhost. Hostnames are validated again at connect
    /// time against their resolved address to defend against DNS-based SSRF and rebinding.
    /// </summary>
    /// <param name="url">The candidate avatar URL.</param>
    /// <param name="uri">The parsed URI when allowed; otherwise null.</param>
    /// <returns>True when the URL is allowed to be fetched.</returns>
    internal static bool IsAllowedUrl(string url, [NotNullWhen(true)] out Uri? uri)
    {
        uri = null;
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var parsed))
        {
            return false;
        }

        if (!string.Equals(parsed.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) && !string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            return false;
        }

        // Strip a fully-qualified trailing dot ("localhost." / "host.") before the localhost check,
        // since it resolves the same but would otherwise slip past the string comparison.
        var host = parsed.DnsSafeHost.TrimEnd('.');
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (IPAddress.TryParse(host, out var literal) && IpAddressClassifier.IsBlockedAddress(literal))
        {
            return false;
        }

        uri = parsed;
        return true;
    }
}
