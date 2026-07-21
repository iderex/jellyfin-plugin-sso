// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Shared;

/// <summary>
/// Builds the Content-Security-Policy for the rendered auth-completion page. The page runs a single
/// inline script and a single inline style, both authorized by a per-response nonce; everything else
/// is denied. Its script XHR-POSTs to <c>/sso/*/Auth</c> and loads <c>/web/index.html</c> in an
/// iframe, both same-origin (the flow shares <c>localStorage</c> between the page and that iframe, so
/// a cross-origin base URL cannot work regardless of CSP).
/// </summary>
public static class AuthPageCsp
{
    /// <summary>
    /// Builds the Content-Security-Policy header value, binding the inline script and style to
    /// <paramref name="nonce"/>. The same nonce must be emitted on the page's script and style tags.
    /// </summary>
    /// <param name="nonce">The per-response base64 nonce.</param>
    /// <returns>The Content-Security-Policy header value.</returns>
    public static string Build(string nonce) =>
        "default-src 'none'; "
        + $"script-src 'nonce-{nonce}'; "
        + $"style-src 'nonce-{nonce}'; "
        + "connect-src 'self'; "
        + "img-src 'self' data:; "
        + "frame-src 'self'; "
        + "base-uri 'none'; "
        + "form-action 'none'; "
        + "frame-ancestors 'none'";
}
