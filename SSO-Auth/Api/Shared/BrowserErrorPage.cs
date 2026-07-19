using System;
using System.Linq;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.SSO_Auth.Api.Shared;

/// <summary>
/// Re-renders a plain-text rejection from a browser-navigated login endpoint — the OpenID/SAML
/// challenge and callback routes, which the user reaches by direct navigation — as a minimal dark HTML
/// page (matching the auth-completion page's shell) with a "Return to login" link, instead of dumping
/// raw text onto what looks like a broken page (#668). Applied ONLY when the client accepts text/html:
/// the XHR <c>/sso/*/Auth</c> leg (Accept: application/json) reads the response status, not the body, so
/// it keeps the plain-text shape and is unaffected. Success, redirect, and already-HTML results (the
/// challenge redirect, the auth-completion page) carry no plain-text error and pass through untouched.
/// </summary>
internal static class BrowserErrorPage
{
    /// <summary>
    /// Restyles <paramref name="result"/> as an HTML error page when it is a plain-text rejection and the
    /// caller is a browser; otherwise returns it unchanged.
    /// </summary>
    /// <param name="result">The flow result to possibly restyle.</param>
    /// <param name="request">The request, whose Accept header decides browser vs XHR/API.</param>
    /// <param name="response">The response the page's CSP nonce and defensive headers are written to.</param>
    /// <returns>The styled HTML result, or the original result unchanged.</returns>
    internal static ActionResult Wrap(ActionResult result, HttpRequest request, HttpResponse response)
    {
        if (!AcceptsHtml(request) || !TryExtractPlainTextError(result, out var status, out var message))
        {
            return result;
        }

        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

        // A script-less page: only the nonce'd <style> is authorized, default-src 'none' denies scripts,
        // fetch, frames and everything else. Same defensive headers the auth-completion page sets.
        response.Headers.ContentSecurityPolicy =
            "default-src 'none'; style-src 'nonce-" + nonce + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
        response.Headers["X-Frame-Options"] = "DENY";
        response.Headers["X-Content-Type-Options"] = "nosniff";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers.CacheControl = "no-store";
        response.Headers["Permissions-Policy"] = FlowResponses.ServedPagePermissionsPolicy;

        return new ContentResult
        {
            Content = Render(nonce, message),
            ContentType = MediaTypeNames.Text.Html,
            StatusCode = status,
        };
    }

    // A browser top-level navigation advertises "text/html" in Accept; the XHR Auth/Link legs send
    // "application/json". Ordinal-ignore-case substring match over every Accept value.
    private static bool AcceptsHtml(HttpRequest request) =>
        request.Headers.Accept.Any(v => v != null && v.Contains("text/html", StringComparison.OrdinalIgnoreCase));

    // A rejection worth restyling is a 4xx/5xx carrying a plain-text body: either a text/plain
    // ContentResult (FlowResponses.PlainTextError, LoginStatusMapper) or a string-valued ObjectResult
    // (BadRequestObjectResult). A success, a redirect, or the already-HTML auth page yields no message.
    private static bool TryExtractPlainTextError(ActionResult result, out int status, out string message)
    {
        switch (result)
        {
            case ContentResult { StatusCode: >= 400 } cr
                when cr.ContentType != null
                     && cr.ContentType.StartsWith(MediaTypeNames.Text.Plain, StringComparison.OrdinalIgnoreCase):
                status = cr.StatusCode.Value;
                message = cr.Content ?? string.Empty;
                return true;
            case ObjectResult { StatusCode: >= 400, Value: string s } or:
                status = or.StatusCode.Value;
                message = s;
                return true;
            default:
                status = 0;
                message = null;
                return false;
        }
    }

    // The message is HTML-encoded because a few plain-text errors interpolate identity-provider-supplied
    // text (an OpenID error/error_description on the callback), which must not break out of the markup.
    // The "Return to login" link is a same-origin relative path, so no request-host derivation is needed.
    private static string Render(string nonce, string message) =>
        "<!DOCTYPE html>\n"
        + "<html lang='en'><head>\n"
        + "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        + "<style nonce='" + nonce + "'>\n"
        + "  body { background: #101010; color: #d1cfce; font-family: Noto Sans, Noto Sans HK, Noto Sans JP, Noto Sans KR, Noto Sans SC, Noto Sans TC, sans-serif; margin: 2rem; }\n"
        + "  a { color: #00a4dc; }\n"
        + "</style>\n"
        + "</head><body>\n"
        + "<p>" + HtmlEncoder.Default.Encode(message) + "</p>\n"
        + "<a href='/web/index.html'>Return to login</a>\n"
        + "</body></html>";
}
