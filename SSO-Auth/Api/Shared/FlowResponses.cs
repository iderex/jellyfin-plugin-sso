// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net.Mime;
using System.Security.Cryptography;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.SSO_Auth.Api.Shared;

/// <summary>
/// The HTTP result shapes shared by both login-flow services (#160): the plain-text error, the
/// security-headered intermediate auth page, and the manual-link write mapping. These were controller
/// helpers (<c>ReturnError</c> + the OpenID service's <c>PlainTextError</c> twin, <c>HtmlAuthPage</c>,
/// <c>MapWrite</c>) that both the OpenID and SAML flows need; consolidating them into one shared home
/// removes the duplication the OpenID extraction (#500) flagged, so the two flow services render identical
/// results from one definition rather than from a passed-in controller delegate. Pure static builders — they
/// construct <see cref="ActionResult"/>s directly (never touching <c>ControllerBase</c>), and the only side
/// effect is setting the defensive headers on the caller's response for the auth page.
/// </summary>
internal static class FlowResponses
{
    // The restrictive Permissions-Policy applied to both served HTML pages — the auth-completion page and
    // the browser-navigated error page in BrowserErrorPage — shared as one constant so the two cannot drift.
    // These pages run only a tiny inline script and need no powerful browser feature, so every listed feature
    // is denied with an empty allowlist. HSTS is deliberately NOT set per page: transport security for the
    // whole origin is the operator's reverse proxy / Jellyfin global responsibility (#756), not a per-response
    // plugin header.

    /// <summary>The restrictive Permissions-Policy header value shared by both served HTML pages (the auth-completion and browser-navigated error pages), denying every listed browser feature so the two cannot drift.</summary>
    internal const string ServedPagePermissionsPolicy =
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=(), autoplay=(), display-capture=()";

    /// <summary>
    /// A plain-text error result (<c>text/plain</c> with the given status), reproducing the controller's
    /// former <c>ReturnError</c> shape exactly so the non-outcome flow errors — a SAML signing-key failure,
    /// an OpenID PrepareLogin failure, a store-capacity refusal — stay byte-identical on the wire.
    /// </summary>
    /// <param name="code">The HTTP status code.</param>
    /// <param name="message">The plain-text body.</param>
    /// <returns>A <see cref="ContentResult"/> carrying the message as <c>text/plain</c>.</returns>
    internal static ContentResult PlainTextError(int code, string message) => new ContentResult
    {
        Content = message,
        ContentType = MediaTypeNames.Text.Plain,
        StatusCode = code,
    };

    /// <summary>
    /// Renders the intermediate auth page as HTML with defensive response headers. The page carries the
    /// one-time state token / signed assertion and completes the login from an inline script, so it must not
    /// be framed (clickjacking), MIME-sniffed, cached, or leak its URL via Referer. A strict
    /// Content-Security-Policy locks it to a single nonce'd inline script and style and same-origin
    /// fetch/frame; the same per-response nonce is threaded into the rendered page via the delegate.
    /// </summary>
    /// <param name="response">The response the defensive headers are written to.</param>
    /// <param name="render">The page renderer, taking the per-response CSP nonce and returning the HTML body.</param>
    /// <returns>A <see cref="ContentResult"/> carrying the rendered page as <c>text/html</c>.</returns>
    internal static ContentResult AuthPage(HttpResponse response, Func<string, string> render)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        response.Headers.ContentSecurityPolicy = AuthPageCsp.Build(nonce);
        response.Headers["X-Frame-Options"] = "DENY";
        response.Headers["X-Content-Type-Options"] = "nosniff";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers.CacheControl = "no-store";
        response.Headers["Permissions-Policy"] = ServedPagePermissionsPolicy;
        return new ContentResult
        {
            Content = render(nonce),
            ContentType = MediaTypeNames.Text.Html,
        };
    }

    /// <summary>
    /// The HTTP boundary for a manual link creation: maps the link service's closed write result to a
    /// response. The empty-key and unknown-provider refusals keep distinct bodies (the service checks the
    /// empty key first), and an unhandled result throws rather than silently returning a wrong status.
    /// </summary>
    /// <param name="result">The closed write-result variant from <c>CanonicalLinkService.TryCreateLink</c>.</param>
    /// <returns>The mapped <see cref="ActionResult"/>.</returns>
    internal static ActionResult MapCanonicalLinkWrite(CanonicalLinkWriteResult result) => result switch
    {
        CanonicalLinkWriteResult.Created => new NoContentResult(),
        CanonicalLinkWriteResult.EmptyKey => new BadRequestObjectResult("The SSO login did not resolve an identity."),
        CanonicalLinkWriteResult.UnknownProvider => new BadRequestObjectResult(LoginStatusMapper.NoMatchingProviderMessage),
        _ => throw new InvalidOperationException($"Unhandled canonical-link write result: {result}"),
    };
}
