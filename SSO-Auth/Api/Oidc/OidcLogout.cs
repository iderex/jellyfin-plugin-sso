// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api.Net;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Composes the OpenID Connect RP-initiated logout (<c>end_session</c>) URL the browser is redirected to
/// after the local Jellyfin session is ended (#727, SLO-2). Pure string logic so its two security controls
/// are unit-testable, because this URL navigates an authenticated user's browser to an external host.
/// </summary>
/// <remarks>
/// Two fail-closed defenses, both here:
/// <list type="bullet">
/// <item><description>
/// <b>Issuer host-binding.</b> The <c>end_session_endpoint</c> comes from the provider's own discovery
/// document, but a tampered/misconfigured discovery could point it at an attacker host. The endpoint is
/// therefore accepted only when its authority (scheme + host + port) equals the discovered issuer's — so a
/// logout can never navigate the browser anywhere but the identity provider itself (an open-redirect / SSRF
/// defense mirroring the login path's issuer checks). A mismatch yields <c>null</c> (local-only logout).
/// </description></item>
/// <item><description>
/// <b><c>post_logout_redirect_uri</c> allow-listing.</b> The return URL is included only when it normalizes
/// (via <see cref="CanonicalBaseUrl"/>) and sits at or under this server's canonical base — so logout can
/// only return the browser to this Jellyfin, never to an attacker site. An absent, malformed, or off-base
/// value is simply omitted; the logout still happens, without a redirect back.
/// </description></item>
/// </list>
/// A blank <c>end_session_endpoint</c> (the OP advertises none, or discovery was unreachable) yields
/// <c>null</c>, and the caller falls back to a local-only logout — a missing OP endpoint must never break it.
/// </remarks>
internal static class OidcLogout
{
    /// <summary>
    /// Builds the RP-initiated <c>end_session</c> URL, or <c>null</c> when RP-initiated logout is not possible
    /// or not safe (no endpoint, or the endpoint is not host-bound to the issuer) — the caller then performs a
    /// local-only logout.
    /// </summary>
    /// <param name="endSessionEndpoint">The OP's advertised <c>end_session_endpoint</c> (may be null/empty).</param>
    /// <param name="issuer">The discovered issuer (its authority host-binds the endpoint).</param>
    /// <param name="idTokenHint">The revealed captured <c>id_token</c> for the <c>id_token_hint</c> (may be null).</param>
    /// <param name="clientId">The provider's client id.</param>
    /// <param name="postLogoutRedirectUri">The desired post-logout return URL (allow-listed below; may be null).</param>
    /// <param name="canonicalBaseUrl">This server's canonical base, the allow-list root for the return URL.</param>
    /// <returns>The absolute end-session URL, or <c>null</c> for a local-only logout.</returns>
    internal static string? BuildEndSessionUrl(
        string? endSessionEndpoint,
        string? issuer,
        string? idTokenHint,
        string? clientId,
        string? postLogoutRedirectUri,
        string? canonicalBaseUrl)
    {
        if (string.IsNullOrWhiteSpace(endSessionEndpoint)
            || !Uri.TryCreate(endSessionEndpoint, UriKind.Absolute, out var endSession)
            || (!string.Equals(endSession.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                && !string.Equals(endSession.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)))
        {
            return null;
        }

        // Issuer host-binding: only redirect to the discovered issuer's own authority.
        if (string.IsNullOrWhiteSpace(issuer)
            || !Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri)
            || !IsSameAuthority(endSession, issuerUri))
        {
            return null;
        }

        var query = new System.Text.StringBuilder();

        if (!string.IsNullOrEmpty(idTokenHint))
        {
            Append(query, "id_token_hint", idTokenHint);
        }

        if (!string.IsNullOrEmpty(clientId))
        {
            Append(query, "client_id", clientId);
        }

        // Allow-list the return URL against this server's canonical base; omit it otherwise.
        if (IsAllowedPostLogoutRedirect(postLogoutRedirectUri, canonicalBaseUrl, out var allowed))
        {
            Append(query, "post_logout_redirect_uri", allowed);
        }

        // The endpoint may already carry a query (RFC 6749 §3.1); use '?' or '&' accordingly. When there is
        // nothing to add, return it unchanged.
        if (query.Length == 0)
        {
            return endSessionEndpoint;
        }

        var separator = string.IsNullOrEmpty(endSession.Query) ? "?" : "&";
        return endSessionEndpoint + separator + query;
    }

    // Two URIs share an authority when scheme, host (ordinal-ignore-case per DNS), and effective port match.
    private static bool IsSameAuthority(Uri a, Uri b)
        => string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase)
            && a.Port == b.Port;

    /// <summary>
    /// Whether a <c>post_logout_redirect_uri</c> candidate is allowed: it normalizes to a valid http(s) URL
    /// with no userinfo and sits at or under this server's <paramref name="canonicalBaseUrl"/> (same origin +
    /// path prefix), so a logout can only return the browser to this Jellyfin. The SINGLE source of truth for
    /// the return-URL rule — the runtime builder above and the save-time
    /// <c>ProviderConfigValidator.ValidatePostLogoutRedirectUri</c> both call it, so the config-page save
    /// rejects exactly the values the runtime would silently drop (no second, divergent URL rule). A blank
    /// candidate or blank base yields <see langword="false"/>.
    /// </summary>
    /// <param name="candidate">The desired post-logout return URL (may be null/blank).</param>
    /// <param name="canonicalBaseUrl">This server's canonical base, the allow-list root.</param>
    /// <param name="allowed">The accepted return URL when the result is <see langword="true"/>, else empty.</param>
    /// <returns><see langword="true"/> if the candidate is a return URL at or under the canonical base.</returns>
    internal static bool IsAllowedPostLogoutRedirect(string? candidate, string? canonicalBaseUrl, out string allowed)
    {
        allowed = string.Empty;
        if (string.IsNullOrWhiteSpace(candidate)
            || string.IsNullOrWhiteSpace(canonicalBaseUrl)
            || !Uri.TryCreate(candidate, UriKind.Absolute, out var candidateUri)
            || (!string.Equals(candidateUri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                && !string.Equals(candidateUri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
            || !string.IsNullOrEmpty(candidateUri.UserInfo)
            || !Uri.TryCreate(canonicalBaseUrl, UriKind.Absolute, out var baseUri))
        {
            return false;
        }

        // Same authority as the canonical base, and its path is under the base path — a prefix check on the
        // canonicalized origin+path, so a sibling host or a path-traversal cannot slip through.
        if (!IsSameAuthority(candidateUri, baseUri))
        {
            return false;
        }

        var basePath = baseUri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        var candidatePath = candidateUri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        if (!candidatePath.StartsWith(basePath, StringComparison.Ordinal))
        {
            return false;
        }

        allowed = candidate;
        return true;
    }

    private static void Append(System.Text.StringBuilder query, string name, string value)
    {
        if (query.Length > 0)
        {
            query.Append('&');
        }

        query.Append(name).Append('=').Append(Uri.EscapeDataString(value));
    }
}
