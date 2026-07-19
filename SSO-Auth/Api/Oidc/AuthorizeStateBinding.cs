using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Binds an in-flight OpenID authorize state to the browser that started it (#326). The authorize
/// <c>state</c> token is stored process-globally and, on its own, only proves knowledge of an
/// unguessable key — it does NOT tie the callback to the user-agent that initiated authorization, the
/// role RFC 6749 section 10.12 and the OAuth 2.0 Security BCP assign it. Without that tie an attacker
/// can start a flow, obtain their own code, and lure a victim to the callback so the victim's browser
/// is silently signed in as the attacker (forced login / session fixation). The challenge sets a
/// browser-scoped cookie carrying a fresh random id and records the same id on the state; the callbacks
/// require the cookie to match before honoring the state, so a state started in one browser cannot be
/// completed in another.
/// </summary>
internal static class AuthorizeStateBinding
{
    /// <summary>
    /// The browser-binding cookie name. The <c>__Host-</c> prefix makes the browser enforce that the
    /// cookie is Secure, host-only (no <c>Domain</c>), and <c>Path=/</c> — so a sibling subdomain under
    /// a shared parent domain cannot plant a same-named <c>Domain</c>-scoped cookie to poison the binding
    /// check (cookie tossing). The prefix requires HTTPS, which every real OpenID deployment already uses.
    /// </summary>
    internal const string CookieName = "__Host-sso_oid_state_binding";

    /// <summary>
    /// The SAML browser-binding cookie name (#415). Separate from the OpenID cookie so the two flows
    /// cannot cross-satisfy each other's binding check; the <c>__Host-</c> prefix carries the same
    /// cookie-tossing defense described for <see cref="CookieName"/>. Checked at the same-origin
    /// session-mint endpoint (SAML/auth), where a <c>SameSite=Lax</c> cookie is sent — the ACS POST
    /// from the identity provider is cross-site and would not carry it.
    /// </summary>
    internal const string SamlCookieName = "__Host-sso_saml_state_binding";

    /// <summary>A fresh 256-bit CSPRNG binding id, hex-encoded (URL- and cookie-safe).</summary>
    /// <returns>The new binding id.</returns>
    internal static string NewId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// Whether a presented binding id matches the one recorded on the state. Fail closed: a state with
    /// no recorded id, or a missing/mismatched presented id, does not match. The stored id is an
    /// unguessable server-minted value, so an ordinal compare carries the same risk profile as the
    /// existing state-token lookup.
    /// </summary>
    /// <param name="storedBindingId">The id recorded on the stored state.</param>
    /// <param name="presentedBindingId">The id presented by the callback (the cookie value).</param>
    /// <returns>True only when both are present and equal.</returns>
    internal static bool Matches(string storedBindingId, string presentedBindingId)
        => !string.IsNullOrEmpty(storedBindingId)
           && string.Equals(storedBindingId, presentedBindingId, StringComparison.Ordinal);

    /// <summary>
    /// The cookie policy for the binding cookie. <c>Secure</c> is always set: every real OpenID
    /// deployment is HTTPS at the browser edge (identity providers reject non-localhost <c>http</c>
    /// redirect URIs), so the browser stores and sends the cookie even when a TLS-terminating proxy
    /// forwards plain HTTP to the app — and marking it Secure is correct there, where a scheme-tracking
    /// flag would wrongly under-set it. <c>SameSite=Lax</c> is required, not Strict: the IdP returns the
    /// browser to the callback via a top-level cross-site navigation, on which Lax cookies are sent but
    /// Strict cookies are not — Strict would suppress the cookie and fail every login. Scoped to the
    /// whole app and bounded to the state's lifetime.
    /// </summary>
    /// <param name="lifetime">How long the cookie should live, matching the authorize-state lifetime.</param>
    /// <returns>The cookie options.</returns>
    internal static CookieOptions CookieOptions(TimeSpan lifetime) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        MaxAge = lifetime,
    };
}
