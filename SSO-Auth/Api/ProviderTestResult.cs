using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The admin-facing result of a provider Test-connection probe (#163): whether the probe passed, a short
/// actionable headline, and a list of non-secret detail lines (issuer, endpoints, JWKS reachability, or the
/// SAML certificate's public facts). It NEVER carries a secret — no <c>OidSecret</c>, no signing-key/DEK
/// material — and its <see cref="Message"/> stays generic about sensitive values (e.g. "authentication
/// failed", not the secret). Serialized to the admin UI as JSON; the page renders every field with
/// <c>textContent</c>/<c>createElement</c> so a reflected provider string cannot inject markup.
/// </summary>
/// <param name="Ok">Whether the probe's core check passed (discovery readable, or the SAML certificate parses).</param>
/// <param name="Message">A short, actionable headline safe to show an administrator.</param>
/// <param name="Details">Non-secret detail lines describing what the probe observed.</param>
internal sealed record ProviderTestResult(bool Ok, string Message, IReadOnlyList<string> Details)
{
    /// <summary>A failed probe with an actionable, secret-free message and no details.</summary>
    /// <param name="message">The actionable failure headline.</param>
    /// <returns>A failed result.</returns>
    internal static ProviderTestResult Failure(string message) =>
        new(false, message, Array.Empty<string>());

    /// <summary>A passing probe carrying the non-secret facts the administrator can confirm the config against.</summary>
    /// <param name="message">The success headline.</param>
    /// <param name="details">The non-secret detail lines.</param>
    /// <returns>A passing result.</returns>
    internal static ProviderTestResult Success(string message, IReadOnlyList<string> details) =>
        new(true, message, details);
}
