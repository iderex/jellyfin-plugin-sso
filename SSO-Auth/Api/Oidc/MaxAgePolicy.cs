// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The <c>max_age</c> freshness check (#961). When a provider configures <c>MaxAge</c>, the authorization
/// request carries <c>max_age=&lt;n&gt;</c> (OidcFrontChannelParameters), and OIDC Core §3.1.2.1 then
/// REQUIRES the id_token to carry <c>auth_time</c> and expects the RP to verify the user authenticated no
/// longer than <c>max_age</c> seconds ago. Fail-closed: a MISSING <c>auth_time</c> (a provider that ignored
/// <c>max_age</c>) or an <c>auth_time</c> older than the window is refused — otherwise a stale session
/// silently satisfies a forced-reauthentication requirement it did not meet. The five-minute skew
/// tolerance mirrors the id_token / SAML-assertion lifetime checks so a small IdP/SP clock difference
/// does not spuriously reject a genuinely fresh login.
/// </summary>
internal static class MaxAgePolicy
{
    /// <summary>Symmetric clock-skew tolerance, matching the SAML/id_token lifetime checks.</summary>
    internal static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether an id_token's <paramref name="authTimeUnixSeconds"/> satisfies a configured <paramref name="maxAgeSeconds"/>.
    /// </summary>
    /// <param name="authTimeUnixSeconds">The id_token's <c>auth_time</c> (Unix seconds), or null when absent/malformed.</param>
    /// <param name="maxAgeSeconds">The configured <c>max_age</c> in seconds (non-negative).</param>
    /// <param name="nowUtc">The current UTC instant.</param>
    /// <returns>
    /// <see langword="true"/> only when <paramref name="authTimeUnixSeconds"/> is present and the user
    /// authenticated at most <paramref name="maxAgeSeconds"/> (plus skew) ago; <see langword="false"/> when
    /// it is absent or too old (fail closed).
    /// </returns>
    internal static bool IsFresh(long? authTimeUnixSeconds, int maxAgeSeconds, DateTimeOffset nowUtc)
    {
        if (authTimeUnixSeconds is not long authTime)
        {
            // max_age was requested but the provider returned no auth_time — treat as not fresh, per the
            // fail-closed contract: an ignored max_age must not pass.
            return false;
        }

        var authenticatedAt = DateTimeOffset.FromUnixTimeSeconds(authTime);

        // A future auth_time beyond the skew is not a genuine "recent authentication" — reject it rather
        // than let a clock-forward IdP satisfy the window indefinitely.
        if (authenticatedAt > nowUtc + ClockSkew)
        {
            return false;
        }

        var age = nowUtc - authenticatedAt;
        return age <= TimeSpan.FromSeconds(maxAgeSeconds) + ClockSkew;
    }
}
