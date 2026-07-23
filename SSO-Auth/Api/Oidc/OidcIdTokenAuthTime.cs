// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Reads the <c>auth_time</c> claim (a JSON number of seconds since the Unix epoch, OIDC Core §2) from the
/// RAW, already-validated id_token for the <c>max_age</c> freshness gate (#961), NOT from the redeemed
/// <c>result.User</c> principal — same reason as <see cref="OidcIdTokenAcr"/>: with <c>LoadProfile</c> on
/// (the default) OidcClient merges the UNSIGNED UserInfo response into <c>result.User</c>, so only the
/// id_token's own, signature-covered <c>auth_time</c> can be trusted to bound how long ago the user actually
/// authenticated.
/// </summary>
internal static class OidcIdTokenAuthTime
{
    /// <summary>
    /// The id_token's <c>auth_time</c> as seconds since the Unix epoch, or null when the token is
    /// absent/degenerate or carries no parseable <c>auth_time</c>. The token was validated by
    /// <see cref="OidcIdTokenValidator"/> before this runs; the guard and catches are defensive so a
    /// degenerate token can never turn the gate into a 500. A non-numeric or negative value reads as null
    /// (absent), so the caller's fail-closed max_age check refuses it rather than trusting a malformed claim.
    /// </summary>
    /// <param name="identityToken">The redeemed, already-validated id_token.</param>
    /// <returns>The <c>auth_time</c> in Unix seconds, or null.</returns>
    internal static long? Read(string? identityToken)
    {
        if (string.IsNullOrEmpty(identityToken))
        {
            return null;
        }

        try
        {
            var raw = new JsonWebToken(identityToken).Claims
                .LastOrDefault(c => string.Equals(c.Type, "auth_time", StringComparison.Ordinal))?.Value;

            if (string.IsNullOrEmpty(raw))
            {
                return null;
            }

            // auth_time is a JSON number; JsonWebToken surfaces it as its string form. Parse as a whole
            // number of seconds and reject anything outside the range DateTimeOffset.FromUnixTimeSeconds
            // accepts as malformed (absent) — including a negative value and an out-of-range positive one.
            // A provider that emits auth_time in MILLISECONDS (a common seconds/ms confusion) yields
            // ~1.7e12, which is past the upper bound; without this guard it would parse, reach IsFresh, and
            // throw ArgumentOutOfRangeException there — an uncaught 500 instead of the clean fail-closed
            // AuthTooOld deny this reader promises never to turn into a 500.
            const long MaxUnixSeconds = 253_402_300_799; // DateTimeOffset max (year 9999)
            return long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
                   && seconds >= 0 && seconds <= MaxUnixSeconds
                ? seconds
                : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (SecurityTokenException)
        {
            return null;
        }
    }
}
