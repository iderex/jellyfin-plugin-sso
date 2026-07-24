// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Net.Http.Headers;

namespace Jellyfin.Plugin.SSO_Auth.Api.Localization;

/// <summary>
/// Resolves the best available culture from a request's Accept-Language header (#913). It parses the
/// weighted language list, orders by q-value (a missing q defaults to 1.0 per RFC 9110; equal q keeps the
/// header's own order), and returns the highest-preference tag that has a loaded catalog — an exact BCP-47
/// tag or its base language, so a "de-CH" preference is served by a "de" catalog. It returns null when the
/// header is absent, malformed, or names no available language, so the caller falls back to English through
/// the <see cref="SsoLocalizer"/> chain. A "q=0" entry explicitly rejects a language and a "*" wildcard
/// expresses no specific preference — both are skipped rather than matched.
/// </summary>
internal static class AcceptLanguage
{
    /// <summary>
    /// Picks the best loaded culture for the given Accept-Language header value, choosing among the
    /// catalogs currently loaded by <see cref="SsoLocalizer"/>.
    /// </summary>
    /// <param name="headerValue">The raw Accept-Language header (may hold several comma-separated, weighted tags).</param>
    /// <returns>The best available culture, or null to fall back to English.</returns>
    internal static string? Resolve(string? headerValue) => Resolve(headerValue, SsoLocalizer.AvailableCultures);

    /// <summary>
    /// Picks the best culture in <paramref name="available"/> for the given Accept-Language header value.
    /// </summary>
    /// <param name="headerValue">The raw Accept-Language header (may hold several comma-separated, weighted tags).</param>
    /// <param name="available">The loaded cultures to choose among, lower-invariant (see <see cref="SsoLocalizer.AvailableCultures"/>).</param>
    /// <returns>The best available culture, or null to fall back to English.</returns>
    internal static string? Resolve(string? headerValue, IReadOnlyCollection<string> available)
    {
        if (string.IsNullOrWhiteSpace(headerValue)
            || !StringWithQualityHeaderValue.TryParseList(new[] { headerValue }, out var parsed)
            || parsed is not { Count: > 0 })
        {
            return null;
        }

        // q=0 explicitly rejects a language; drop it. OrderByDescending is stable, so equal-q tags keep the
        // header's own left-to-right preference order.
        var ranked = parsed
            .Where(value => (value.Quality ?? 1.0) > 0.0)
            .OrderByDescending(value => value.Quality ?? 1.0);

        foreach (var value in ranked)
        {
            var tag = value.Value.ToString().ToLowerInvariant();
            if (tag.Length == 0 || string.Equals(tag, "*", StringComparison.Ordinal))
            {
                continue;
            }

            if (available.Contains(tag))
            {
                return tag;
            }

            var dash = tag.IndexOf('-', StringComparison.Ordinal);
            if (dash > 0 && available.Contains(tag[..dash]))
            {
                return tag[..dash];
            }
        }

        return null;
    }
}
