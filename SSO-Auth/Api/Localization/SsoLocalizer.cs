// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Localization;

/// <summary>
/// Minimal string localizer for the plugin's user-facing served surfaces, in Jellyfin's own idiom
/// (#913). It loads flat per-culture key→value JSON catalogs — embedded resources named by BCP-47
/// culture, the shape of Jellyfin core's
/// <c>Emby.Server.Implementations/Localization/Core/&lt;culture&gt;.json</c> — and resolves a key
/// through a fallback chain that never blanks: the requested culture, then its base language, then
/// English (the invariant fallback), then the key itself. The plugin cannot register its catalogs into
/// core's <c>ILocalizationManager</c> (core owns that surface), so it keeps its own; the format and the
/// <c>GetString(key, culture)</c> lookup mirror Jellyfin so a translator sees a familiar file.
///
/// Catalogs are DATA and are treated fail-closed: a catalog that is missing, is not a JSON object, is not
/// a flat string→string map, or carries a null value is skipped at load (its keys fall through the chain
/// to English), never fatal. No user-controlled value is ever used as a key.
/// </summary>
internal static class SsoLocalizer
{
    /// <summary>
    /// The invariant fallback culture. Every key is guaranteed to exist here, so the chain never blanks.
    /// </summary>
    internal const string FallbackCulture = "en";

    private const string ResourcePrefix = "Jellyfin.Plugin.SSO_Auth.Localization.";
    private const string ResourceSuffix = ".json";

    // culture (lower-invariant) -> (key -> non-null value). Immutable snapshot built once at load.
    private static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> CatalogsByCulture = Load();

    /// <summary>Gets the BCP-47 cultures that loaded a valid catalog (lower-invariant). For tests/diagnostics.</summary>
    internal static IReadOnlyCollection<string> AvailableCultures => CatalogsByCulture.Keys.ToArray();

    /// <summary>
    /// Gets the localized value for <paramref name="key"/> in <paramref name="culture"/>, falling back to
    /// the base language, then English, then the key itself. Never returns null or empty for a key present
    /// in the English catalog; returns the key verbatim when it is defined nowhere.
    /// </summary>
    /// <param name="key">The catalog key. Never a user-controlled value.</param>
    /// <param name="culture">The requested BCP-47 culture, or null/empty to use the fallback.</param>
    /// <returns>The best available translation, or the key itself.</returns>
    internal static string GetString(string key, string? culture)
    {
        ArgumentNullException.ThrowIfNull(key);

        foreach (var candidate in CultureFallbackChain(culture))
        {
            if (CatalogsByCulture.TryGetValue(candidate, out var catalog)
                && catalog.TryGetValue(key, out var value))
            {
                return value;
            }
        }

        // Defined nowhere: return the key so a missing translation is visible, never a blank.
        return key;
    }

    // The requested culture, then its base language ("de-CH" -> "de"), then English — lower-invariant,
    // de-duplicated in order.
    private static IEnumerable<string> CultureFallbackChain(string? culture)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var candidate in Candidates(culture))
        {
            var normalized = candidate.ToLowerInvariant();
            if (seen.Add(normalized))
            {
                yield return normalized;
            }
        }
    }

    private static IEnumerable<string> Candidates(string? culture)
    {
        if (!string.IsNullOrWhiteSpace(culture))
        {
            var trimmed = culture.Trim();
            yield return trimmed;

            var dash = trimmed.IndexOf('-', StringComparison.Ordinal);
            if (dash > 0)
            {
                yield return trimmed[..dash];
            }
        }

        yield return FallbackCulture;
    }

    private static Dictionary<string, IReadOnlyDictionary<string, string>> Load()
    {
        var result = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal);
        var assembly = typeof(SsoLocalizer).Assembly;

        foreach (var resourceName in assembly.GetManifestResourceNames())
        {
            if (!resourceName.StartsWith(ResourcePrefix, StringComparison.Ordinal)
                || !resourceName.EndsWith(ResourceSuffix, StringComparison.Ordinal))
            {
                continue;
            }

            var culture = resourceName[ResourcePrefix.Length..^ResourceSuffix.Length].ToLowerInvariant();
            var catalog = TryReadCatalog(assembly, resourceName);
            if (catalog != null)
            {
                result[culture] = catalog;
            }
        }

        return result;
    }

    // A catalog is DATA: a stream that is missing, is not a JSON object, is not a flat string->string map,
    // or carries a null value is skipped (its keys fall through the chain to English), never fatal.
    private static Dictionary<string, string>? TryReadCatalog(Assembly assembly, string resourceName)
    {
        try
        {
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null)
            {
                return null;
            }

            using var reader = new StreamReader(stream);
            var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.ReadToEnd());
            if (parsed == null || parsed.Values.Any(value => value == null))
            {
                return null;
            }

            return parsed;
        }
        catch (JsonException)
        {
            // Malformed catalog (not an object, wrong value shape): fail closed to the fallback chain.
            return null;
        }
    }
}
