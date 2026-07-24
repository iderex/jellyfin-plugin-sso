// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Api.Localization;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Conformance guard for the localization catalogs (#913). English is the invariant baseline that the
/// fallback chain terminates on, so every embedded catalog must be a flat string→string map with no blank
/// values, and every non-English catalog must carry EXACTLY the English key set — a missing key would blank
/// (it falls back, but a translator's catalog claiming completeness must be complete), an orphan key is dead
/// data. This is the standing drift guard for when the full language set lands (a later sub-unit).
/// </summary>
public class LocalizationCatalogTests
{
    private const string ResourcePrefix = "Jellyfin.Plugin.SSO_Auth.Localization.";
    private const string ResourceSuffix = ".json";
    private const string EnglishResource = ResourcePrefix + "en" + ResourceSuffix;

    // Any type in the plugin assembly anchors GetManifestResourceStream to the resource-bearing assembly.
    private static readonly Assembly PluginAssembly = typeof(SsoLocalizer).Assembly;

    private static IEnumerable<string> CatalogResources() =>
        PluginAssembly.GetManifestResourceNames()
            .Where(name => name.StartsWith(ResourcePrefix, System.StringComparison.Ordinal)
                && name.EndsWith(ResourceSuffix, System.StringComparison.Ordinal));

    private static Dictionary<string, string> ReadCatalog(string resourceName)
    {
        using var stream = PluginAssembly.GetManifestResourceStream(resourceName);
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream!);
        var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.ReadToEnd());
        Assert.NotNull(parsed);
        return parsed!;
    }

    [Fact]
    public void EnglishCatalog_ExistsAndIsNonEmpty()
    {
        Assert.Contains(EnglishResource, CatalogResources());
        Assert.NotEmpty(ReadCatalog(EnglishResource));
    }

    [Fact]
    public void EveryCatalog_HasNoBlankValues()
    {
        foreach (var resource in CatalogResources())
        {
            Assert.All(
                ReadCatalog(resource),
                entry => Assert.False(
                    string.IsNullOrWhiteSpace(entry.Value),
                    $"{resource}: key '{entry.Key}' has a blank value"));
        }
    }

    [Fact]
    public void EveryNonEnglishCatalog_HasExactlyTheEnglishKeySet()
    {
        var englishKeys = ReadCatalog(EnglishResource).Keys.ToHashSet();

        foreach (var resource in CatalogResources().Where(name => name != EnglishResource))
        {
            var keys = ReadCatalog(resource).Keys.ToHashSet();

            var missing = englishKeys.Except(keys).ToList();
            var orphan = keys.Except(englishKeys).ToList();

            Assert.True(missing.Count == 0, $"{resource}: missing keys: {string.Join(", ", missing)}");
            Assert.True(orphan.Count == 0, $"{resource}: orphan keys not in English: {string.Join(", ", orphan)}");
        }
    }
}
