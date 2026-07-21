// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Builds the redacted, importable configuration export document (#161). It does NOT re-implement any
/// redaction: the plugin configuration already withholds its secrets and server-managed link maps at the
/// JSON boundary (the <see cref="WriteOnlySecretConverter"/> on the three secret fields, #189, and
/// <c>[JsonIgnore]</c> on the canonical-link maps, #157/#186), so serializing the snapshot this builds is
/// redacted by construction — the export reflects the same withholding an <c>OID/Get</c> response already
/// does, reused rather than duplicated. This type only detaches the live configuration so the JSON
/// formatter (which runs after the config lock is released) serializes a stable snapshot rather than a
/// live, concurrently-mutated object.
/// </summary>
internal static class ConfigExport
{
    /// <summary>
    /// The current export/import document format version. Bumped only on a breaking change to the document
    /// shape; the import rejects any other version fail-closed (<see cref="ConfigImport.Apply"/>).
    /// </summary>
    internal const int FormatVersion = 1;

    /// <summary>
    /// Builds the export document from the live configuration. Call it under the config lock (through
    /// <c>ReadConfiguration</c>) so the snapshot is taken atomically; the returned document holds a detached
    /// copy of the provider maps, so the JSON formatter serializing it later cannot tear against a concurrent
    /// provider add/remove.
    /// </summary>
    /// <param name="live">The live plugin configuration to snapshot.</param>
    /// <returns>The redacted export document.</returns>
    internal static ConfigExportDocument Build(PluginConfiguration live)
    {
        ArgumentNullException.ThrowIfNull(live);
        return new ConfigExportDocument
        {
            FormatVersion = FormatVersion,
            Configuration = Snapshot(live),
        };
    }

    // A fresh configuration carrying the live scalars and shallow copies of the provider maps. The provider
    // objects are shared (not cloned): their secrets and link maps are withheld by the JSON converters, and
    // the only in-place write on the login hot path is the NewPath scalar flip — which cannot tear a JSON
    // serialization — so a shallow copy is the same safe snapshot SSOController.SnapshotConfigs relies on
    // (#157/F-10).
    private static PluginConfiguration Snapshot(PluginConfiguration live) => new()
    {
        EnableRateLimit = live.EnableRateLimit,
        RateLimitMaxAttempts = live.RateLimitMaxAttempts,
        RateLimitWindowSeconds = live.RateLimitWindowSeconds,
        OidConfigs = ShallowCopy(live.OidConfigs),
        SamlConfigs = ShallowCopy(live.SamlConfigs),
    };

    private static SerializableDictionary<string, T> ShallowCopy<T>(SerializableDictionary<string, T> source)
    {
        var copy = new SerializableDictionary<string, T>();
        if (source is not null)
        {
            foreach (var kvp in source)
            {
                copy[kvp.Key] = kvp.Value;
            }
        }

        return copy;
    }
}
