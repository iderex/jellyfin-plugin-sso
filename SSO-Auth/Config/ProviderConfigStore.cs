using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api;
using MediaBrowser.Model.Plugins;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Owns every read and write of the plugin configuration behind one lock (#318): locked reads and
/// atomic read-modify-writes of the live configuration, plus the validated save pipeline
/// (validate, preserve server-managed fields, persist, audit) for a replacement configuration such
/// as an admin config-page save. Extracted from <see cref="SSOPlugin"/>, which keeps only a thin
/// delegating facade; persistence itself stays with the plugin base class and is reached through
/// the injected persist delegate.
/// </summary>
internal sealed class ProviderConfigStore
{
    // Serializes every read-modify-write of the plugin configuration so concurrent mutations
    // (notably first-logins each writing a canonical link) cannot lose one another's updates.
    // Static on purpose: it keeps the process-wide serialization of the old SSOPlugin lock, so two
    // plugin instances (tests construct several; production has one) can never interleave writes.
    // It becomes an instance field once the store is a DI singleton (#318 step 9).
    private static readonly System.Threading.Lock Sync = new();

    private readonly Func<PluginConfiguration> _live;
    private readonly Action<BasePluginConfiguration> _persist;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ProviderConfigStore"/> class.
    /// </summary>
    /// <param name="live">Returns the live plugin configuration (the plugin's lazily loaded <c>Configuration</c>).</param>
    /// <param name="persist">Persists a configuration through the plugin base class (<c>base.UpdateConfiguration</c>).</param>
    /// <param name="logger">The logger (used to audit insecure-option saves, #140).</param>
    internal ProviderConfigStore(Func<PluginConfiguration> live, Action<BasePluginConfiguration> persist, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(live);
        ArgumentNullException.ThrowIfNull(persist);
        _live = live;
        _persist = persist;
        _logger = logger;
    }

    /// <summary>
    /// Reads a value from the live configuration under the same lock as <see cref="Mutate(Action{PluginConfiguration})"/>,
    /// so a read cannot tear against a concurrent write of a (non-thread-safe) configuration collection.
    /// </summary>
    /// <typeparam name="T">The value read.</typeparam>
    /// <param name="read">The read to perform against the live configuration.</param>
    /// <returns>The value returned by <paramref name="read"/>.</returns>
    public T Read<T>(Func<PluginConfiguration, T> read)
    {
        ArgumentNullException.ThrowIfNull(read);
        lock (Sync)
        {
            return read(_live());
        }
    }

    /// <summary>
    /// Applies a mutation to the live configuration under a single lock and persists it, so a
    /// read-modify-write cannot race another and lose its update.
    /// </summary>
    /// <param name="mutate">The mutation to apply to the live configuration.</param>
    public void Mutate(Action<PluginConfiguration> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        lock (Sync)
        {
            var configuration = _live();
            mutate(configuration);

            // Persists directly instead of routing through Save: the object being written IS the live
            // one, so Save's fresh-config pipeline (validate/preserve/audit) would be skipped by its
            // identity guard anyway — same observable behavior, without the reentrant detour.
            _persist(configuration);
        }
    }

    /// <summary>
    /// Applies a mutation that returns a result (e.g. whether a removal changed anything) under the
    /// same single lock and persists it, so the read-modify-write and the result observation are one
    /// atomic operation.
    /// </summary>
    /// <typeparam name="T">The value the mutation returns.</typeparam>
    /// <param name="mutate">The mutation to apply to the live configuration.</param>
    /// <returns>The value returned by <paramref name="mutate"/>.</returns>
    public T Mutate<T>(Func<PluginConfiguration, T> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        lock (Sync)
        {
            var configuration = _live();
            var result = mutate(configuration);
            _persist(configuration);
            return result;
        }
    }

    /// <summary>
    /// Persists a replacement configuration, re-injecting server-managed fields from the live
    /// configuration first (#157). The admin settings page saves through this path (Jellyfin core's
    /// UpdatePluginConfiguration) with a snapshot taken at page load, so a canonical link created by a
    /// login since then would be absent from the posted config; re-injecting the live links stops the
    /// save from wiping them. Takes the same lock as <see cref="Mutate(Action{PluginConfiguration})"/>
    /// and skips the copy when the incoming object is the live one.
    /// </summary>
    /// <param name="configuration">The configuration to persist.</param>
    public void Save(BasePluginConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        List<(string Provider, IReadOnlyList<string> Options)> insecureToAudit = null;
        lock (Sync)
        {
            if (configuration is PluginConfiguration incoming && !ReferenceEquals(incoming, _live()))
            {
                // Reject the save fail-closed before anything is persisted if a base-URL override is
                // malformed (#139), a SAML signing certificate is not loadable (#206), or a NEWLY
                // registered provider name contains control, URI-reserved, or backslash characters
                // (#336/#360 — the live config is passed so names it already holds stay saveable). This validates the config-page save
                // (a fresh incoming config); the OID/SAML Add endpoints write through Mutate (the live
                // object, so this branch is skipped) and validate their own incoming provider at the
                // controller via the Reject* guards. Login-path writes (canonical links) also reuse the
                // live object and are intentionally not revalidated here, so a slow/bad override can
                // never throw on the login path.
                ProviderConfigValidator.Validate(incoming, _live());

                ServerManagedFields.Preserve(incoming, _live());

                // Snapshot which providers were saved with an insecure option (#140) while under the
                // lock, but emit the warnings AFTER releasing it (below) — logging must not run inside
                // the global config lock, where a slow provider would block concurrent config access.
                insecureToAudit = CollectInsecureOptions(incoming);
            }

            _persist(configuration);
        }

        // Outside the lock, and after the save is durably persisted: a slow or misbehaving logging
        // provider can neither block config reads/writes nor turn a completed save into a failure.
        if (insecureToAudit != null && _logger != null)
        {
            foreach (var (provider, options) in insecureToAudit)
            {
                SsoAudit.InsecureOptionsEnabled(_logger, "OpenID", provider, options);
            }
        }
    }

    // Snapshots, under the caller's lock, the OpenID providers saved with a security check disabled
    // (#140), as (provider, enabled-option-names) pairs. Pure read: it does not log, so the audit
    // warnings can be emitted after the config lock is released. Only the admin save path reaches
    // here (a fresh incoming config), so it fires once per save, not per login.
    private static List<(string Provider, IReadOnlyList<string> Options)> CollectInsecureOptions(PluginConfiguration incoming)
    {
        var records = new List<(string, IReadOnlyList<string>)>();
        if (incoming.OidConfigs == null)
        {
            return records;
        }

        foreach (var kvp in incoming.OidConfigs)
        {
            var insecure = OidcInsecureToggles.Enabled(kvp.Value);
            if (insecure.Count > 0)
            {
                records.Add((kvp.Key, insecure));
            }
        }

        return records;
    }
}
