#nullable enable

using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Applies a redacted export document (<see cref="ConfigExportDocument"/>) onto the live configuration as a
/// MERGE (#161), reusing the config tier's own validation and server-managed-field preservation rather than
/// hand-rolling a merge that bypasses them. Two invariants make an import safe:
/// <list type="bullet">
/// <item>Fail-closed: the whole incoming set is validated through <see cref="ProviderConfigValidator"/>
/// BEFORE anything is mutated, so a malformed or hostile document is rejected without partially applying it.
/// Call this inside <c>MutateConfiguration</c>, which persists only when the mutation returns without
/// throwing, so a rejected import leaves the stored configuration untouched (atomic).</item>
/// <item>No accidental wipe: each imported provider is merged through <see cref="ServerManagedFields.Preserve(OidConfig, OidConfig)"/>
/// (and its SAML overload), so a redacted (blank) secret keeps the target's stored secret (#189) and the
/// server-managed links/issuers are re-injected from the target (#157/#186) as long as the provider's
/// identity is unchanged. The ONE deliberate exception is Preserve's OpenID repoint belt (#186): if the
/// imported document changes an existing OpenID provider's discovery endpoint or client id, that is treated
/// as a repoint to a potentially different identity provider, so its links/issuers are cleared and its
/// stored secret is not carried over — exactly as a config-page edit behaves, so a foreign IdP cannot
/// inherit the old one's account mappings. SAML links are preserved regardless.</item>
/// </list>
/// A merge (upsert), not a replace: a provider that exists only on the target is left untouched, and a
/// provider new to the target is added with its own empty link maps and a blank secret (fail closed until an
/// admin re-enters it — a redacted export cannot ship the secret).
/// </summary>
internal static class ConfigImport
{
    /// <summary>
    /// Validates and merges the export document into <paramref name="live"/>. Throws before any mutation on a
    /// document with an unsupported version, an absent payload, or an invalid provider, so the caller's
    /// <c>MutateConfiguration</c> persists nothing.
    /// </summary>
    /// <param name="live">The live configuration to merge into (mutated in place).</param>
    /// <param name="document">The import document.</param>
    /// <param name="resolveBreakGlass">
    /// Resolves a username to its <see cref="BreakGlassAdminState"/> for the SSO-only activation guard (#165);
    /// the controller supplies one backed by <c>IUserManager</c>. Null (or an unresolved account) makes the
    /// guard fail closed, so a document asserting SSO-only can never be imported without a provable safe
    /// admin.
    /// </param>
    /// <exception cref="ArgumentException">The document is unsupported, empty, carries an invalid provider, or asserts SSO-only with no surviving admin login path.</exception>
    internal static void Apply(PluginConfiguration live, ConfigExportDocument document, Func<string, BreakGlassAdminState>? resolveBreakGlass = null)
    {
        ArgumentNullException.ThrowIfNull(live);
        ArgumentNullException.ThrowIfNull(document);

        if (document.FormatVersion != ConfigExport.FormatVersion)
        {
            throw new ArgumentException(
                $"Unsupported configuration export format version {document.FormatVersion}; this plugin imports version {ConfigExport.FormatVersion}.");
        }

        var imported = document.Configuration
            ?? throw new ArgumentException("The configuration import document has no configuration payload.");

        // #165: the fail-closed SSO-only guard fires on the import persistence path too (T-T2). A document
        // asserting DisablePasswordLogin must prove a surviving admin password login path or the whole import
        // is rejected before anything is merged (the caller runs this inside MutateConfiguration, which
        // persists nothing when the lambda throws). The SSO-only globals themselves are NOT applied by an
        // import — like the rate-limit settings they are instance-local operational state with no
        // blank-means-keep signal, and enabling them also requires the per-user enforcement sweep that only
        // the SSO-Only endpoints (with IUserManager) can run — so import VALIDATES the assertion fail-closed
        // but leaves the target's own DisablePasswordLogin/BreakGlassAdminUsername untouched. An operator
        // enables the mode through the elevated, audited SSO-Only endpoints, not by import.
        if (imported.DisablePasswordLogin)
        {
            var breakGlass = imported.BreakGlassAdminUsername ?? string.Empty;
            SsoOnlyLoginGuard.AssertCanActivate(breakGlass, resolveBreakGlass?.Invoke(breakGlass) ?? default);
        }

        // 1. Validate the incoming providers fail-closed BEFORE touching the live configuration, exactly as
        //    the config-page save does (ProviderConfigStore.Save): a malformed Base URL override (#139), an
        //    unloadable SAML certificate/signing key (#206/#167), or a provider name new to this instance
        //    carrying URI-reserved/control characters (#336/#360) rejects the whole import. The live config is
        //    passed so a reserved-character name this instance already holds stays importable.
        ProviderConfigValidator.Validate(imported, live);

        // 2. Only now — with the document proven valid — merge each provider. ServerManagedFields.Preserve is
        //    the SAME re-injection the config-page save and OID/SAML Add use, so blank-means-keep for secrets
        //    and the server-managed link/issuer maps behave identically on every write path (#318). The
        //    global rate-limit settings (EnableRateLimit/RateLimitMaxAttempts/RateLimitWindowSeconds) are
        //    deliberately NOT imported: they are instance-local operational tuning (reverse-proxy dependent —
        //    see the config-page caution), and a scalar has no blank-means-keep signal, so importing them
        //    would let a foreign or partial document SILENTLY disable this instance's rate limiter (a DoS
        //    control) down to the deserialized defaults. The target keeps its own limiter configuration; an
        //    admin tunes it on the config page, not by import.
        MergeProviders(live.OidConfigs, imported.OidConfigs, ServerManagedFields.Preserve);
        MergeProviders(live.SamlConfigs, imported.SamlConfigs, ServerManagedFields.Preserve);
    }

    // Upserts each imported provider into the target map. An existing target provider has its server-managed
    // fields re-injected (Preserve carries the stored secret when the import's is blank, and the links/issuers
    // always) before the imported object replaces it, so nothing server-owned is wiped; a provider new to the
    // target is added as-is (its own empty link maps, a blank secret that fails the login closed until an
    // admin supplies one). A provider present only on the target is not in this loop, so it is left untouched
    // (merge, not replace). A null-valued incoming entry carries nothing to import and is skipped rather than
    // dereferenced (#538).
    private static void MergeProviders<T>(
        SerializableDictionary<string, T> live,
        SerializableDictionary<string, T> imported,
        Action<T, T> preserve)
        where T : ProviderConfigBase
    {
        if (imported is null)
        {
            return;
        }

        foreach (var kvp in imported)
        {
            if (kvp.Value is null)
            {
                continue;
            }

            if (live.TryGetValue(kvp.Key, out var existing) && existing is not null)
            {
                preserve(kvp.Value, existing);

                // NewPath is server-managed runtime state (which redirect-path spelling the last challenge
                // used), not an admin setting, and it is meaningless across instances — so on a merge into an
                // EXISTING provider we keep the target's own value rather than let the imported document
                // overwrite it. ServerManagedFields.Preserve deliberately leaves NewPath to round-trip on the
                // config-page save (same-instance), so this cross-instance carry-over is done here, on top of
                // Preserve, not by changing that shared rule. A provider NEW to the target keeps whatever the
                // import carried (defaults false); its next challenge sets it correctly.
                kvp.Value.NewPath = existing.NewPath;
            }

            live[kvp.Key] = kvp.Value;
        }
    }
}
