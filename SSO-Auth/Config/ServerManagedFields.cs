using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Re-injects the server-managed provider fields a save must not be allowed to clear (#157/#189).
/// The whole-config <see cref="Preserve(PluginConfiguration, PluginConfiguration)"/> runs inside the
/// config-page save pipeline (<see cref="ProviderConfigStore.Save"/>); the per-provider overloads are
/// the single shared rule every admin write path converges on, so a field added to them is preserved
/// on every door by construction (#318). <c>NewPath</c> is documented as server-managed too but is
/// deliberately not preserved here: it round-trips through JSON, so a posted config carries the live
/// value (see <see cref="ProviderConfigBase.NewPath"/>).
/// </summary>
internal static class ServerManagedFields
{
    /// <summary>
    /// Copies the server-managed fields from <paramref name="live"/> into <paramref name="incoming"/>,
    /// so a save built from a stale client snapshot cannot clear them. Only providers present in
    /// <paramref name="incoming"/> are touched (a deleted provider stays deleted; a newly added one
    /// keeps its own empty map). Two kinds of field are preserved: the per-provider canonical links
    /// (always server-owned, #157), and the write-only secrets (the OpenID client secret #189, the SAML
    /// signing key #167) — the latter only when the incoming value is blank, since a secret is withheld
    /// from JSON responses so a save that did not set a new one arrives empty and must keep the stored
    /// value (a non-blank incoming value is an intentional rotation and is left as-is).
    /// </summary>
    /// <param name="incoming">The configuration about to be persisted.</param>
    /// <param name="live">The current live configuration to read server-managed values from.</param>
    internal static void Preserve(PluginConfiguration incoming, PluginConfiguration live)
    {
        Preserve(incoming?.OidConfigs, live?.OidConfigs, Preserve);
        Preserve(incoming?.SamlConfigs, live?.SamlConfigs, Preserve);

        // SSO-only login state is server-managed (#165): the config-page save must not be able to flip
        // DisablePasswordLogin or repoint the break-glass admin. The plugin-config PUT carries no user
        // context, so it cannot run the last-admin guard or the enforcement sweep — re-injecting the live
        // values here freezes the pair on this path, leaving the RequiresElevation-gated SSO-Only endpoints
        // (which DO run the guard, the sweep, and the audit) as the only way to change them. This is
        // stronger than re-validating an incoming toggle: an unsafe (or accidental) value can never be
        // introduced via the config-page save at all. A raw config.xml edit is the documented total-lockout
        // recovery path and is out of the plugin's reach either way (SSO-ONLY-LOGIN-DESIGN.md §3 option B).
        if (incoming is not null && live is not null)
        {
            incoming.DisablePasswordLogin = live.DisablePasswordLogin;
            incoming.BreakGlassAdminUsername = live.BreakGlassAdminUsername;
            incoming.SsoOnlyRepointedUserIds = live.SsoOnlyRepointedUserIds;

            // The Single Logout session store is server-managed runtime state (#727): it is withheld from
            // JSON, so a config-page PUT arrives with it empty. Re-inject the live map so a save never wipes
            // the captured sessions (which would strand every live session's id_token_hint) and a config PUT
            // can neither read the stored id_tokens nor forge session entries — the login/logout paths are the
            // only writers, exactly as for the SSO-only bookkeeping above.
            incoming.LogoutSessions = live.LogoutSessions;
        }
    }

    // One generic loop for both protocols — the maps differ only in the per-provider overload the method
    // group resolves to. Only providers present in BOTH maps are touched (a deleted provider stays
    // deleted; a newly added one keeps its own empty map), and a null map on either side (a legacy store,
    // a partial post) preserves nothing rather than NRE the save.
    private static void Preserve<T>(SerializableDictionary<string, T> incoming, SerializableDictionary<string, T> live, Action<T, T> preserveProvider)
        where T : ProviderConfigBase
    {
        if (incoming is null || live is null)
        {
            return;
        }

        foreach (var kvp in live)
        {
            if (incoming.TryGetValue(kvp.Key, out var incomingProvider))
            {
                preserveProvider(incomingProvider, kvp.Value);
            }
        }
    }

    // Links + issuer bindings + secret: an OpenID provider carries these server-managed fields
    // (#157/#189/#186).
    internal static void Preserve(OidConfig incoming, OidConfig live)
    {
        // A null provider entry (a malformed Add before #350, or a legacy store) carries no
        // server-managed fields; skip it rather than NRE the whole config-page save.
        if (incoming is null || live is null)
        {
            return;
        }

        // The repoint belt (#186): an OidEndpoint change re-identifies the provider — a different discovery
        // URL is potentially a different identity provider — exactly as ResolveUpdatedSecret treats it when
        // it drops the client secret on the same change. Carrying the accumulated sub-keyed links across
        // such a change is the silent-mapping this issue closes, so DROP them (and their issuer bindings)
        // rather than preserve them. This protects even un-stamped legacy links (a user who has not logged
        // in since the upgrade) against a post-upgrade repoint, which the per-login issuer gate alone could
        // not. While the endpoint is UNCHANGED (the common save), both maps are carried over verbatim so
        // existing links keep working (issue #186 criterion 3). The complementary per-login issuer gate
        // covers a repoint that keeps the SAME discovery URL (a swapped IdP behind it), which this string
        // compare cannot detect.
        var endpointUnchanged = string.Equals(incoming.OidEndpoint, live.OidEndpoint, StringComparison.Ordinal);
        incoming.CanonicalLinks = endpointUnchanged ? live.CanonicalLinks : new SerializableDictionary<string, Guid>();
        incoming.CanonicalLinkIssuers = endpointUnchanged ? live.CanonicalLinkIssuers : new SerializableDictionary<string, string>();

        incoming.OidSecret = ResolveUpdatedSecret(incoming, live);
    }

    // Links + the write-only signing key: a SAML provider carries the server-managed link map (#157) and,
    // since #167, an optional service-provider signing key that is withheld from JSON like the OpenID
    // secret, so a save that did not rotate it arrives blank and must keep the stored value.
    internal static void Preserve(SamlConfig incoming, SamlConfig live)
    {
        if (incoming is null || live is null)
        {
            return;
        }

        incoming.CanonicalLinks = live.CanonicalLinks;
        incoming.SamlSigningKeyPfx = ResolveUpdatedSigningKey(incoming, live);

        // The rollover signing key (#491) is withheld from JSON exactly like the primary, so a config-page
        // save arrives with it blank and must keep the stored value; a non-blank incoming value is an
        // intentional rotation of the overlap key and wins. Same no-identity-guard reasoning as the primary.
        incoming.SamlRolloverSigningKeyPfx = ResolveUpdatedRolloverSigningKey(incoming, live);
    }

    /// <summary>
    /// Decides which service-provider signing key an updated SAML provider should keep (#167). A non-blank
    /// incoming key is an explicit rotation and wins; a blank one keeps the stored key, so a config-page
    /// save (which never carries the withheld key) does not wipe it. Unlike the OpenID client secret this
    /// has no provider-identity guard: the key is never transmitted anywhere — it is used only to sign a
    /// public AuthnRequest locally — so repointing the endpoint cannot exfiltrate it, and carrying it over
    /// keeps a working signed-login provider from breaking on an unrelated edit.
    /// </summary>
    /// <param name="incoming">The provider config about to be persisted.</param>
    /// <param name="live">The current live provider config.</param>
    /// <returns>The signing key to persist for the updated provider.</returns>
    internal static string ResolveUpdatedSigningKey(SamlConfig incoming, SamlConfig live)
        => string.IsNullOrWhiteSpace(incoming.SamlSigningKeyPfx) ? live.SamlSigningKeyPfx : incoming.SamlSigningKeyPfx;

    /// <summary>
    /// Decides which OPTIONAL rollover signing key an updated SAML provider should keep (#491), the exact
    /// same blank-keeps-stored / non-blank-rotates rule as <see cref="ResolveUpdatedSigningKey"/>: the
    /// rollover key is withheld from JSON, so a config-page save arrives blank and must keep the stored
    /// value rather than silently ending the overlap window, while an explicit non-blank value stages a new
    /// overlap certificate. Like the primary it is never transmitted (publish-only, used to export its
    /// public certificate into metadata), so it carries no provider-identity guard.
    /// </summary>
    /// <param name="incoming">The provider config about to be persisted.</param>
    /// <param name="live">The current live provider config.</param>
    /// <returns>The rollover signing key to persist for the updated provider.</returns>
    internal static string ResolveUpdatedRolloverSigningKey(SamlConfig incoming, SamlConfig live)
        => string.IsNullOrWhiteSpace(incoming.SamlRolloverSigningKeyPfx) ? live.SamlRolloverSigningKeyPfx : incoming.SamlRolloverSigningKeyPfx;

    /// <summary>
    /// Decides which OpenID client secret an updated provider should keep (#189), the single rule
    /// shared by the config-page save and <c>OID/Add</c>. A non-blank incoming secret is an explicit
    /// rotation and wins. A blank one means "keep the stored secret" — but ONLY while the provider
    /// identity (endpoint and client id) is unchanged: if either changed, the stored secret is not
    /// carried over (it stays blank, failing the login closed until an admin supplies one), so a
    /// write-only secret cannot be exfiltrated by repointing the provider at a different token
    /// endpoint. Whitespace-only counts as blank, matching the <c>Trim()</c> at the consumption site.
    /// </summary>
    /// <param name="incoming">The provider config about to be persisted.</param>
    /// <param name="live">The current live provider config.</param>
    /// <returns>The secret to persist for the updated provider.</returns>
    internal static string ResolveUpdatedSecret(OidConfig incoming, OidConfig live)
    {
        if (!string.IsNullOrWhiteSpace(incoming.OidSecret))
        {
            return incoming.OidSecret;
        }

        var identityUnchanged =
            string.Equals(incoming.OidEndpoint, live.OidEndpoint, StringComparison.Ordinal)
            && string.Equals(incoming.OidClientId, live.OidClientId, StringComparison.Ordinal);
        return identityUnchanged ? live.OidSecret : incoming.OidSecret;
    }
}
