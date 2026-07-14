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
    /// (always server-owned, #157), and the OpenID client secret (#189) — the latter only when the
    /// incoming value is blank, since the secret is withheld from JSON responses so a save that did
    /// not set a new one arrives empty and must keep the stored value (a non-blank incoming value is
    /// an intentional rotation and is left as-is).
    /// </summary>
    /// <param name="incoming">The configuration about to be persisted.</param>
    /// <param name="live">The current live configuration to read server-managed values from.</param>
    internal static void Preserve(PluginConfiguration incoming, PluginConfiguration live)
    {
        if (incoming?.OidConfigs != null && live?.OidConfigs != null)
        {
            foreach (var kvp in live.OidConfigs)
            {
                if (incoming.OidConfigs.TryGetValue(kvp.Key, out var incomingProvider))
                {
                    Preserve(incomingProvider, kvp.Value);
                }
            }
        }

        if (incoming?.SamlConfigs != null && live?.SamlConfigs != null)
        {
            foreach (var kvp in live.SamlConfigs)
            {
                if (incoming.SamlConfigs.TryGetValue(kvp.Key, out var incomingProvider))
                {
                    Preserve(incomingProvider, kvp.Value);
                }
            }
        }
    }

    // Links + secret: an OpenID provider carries both server-managed fields (#157/#189).
    internal static void Preserve(OidConfig incoming, OidConfig live)
    {
        incoming.CanonicalLinks = live.CanonicalLinks;
        incoming.OidSecret = ResolveUpdatedSecret(incoming, live);
    }

    // Links only: a SAML provider has no write-only secret (#157).
    internal static void Preserve(SamlConfig incoming, SamlConfig live)
    {
        incoming.CanonicalLinks = live.CanonicalLinks;
    }

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
