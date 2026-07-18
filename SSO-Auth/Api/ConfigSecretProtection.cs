using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Encrypts the at-rest secrets carried in a <see cref="PluginConfiguration"/> - the OpenID client secrets
/// and the SAML signing keys - just before it is persisted. Applied on every configuration save so a value
/// entered in plaintext (via the settings page, the API, or an import) is stored encrypted, and a value
/// already encrypted is left unchanged (both <see cref="SecretStore.Protect"/> and the underlying envelope
/// are idempotent). At-rest reads decrypt on demand via <see cref="SecretStore.Reveal"/>. A legacy plaintext
/// config is therefore migrated transparently: its values stay readable, and the next save rewrites them
/// encrypted.
/// </summary>
internal static class ConfigSecretProtection
{
    /// <summary>
    /// Encrypts, in place, every provider secret in the configuration.
    /// </summary>
    /// <param name="configuration">The configuration about to be persisted.</param>
    /// <param name="store">The secret store providing the data-encryption key.</param>
    internal static void ProtectAll(PluginConfiguration configuration, SecretStore store)
    {
        if (configuration.OidConfigs != null)
        {
            foreach (var oid in configuration.OidConfigs.Values)
            {
                if (oid == null)
                {
                    continue;
                }

                oid.OidSecret = store.Protect(oid.OidSecret);
            }
        }

        if (configuration.SamlConfigs != null)
        {
            foreach (var saml in configuration.SamlConfigs.Values)
            {
                if (saml == null)
                {
                    continue;
                }

                saml.SamlSigningKeyPfx = store.Protect(saml.SamlSigningKeyPfx);
            }
        }
    }
}
