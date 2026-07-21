// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Secrets;

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
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// The configuration already holds encrypted envelopes but the key file is missing - a lost key that must
    /// be restored deliberately rather than silently replaced (which would orphan those envelopes).
    /// </exception>
    internal static void ProtectAll(PluginConfiguration configuration, SecretStore store)
    {
        // Decide once, over the whole config, whether any encrypted envelope is already present. Passed into
        // every Protect call so that minting a fresh key over a missing-key-but-envelopes-present config is
        // refused (orphan-prevention), while a genuine first run (no envelopes anywhere) still creates a key.
        var configHasEnvelopes = HasAnyEnvelope(configuration);

        if (configuration.OidConfigs != null)
        {
            foreach (var oid in configuration.OidConfigs.Values)
            {
                if (oid == null)
                {
                    continue;
                }

                oid.OidSecret = store.Protect(oid.OidSecret, configHasEnvelopes);
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

                saml.SamlSigningKeyPfx = store.Protect(saml.SamlSigningKeyPfx, configHasEnvelopes);

                // The rollover signing key (#491) carries a private key too, so it is encrypted at rest
                // exactly like the primary — a plaintext rollover key would be a secrets-at-rest regression.
                saml.SamlRolloverSigningKeyPfx = store.Protect(saml.SamlRolloverSigningKeyPfx, configHasEnvelopes);
            }
        }

        if (configuration.LogoutSessions != null)
        {
            foreach (var session in configuration.LogoutSessions.Values)
            {
                if (session == null)
                {
                    continue;
                }

                // The captured id_token (#727) is a bearer secret used as an id_token_hint at logout, so it
                // is encrypted at rest exactly like the provider secrets — a plaintext id_token in config.xml
                // would be a secrets-at-rest regression.
                session.IdToken = store.Protect(session.IdToken, configHasEnvelopes);
            }
        }
    }

    // True when any protected field already carries a well-formed envelope. Inspects exactly the fields
    // ProtectAll encrypts (the OpenID client secrets and the SAML signing keys) - the only values this
    // plugin ever writes as envelopes - so the presence signal is accurate to the data that could be
    // orphaned.
    private static bool HasAnyEnvelope(PluginConfiguration configuration)
    {
        if (configuration.OidConfigs != null)
        {
            foreach (var oid in configuration.OidConfigs.Values)
            {
                if (oid != null && SecretEnvelope.IsWellFormedEnvelope(oid.OidSecret))
                {
                    return true;
                }
            }
        }

        if (configuration.SamlConfigs != null)
        {
            foreach (var saml in configuration.SamlConfigs.Values)
            {
                if (saml != null
                    && (SecretEnvelope.IsWellFormedEnvelope(saml.SamlSigningKeyPfx)
                        || SecretEnvelope.IsWellFormedEnvelope(saml.SamlRolloverSigningKeyPfx)))
                {
                    return true;
                }
            }
        }

        if (configuration.LogoutSessions != null)
        {
            foreach (var session in configuration.LogoutSessions.Values)
            {
                if (session != null && SecretEnvelope.IsWellFormedEnvelope(session.IdToken))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
