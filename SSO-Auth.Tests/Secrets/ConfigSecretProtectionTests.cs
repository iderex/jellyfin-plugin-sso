using System;
using System.IO;
using System.Security.Cryptography;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Secrets;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Coverage for encrypting a configuration's provider secrets before it is persisted at rest.
/// </summary>
public class ConfigSecretProtectionTests
{
    private static void WithStore(Action<SecretStore> test)
    {
        var path = Path.Combine(Path.GetTempPath(), "sso-cfgsec-" + Guid.NewGuid().ToString("N") + ".key");
        try
        {
            test(new SecretStore(path));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void ProtectAll_EncryptsEveryProviderSecret_AndRevealRecoversThem()
    {
        WithStore(store =>
        {
            var config = new PluginConfiguration();
            config.OidConfigs["authelia"] = new OidConfig { OidSecret = "oidc-client-secret" };
            config.SamlConfigs["keycloak"] = new SamlConfig { SamlSigningKeyPfx = "pfx-blob" };

            ConfigSecretProtection.ProtectAll(config, store);

            Assert.True(SecretEnvelope.IsProtected(config.OidConfigs["authelia"].OidSecret));
            Assert.True(SecretEnvelope.IsProtected(config.SamlConfigs["keycloak"].SamlSigningKeyPfx));
            Assert.Equal("oidc-client-secret", store.Reveal(config.OidConfigs["authelia"].OidSecret));
            Assert.Equal("pfx-blob", store.Reveal(config.SamlConfigs["keycloak"].SamlSigningKeyPfx));
        });
    }

    [Fact]
    public void ProtectAll_CoversEveryProvider_ButLeavesPublicCertificatesAsPlaintext()
    {
        WithStore(store =>
        {
            var config = new PluginConfiguration();

            // Two providers of each kind, so the loop must reach all of them - not just the first entry.
            config.OidConfigs["a"] = new OidConfig { OidClientId = "client-a", OidSecret = "secret-a" };
            config.OidConfigs["b"] = new OidConfig { OidClientId = "client-b", OidSecret = "secret-b" };
            config.SamlConfigs["x"] = new SamlConfig
            {
                SamlSigningKeyPfx = "pfx-x",
                SamlCertificate = "PUBLIC-IDP-CERT-X",
                SamlSecondaryCertificate = "PUBLIC-IDP-CERT-SECONDARY-X",
            };
            config.SamlConfigs["y"] = new SamlConfig { SamlSigningKeyPfx = "pfx-y" };

            ConfigSecretProtection.ProtectAll(config, store);

            // Every genuine secret, across every provider, is encrypted.
            Assert.True(SecretEnvelope.IsProtected(config.OidConfigs["a"].OidSecret));
            Assert.True(SecretEnvelope.IsProtected(config.OidConfigs["b"].OidSecret));
            Assert.True(SecretEnvelope.IsProtected(config.SamlConfigs["x"].SamlSigningKeyPfx));
            Assert.True(SecretEnvelope.IsProtected(config.SamlConfigs["y"].SamlSigningKeyPfx));

            // The identity provider's certificate is a PUBLIC key, not a secret. Signature verification reads
            // it directly (never through Reveal), so encrypting it here would silently break every SAML
            // login. It - and non-secret ids - must be left verbatim.
            Assert.Equal("PUBLIC-IDP-CERT-X", config.SamlConfigs["x"].SamlCertificate);

            // The inbound secondary verification certificate (#491) is likewise the identity provider's
            // PUBLIC key, read directly by signature verification (never through Reveal); encrypting it would
            // silently break rotation logins, so it too must be left verbatim.
            Assert.Equal("PUBLIC-IDP-CERT-SECONDARY-X", config.SamlConfigs["x"].SamlSecondaryCertificate);
            Assert.Equal("client-a", config.OidConfigs["a"].OidClientId);
        });
    }

    [Fact]
    public void ProtectAll_EncryptsTheRolloverSigningKey_AndRevealRecoversIt()
    {
        WithStore(store =>
        {
            // The rollover signing key (#491) carries a private key, so it must be encrypted at rest exactly
            // like the primary — a plaintext rollover key would be a secrets-at-rest regression.
            var config = new PluginConfiguration();
            config.SamlConfigs["keycloak"] = new SamlConfig
            {
                SamlSigningKeyPfx = "primary-pfx-blob",
                SamlRolloverSigningKeyPfx = "rollover-pfx-blob",
            };

            ConfigSecretProtection.ProtectAll(config, store);

            Assert.True(SecretEnvelope.IsProtected(config.SamlConfigs["keycloak"].SamlSigningKeyPfx));
            Assert.True(SecretEnvelope.IsProtected(config.SamlConfigs["keycloak"].SamlRolloverSigningKeyPfx));
            Assert.Equal("primary-pfx-blob", store.Reveal(config.SamlConfigs["keycloak"].SamlSigningKeyPfx));
            Assert.Equal("rollover-pfx-blob", store.Reveal(config.SamlConfigs["keycloak"].SamlRolloverSigningKeyPfx));
        });
    }

    [Fact]
    public void ProtectAll_EncryptsTheCapturedLogoutIdToken_AndRevealRecoversIt()
    {
        WithStore(store =>
        {
            // The Single Logout id_token (#727) is a bearer secret used as an id_token_hint at logout, so it
            // must be encrypted at rest exactly like the provider secrets — a plaintext id_token in config.xml
            // would be a secrets-at-rest regression.
            var config = new PluginConfiguration();
            config.LogoutSessions["session-1"] = new LogoutSession
            {
                Protocol = "OID",
                Provider = "keycloak",
                Subject = "sub-1",
                IdToken = "raw.id.token",
            };

            ConfigSecretProtection.ProtectAll(config, store);

            Assert.True(SecretEnvelope.IsProtected(config.LogoutSessions["session-1"].IdToken));
            Assert.Equal("raw.id.token", store.Reveal(config.LogoutSessions["session-1"].IdToken));
        });
    }

    [Fact]
    public void HasAnyEnvelope_ALogoutIdTokenEnvelopeAlone_IsDetected_SoAMissingKeyFailsClosed()
    {
        var path = Path.Combine(Path.GetTempPath(), "sso-cfgsec-" + Guid.NewGuid().ToString("N") + ".key");
        try
        {
            // An envelope living ONLY in a captured logout id_token must still be seen as "config holds an
            // envelope", so a lost key fails closed (orphan-prevention must cover the logout store too).
            var envelope = new SecretStore(path).Protect("old-id-token");
            File.Delete(path);

            var config = new PluginConfiguration();
            config.LogoutSessions["s"] = new LogoutSession { Provider = "keycloak", Subject = "sub", IdToken = envelope };
            config.OidConfigs["b"] = new OidConfig { OidSecret = "new-plaintext" };

            Assert.Throws<CryptographicException>(() => ConfigSecretProtection.ProtectAll(config, new SecretStore(path)));
            Assert.False(File.Exists(path)); // no replacement key minted
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void HasAnyEnvelope_ARolloverEnvelopeAlone_IsDetected_SoAMissingKeyFailsClosed()
    {
        var path = Path.Combine(Path.GetTempPath(), "sso-cfgsec-" + Guid.NewGuid().ToString("N") + ".key");
        try
        {
            // Encrypt a value so a real envelope exists, place it ONLY in the rollover field, then lose the
            // key: ProtectAll must still see the config holds an envelope and refuse to mint a fresh key over
            // it (orphan-prevention must cover the rollover field, not just the primary).
            var envelope = new SecretStore(path).Protect("old-rollover");
            File.Delete(path);

            var config = new PluginConfiguration();
            config.SamlConfigs["a"] = new SamlConfig { SamlRolloverSigningKeyPfx = envelope };
            config.OidConfigs["b"] = new OidConfig { OidSecret = "new-plaintext" };

            Assert.Throws<CryptographicException>(() => ConfigSecretProtection.ProtectAll(config, new SecretStore(path)));
            Assert.False(File.Exists(path)); // no replacement key minted
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void ProtectAll_IsIdempotent()
    {
        WithStore(store =>
        {
            var config = new PluginConfiguration();
            config.OidConfigs["a"] = new OidConfig { OidSecret = "secret" };

            ConfigSecretProtection.ProtectAll(config, store);
            var afterFirst = config.OidConfigs["a"].OidSecret;
            ConfigSecretProtection.ProtectAll(config, store);

            Assert.Equal(afterFirst, config.OidConfigs["a"].OidSecret);
        });
    }

    [Fact]
    public void ProtectAll_ExistingEnvelopeButMissingKey_FailsClosedWithoutMinting()
    {
        var path = Path.Combine(Path.GetTempPath(), "sso-cfgsec-" + Guid.NewGuid().ToString("N") + ".key");
        try
        {
            // Encrypt one secret so a real envelope exists, then lose the key file (restored config, lost key).
            var envelope = new SecretStore(path).Protect("old-secret");
            File.Delete(path);

            var config = new PluginConfiguration();
            config.OidConfigs["a"] = new OidConfig { OidSecret = envelope };           // encrypted under the lost key
            config.SamlConfigs["b"] = new SamlConfig { SamlSigningKeyPfx = "new-plaintext" };

            // Persisting must refuse to mint a fresh key over the orphaned envelope rather than mask the loss.
            Assert.Throws<CryptographicException>(
                () => ConfigSecretProtection.ProtectAll(config, new SecretStore(path)));

            Assert.False(File.Exists(path)); // no replacement key minted
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void ProtectAll_LegacyPlaintextOnly_NoKey_MigratesByMintingKey()
    {
        WithStore(store =>
        {
            // A legacy plaintext config with no envelopes and no key must still be migrated on first save.
            var config = new PluginConfiguration();
            config.OidConfigs["a"] = new OidConfig { OidSecret = "legacy-plaintext" };

            ConfigSecretProtection.ProtectAll(config, store);

            Assert.True(SecretEnvelope.IsProtected(config.OidConfigs["a"].OidSecret));
            Assert.Equal("legacy-plaintext", store.Reveal(config.OidConfigs["a"].OidSecret));
        });
    }

    [Fact]
    public void ProtectAll_NewPlaintextAlongsideEnvelope_KeyPresent_StillEncrypts()
    {
        WithStore(store =>
        {
            var envelope = store.Protect("existing-secret"); // mints the key and encrypts

            // A config that already holds an envelope, with the key present, must not be bricked when a new
            // plaintext secret is added (adding a provider to an already-encrypted config).
            var config = new PluginConfiguration();
            config.OidConfigs["a"] = new OidConfig { OidSecret = envelope };
            config.OidConfigs["b"] = new OidConfig { OidSecret = "brand-new-plaintext" };

            ConfigSecretProtection.ProtectAll(config, store);

            Assert.True(SecretEnvelope.IsProtected(config.OidConfigs["b"].OidSecret));
            Assert.Equal("existing-secret", store.Reveal(config.OidConfigs["a"].OidSecret));
            Assert.Equal("brand-new-plaintext", store.Reveal(config.OidConfigs["b"].OidSecret));
        });
    }

    [Fact]
    public void ProtectAll_LeavesEmptySecretsUntouched()
    {
        WithStore(store =>
        {
            var config = new PluginConfiguration();
            config.OidConfigs["a"] = new OidConfig { OidSecret = string.Empty };
            config.SamlConfigs["b"] = new SamlConfig { SamlSigningKeyPfx = null };

            ConfigSecretProtection.ProtectAll(config, store);

            Assert.Equal(string.Empty, config.OidConfigs["a"].OidSecret);
            Assert.Null(config.SamlConfigs["b"].SamlSigningKeyPfx);
        });
    }
}
