using System;
using System.IO;
using Jellyfin.Plugin.SSO_Auth.Api;
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
            Assert.Equal("client-a", config.OidConfigs["a"].OidClientId);
        });
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
