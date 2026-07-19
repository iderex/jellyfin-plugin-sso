using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Secrets;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Lifecycle coverage for the whole <see cref="PluginConfiguration"/> on-disk XML, through the same
/// <see cref="XmlSerializer"/> the Jellyfin plugin base uses to persist and load config: a legacy config
/// that predates newer elements loads with safe defaults, a config carrying UNKNOWN (forward-version)
/// elements loads without failing, a populated multi-provider config round-trips losslessly, and a legacy
/// plaintext secret survives the full deserialize → protect → serialize → deserialize → reveal disk cycle.
/// The existing suites cover adjacent-but-different ground: <see cref="SerializableDictionarySerializationTests"/>
/// pins the bare dictionary format, <see cref="ConfigPreservationTests"/> round-trips the individual
/// SamlConfig/OidConfig types and their legacy element ORDER, and <see cref="ConfigSecretProtectionTests"/>
/// pins the in-memory plaintext→envelope migration; none exercise the whole-configuration document nor the
/// missing/unknown-element tolerance pinned here.
/// </summary>
public class ConfigXmlLifecycleTests
{
    private static readonly Guid UserA = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid UserB = Guid.Parse("22222222-2222-2222-2222-222222222222");

    [Fact]
    public void FullConfiguration_WithMultipleProviders_RoundTripsThroughXml_Losslessly()
    {
        // The document the plugin base actually writes to disk is the whole PluginConfiguration, with its
        // OidConfigs/SamlConfigs dictionaries populated. The existing round-trip tests only exercise a single
        // provider object or a bare dictionary, never the composed document — this pins that the entire
        // config, across two providers of each protocol plus the global limiter settings, survives a
        // serialize→deserialize round-trip byte-for-value.
        var original = new PluginConfiguration
        {
            EnableRateLimit = true,
            RateLimitMaxAttempts = 42,
            RateLimitWindowSeconds = 120,
        };
        original.OidConfigs["keycloak"] = new OidConfig
        {
            OidEndpoint = "https://kc.example.com/.well-known/openid-configuration",
            OidClientId = "kc-client",
            OidSecret = "kc-plaintext-secret",
            OidScopes = new[] { "openid", "profile", "email" },
            Enabled = true,
            RequirePkce = true,
            PortOverride = 8443,
            Roles = new[] { "media" },
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-kc"] = UserA },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-kc"] = "https://kc.example.com" },
        };
        original.OidConfigs["authelia"] = new OidConfig
        {
            OidEndpoint = "https://auth.example.com/.well-known/openid-configuration",
            OidClientId = "authelia-client",
            RequireVerifiedEmailForLogin = true,
        };
        original.SamlConfigs["adfs"] = new SamlConfig
        {
            SamlEndpoint = "https://adfs.example.com/sso",
            SamlClientId = "sp-entity",
            SamlCertificate = "PUBLIC-IDP-CERT",
            SamlSigningKeyPfx = "adfs-pfx-blob",
            SignAuthnRequests = true,
            AdminRoles = new[] { "sso-admins" },
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-adfs"] = UserB },
        };
        original.SamlConfigs["okta"] = new SamlConfig
        {
            SamlEndpoint = "https://okta.example.com/sso",
            ValidateInResponseTo = true,
        };

        var back = RoundTripXml(original);

        // Global limiter settings.
        Assert.True(back.EnableRateLimit);
        Assert.Equal(42, back.RateLimitMaxAttempts);
        Assert.Equal(120, back.RateLimitWindowSeconds);

        // Both dictionaries kept every entry.
        Assert.Equal(2, back.OidConfigs.Count);
        Assert.Equal(2, back.SamlConfigs.Count);

        var kc = back.OidConfigs["keycloak"];
        Assert.Equal("https://kc.example.com/.well-known/openid-configuration", kc.OidEndpoint);
        Assert.Equal("kc-client", kc.OidClientId);
        // The at-rest XML stores the secret verbatim (encryption is a separate save-time step); it must
        // survive the disk round-trip so a restart does not lose it.
        Assert.Equal("kc-plaintext-secret", kc.OidSecret);
        Assert.Equal(new[] { "openid", "profile", "email" }, kc.OidScopes);
        Assert.True(kc.Enabled);
        Assert.True(kc.RequirePkce);
        Assert.Equal(8443, kc.PortOverride);
        Assert.Equal(new[] { "media" }, kc.Roles);
        Assert.Equal(UserA, kc.CanonicalLinks["sub-kc"]);
        Assert.Equal("https://kc.example.com", kc.CanonicalLinkIssuers["sub-kc"]);

        var authelia = back.OidConfigs["authelia"];
        Assert.Equal("authelia-client", authelia.OidClientId);
        Assert.True(authelia.RequireVerifiedEmailForLogin);

        var adfs = back.SamlConfigs["adfs"];
        Assert.Equal("https://adfs.example.com/sso", adfs.SamlEndpoint);
        Assert.Equal("sp-entity", adfs.SamlClientId);
        Assert.Equal("PUBLIC-IDP-CERT", adfs.SamlCertificate);
        Assert.Equal("adfs-pfx-blob", adfs.SamlSigningKeyPfx);
        Assert.True(adfs.SignAuthnRequests);
        Assert.Equal(new[] { "sso-admins" }, adfs.AdminRoles);
        Assert.Equal(UserB, adfs.CanonicalLinks["nameid-adfs"]);

        var okta = back.SamlConfigs["okta"];
        Assert.Equal("https://okta.example.com/sso", okta.SamlEndpoint);
        Assert.True(okta.ValidateInResponseTo);
    }

    [Fact]
    public void Deserialize_LegacyConfig_MissingRateLimitElements_FallsBackToSafeConstructorDefaults()
    {
        // A config written before the rate-limit feature (#128) has no EnableRateLimit / RateLimitMaxAttempts /
        // RateLimitWindowSeconds elements. XmlSerializer runs the parameterless constructor, so the omitted
        // integers must come back as the constructor's SAFE defaults (30 / 60) rather than 0 — a
        // 0-max-attempts default would silently mean "limiter effectively off" on every legacy upgrade.
        var modern = new PluginConfiguration
        {
            EnableRateLimit = true,
            RateLimitMaxAttempts = 5,
            RateLimitWindowSeconds = 15,
        };
        var legacyXml = StripElements(
            Serialize(modern),
            "<EnableRateLimit>true</EnableRateLimit>",
            "<RateLimitMaxAttempts>5</RateLimitMaxAttempts>",
            "<RateLimitWindowSeconds>15</RateLimitWindowSeconds>");

        // Guard against a silent no-op strip masking the assertion.
        Assert.DoesNotContain("RateLimitMaxAttempts", legacyXml, StringComparison.Ordinal);
        Assert.DoesNotContain("RateLimitWindowSeconds", legacyXml, StringComparison.Ordinal);
        Assert.DoesNotContain("EnableRateLimit", legacyXml, StringComparison.Ordinal);

        var back = Deserialize<PluginConfiguration>(legacyXml);

        Assert.False(back.EnableRateLimit);
        Assert.Equal(30, back.RateLimitMaxAttempts);
        Assert.Equal(60, back.RateLimitWindowSeconds);
    }

    [Fact]
    public void Deserialize_LegacyProvider_MissingNewerElements_UsesFailClosedDefaults()
    {
        // A provider entry written before the newer per-provider toggles existed omits their elements. They
        // must deserialize to their documented defaults — the security toggles fail closed (false), the
        // nullable PortOverride to null — without a throw, so an old on-disk provider keeps loading.
        var modern = new PluginConfiguration();
        modern.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.com/.well-known/openid-configuration",
            OidClientId = "idp-client",
            RequirePkce = true,
            RequireVerifiedEmailForLogin = true,
            AllowExistingAccountLink = true,
            PortOverride = 9443,
        };

        var legacyXml = StripElements(
            Serialize(modern),
            "<RequirePkce>true</RequirePkce>",
            "<RequireVerifiedEmailForLogin>true</RequireVerifiedEmailForLogin>",
            "<AllowExistingAccountLink>true</AllowExistingAccountLink>",
            "<PortOverride>9443</PortOverride>");

        Assert.DoesNotContain("RequirePkce", legacyXml, StringComparison.Ordinal);
        Assert.DoesNotContain("RequireVerifiedEmailForLogin", legacyXml, StringComparison.Ordinal);
        Assert.DoesNotContain("AllowExistingAccountLink", legacyXml, StringComparison.Ordinal);
        Assert.DoesNotContain("PortOverride", legacyXml, StringComparison.Ordinal);

        var back = Deserialize<PluginConfiguration>(legacyXml);
        var idp = back.OidConfigs["idp"];

        // Elements that were still present survive.
        Assert.Equal("https://idp.example.com/.well-known/openid-configuration", idp.OidEndpoint);
        Assert.Equal("idp-client", idp.OidClientId);
        // The omitted newer elements fall to their fail-closed / unset defaults.
        Assert.False(idp.RequirePkce);
        Assert.False(idp.RequireVerifiedEmailForLogin);
        Assert.False(idp.AllowExistingAccountLink);
        Assert.Null(idp.PortOverride);
    }

    [Fact]
    public void Deserialize_ConfigWithUnknownElements_DoesNotThrow_AndKeepsKnownValues()
    {
        // Forward compatibility: a config written by a NEWER plugin version can carry elements this version
        // does not know — at the top level and inside a provider entry. XmlSerializer must skip the unknown
        // elements (its default UnknownElement behavior is to ignore, not throw), so a downgrade or a
        // hand-edited config still loads with every known value intact.
        var modern = new PluginConfiguration { RateLimitMaxAttempts = 25 };
        modern.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.com/.well-known/openid-configuration",
            OidClientId = "idp-client",
        };

        var xml = Serialize(modern);
        // Inject an unknown element inside the provider entry (right after a known provider element)...
        xml = xml.Replace(
            "</OidEndpoint>",
            "</OidEndpoint><FutureProviderToggle>on</FutureProviderToggle>",
            StringComparison.Ordinal);
        // ...and an unknown element at the top level, before the document's closing root tag.
        var lastClose = xml.LastIndexOf("</PluginConfiguration>", StringComparison.Ordinal);
        xml = xml.Insert(lastClose, "<FutureGlobalSetting><Nested>value</Nested></FutureGlobalSetting>");

        var back = Record.Exception(() => Deserialize<PluginConfiguration>(xml));
        Assert.Null(back);

        var reparsed = Deserialize<PluginConfiguration>(xml);
        Assert.Equal(25, reparsed.RateLimitMaxAttempts);
        Assert.Equal("https://idp.example.com/.well-known/openid-configuration", reparsed.OidConfigs["idp"].OidEndpoint);
        Assert.Equal("idp-client", reparsed.OidConfigs["idp"].OidClientId);
    }

    [Fact]
    public void LegacyPlaintextSecrets_SurviveTheFullOnDiskLifecycle_UpgradingToEnvelope()
    {
        // End-to-end on-disk lifecycle for the secret-at-rest upgrade (#158), stitched through the REAL XML
        // serializer rather than in-memory objects: a legacy config XML holds plaintext provider secrets;
        // it deserializes, the persist boundary encrypts them (ConfigSecretProtection.ProtectAll), the
        // encrypted config is written back to XML and read again, and the original plaintext is recovered via
        // SecretStore.Reveal. NOTE: this exercises secret-at-rest migration — a security-surface change of
        // this shape belongs to the /security-review gate.
        var keyPath = Path.Combine(Path.GetTempPath(), "sso-cfgxml-" + Guid.NewGuid().ToString("N") + ".key");
        try
        {
            var legacy = new PluginConfiguration();
            legacy.OidConfigs["idp"] = new OidConfig { OidClientId = "client", OidSecret = "legacy-oidc-plaintext" };
            legacy.SamlConfigs["saml"] = new SamlConfig { SamlClientId = "sp", SamlSigningKeyPfx = "legacy-pfx-plaintext" };
            var legacyOnDisk = Serialize(legacy);

            // The plaintext is exactly what a pre-#158 install has sitting in its config XML.
            Assert.Contains("legacy-oidc-plaintext", legacyOnDisk, StringComparison.Ordinal);
            Assert.Contains("legacy-pfx-plaintext", legacyOnDisk, StringComparison.Ordinal);
            Assert.DoesNotContain("ssoenc:", legacyOnDisk, StringComparison.Ordinal);

            // Load it, then encrypt at the persist boundary and write it back — the plugin's save path.
            var loaded = Deserialize<PluginConfiguration>(legacyOnDisk);
            var store = new SecretStore(keyPath);
            ConfigSecretProtection.ProtectAll(loaded, store);
            var encryptedOnDisk = Serialize(loaded);

            // The rewritten config no longer carries the plaintext; it carries envelopes.
            Assert.DoesNotContain("legacy-oidc-plaintext", encryptedOnDisk, StringComparison.Ordinal);
            Assert.DoesNotContain("legacy-pfx-plaintext", encryptedOnDisk, StringComparison.Ordinal);
            Assert.Contains("ssoenc:", encryptedOnDisk, StringComparison.Ordinal);

            // Read the encrypted config back and recover the original secrets — nothing was lost.
            var reloaded = Deserialize<PluginConfiguration>(encryptedOnDisk);
            Assert.True(SecretEnvelope.IsProtected(reloaded.OidConfigs["idp"].OidSecret));
            Assert.True(SecretEnvelope.IsProtected(reloaded.SamlConfigs["saml"].SamlSigningKeyPfx));
            Assert.Equal("legacy-oidc-plaintext", store.Reveal(reloaded.OidConfigs["idp"].OidSecret));
            Assert.Equal("legacy-pfx-plaintext", store.Reveal(reloaded.SamlConfigs["saml"].SamlSigningKeyPfx));
        }
        finally
        {
            if (File.Exists(keyPath))
            {
                File.Delete(keyPath);
            }
        }
    }

    private static string Serialize<T>(T value)
    {
        var serializer = new XmlSerializer(typeof(T));
        using var writer = new StringWriter();
        serializer.Serialize(writer, value);
        return writer.ToString();
    }

    // Deserializes through the XmlReader overload with DTD processing prohibited (the hardened CA5369
    // pattern), mirroring how the production config is only ever read through an XmlReader.
    private static T Deserialize<T>(string xml)
    {
        var serializer = new XmlSerializer(typeof(T));
        using var stringReader = new StringReader(xml);
        using var xmlReader = XmlReader.Create(
            stringReader,
            new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        return (T)serializer.Deserialize(xmlReader)!;
    }

    private static T RoundTripXml<T>(T value) => Deserialize<T>(Serialize(value));

    // Removes each exact element substring, asserting via the caller that the element name is truly gone so a
    // no-op strip cannot silently pass the test.
    private static string StripElements(string xml, params string[] elements)
    {
        foreach (var element in elements)
        {
            xml = xml.Replace(element, string.Empty, StringComparison.Ordinal);
        }

        return xml;
    }
}
