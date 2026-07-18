using System;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for the server-managed-field handling (#157): canonical links are preserved across a save
/// built from a stale client snapshot (<see cref="ServerManagedFields.Preserve(PluginConfiguration, PluginConfiguration)"/>), are
/// withheld from JSON responses ([JsonIgnore]), and still round-trip through the config XML.
/// </summary>
public class ConfigPreservationTests
{
    private static readonly Guid User = Guid.Parse("11111111-1111-1111-1111-111111111111");

    [Fact]
    public void Preserve_ReinjectsLiveLinks_IntoStaleIncomingProvider()
    {
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User } };
        live.SamlConfigs["saml"] = new SamlConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-1"] = User } };

        // The incoming (stale) config has the providers but empty link maps — as a client snapshot
        // taken before the login that created the links would.
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig();
        incoming.SamlConfigs["saml"] = new SamlConfig();

        ServerManagedFields.Preserve(incoming, live);

        Assert.Equal(User, incoming.OidConfigs["idp"].CanonicalLinks["sub-1"]);
        Assert.Equal(User, incoming.SamlConfigs["saml"].CanonicalLinks["nameid-1"]);
    }

    [Fact]
    public void Preserve_NewProviderNotInLive_KeepsItsOwnEmptyMap()
    {
        var live = new PluginConfiguration();
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["fresh"] = new OidConfig();

        ServerManagedFields.Preserve(incoming, live);

        Assert.Empty(incoming.OidConfigs["fresh"].CanonicalLinks);
    }

    [Fact]
    public void Preserve_ProviderDeletedInIncoming_IsNotReAdded()
    {
        // Deleting a provider must survive the save: a provider present only in live is not resurrected.
        var live = new PluginConfiguration();
        live.OidConfigs["gone"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub"] = User } };
        var incoming = new PluginConfiguration();

        ServerManagedFields.Preserve(incoming, live);

        Assert.False(incoming.OidConfigs.ContainsKey("gone"));
    }

    [Fact]
    public void Preserve_NullConfigMaps_DoNotThrow()
    {
        var incoming = new PluginConfiguration { OidConfigs = null, SamlConfigs = null };
        var live = new PluginConfiguration { OidConfigs = null, SamlConfigs = null };

        // Fail-safe: a malformed config with missing maps must not NRE the save path.
        var exception = Record.Exception(() => ServerManagedFields.Preserve(incoming, live));

        Assert.Null(exception);
        // Nothing to preserve from, so the null maps are left exactly as they arrived.
        Assert.Null(incoming.OidConfigs);
        Assert.Null(incoming.SamlConfigs);
    }

    [Fact]
    public void Preserve_NullProviderEntry_DoesNotThrow()
    {
        // A malformed Add before #350 could store a null provider entry; preserving with a null on
        // either side must skip it, not NRE the whole config-page save.
        var live = new PluginConfiguration();
        live.OidConfigs["null-in-live"] = null;
        live.OidConfigs["null-in-incoming"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub"] = User } };
        live.SamlConfigs["saml-null-in-live"] = null;

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["null-in-live"] = new OidConfig();
        incoming.OidConfigs["null-in-incoming"] = null;
        incoming.SamlConfigs["saml-null-in-live"] = new SamlConfig();

        var exception = Record.Exception(() => ServerManagedFields.Preserve(incoming, live));

        Assert.Null(exception);
    }

    // --- Per-link issuer binding + repoint belt (#186) ---

    [Fact]
    public void Preserve_OidEndpointUnchanged_KeepsLinksAndIssuerBindings()
    {
        // Criterion 3 (#186): while the provider endpoint is unchanged, both the links and their issuer
        // bindings are carried over verbatim, so existing links keep working across an unrelated save.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp/.well-known",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-1"] = "https://idp" },
        };
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { OidEndpoint = "https://idp/.well-known" };

        ServerManagedFields.Preserve(incoming, live);

        Assert.Equal(User, incoming.OidConfigs["idp"].CanonicalLinks["sub-1"]);
        Assert.Equal("https://idp", incoming.OidConfigs["idp"].CanonicalLinkIssuers["sub-1"]);
    }

    [Fact]
    public void Preserve_OidEndpointChanged_ClearsLinksAndIssuerBindings_TheRepointBelt()
    {
        // Criterion 1 (#186), the belt: repointing the endpoint at a (potentially) different IdP drops the
        // accumulated sub-keyed links AND their issuer bindings rather than carrying them across, so a
        // new-IdP user whose sub collides with an old link cannot inherit the old account — even an
        // un-stamped legacy link (a user who had not logged in since the upgrade) is protected here.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp/.well-known",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["1"] = User },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["1"] = "https://idp" },
        };
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { OidEndpoint = "https://other-idp/.well-known" };

        ServerManagedFields.Preserve(incoming, live);

        Assert.Empty(incoming.OidConfigs["idp"].CanonicalLinks);
        Assert.Empty(incoming.OidConfigs["idp"].CanonicalLinkIssuers);
    }

    [Fact]
    public void CanonicalLinkIssuers_AreOmittedFromJson_ButKeptInXml()
    {
        // The issuer map is server-managed exactly like CanonicalLinks (#186/#157): withheld from JSON so it
        // cannot be read back or set via a config PUT, but persisted in the config XML so bindings survive a
        // restart. This also pins the SerializableDictionary&lt;string,string&gt; XML round-trip shape.
        var config = new OidConfig
        {
            OidClientId = "client",
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-secret"] = "https://issuer.example" },
        };

        var json = System.Text.Json.JsonSerializer.Serialize(config);
        Assert.DoesNotContain("CanonicalLinkIssuers", json, StringComparison.Ordinal);
        Assert.DoesNotContain("issuer.example", json, StringComparison.Ordinal);

        var serializer = new XmlSerializer(typeof(OidConfig));
        using var writer = new System.IO.StringWriter();
        serializer.Serialize(writer, config);
        var xml = writer.ToString();
        Assert.Contains("CanonicalLinkIssuers", xml, StringComparison.Ordinal);
        Assert.Contains("sub-secret", xml, StringComparison.Ordinal);
        Assert.Contains("https://issuer.example", xml, StringComparison.Ordinal);

        // Round-trips back with the value intact.
        var back = RoundTripXml(config);
        Assert.Equal("https://issuer.example", back.CanonicalLinkIssuers["sub-secret"]);
    }

    [Fact]
    public void CanonicalLinks_AreOmittedFromJson_ButKeptInXml()
    {
        var config = new OidConfig
        {
            OidClientId = "client",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-secret"] = User },
        };

        // JSON (API responses / core getPluginConfiguration) must not leak the account-link map.
        var json = System.Text.Json.JsonSerializer.Serialize(config);
        Assert.DoesNotContain("CanonicalLinks", json, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-secret", json, StringComparison.Ordinal);
        Assert.Contains("client", json, StringComparison.Ordinal);

        // XML (on-disk config) must still persist it, so links survive a restart.
        var serializer = new XmlSerializer(typeof(OidConfig));
        using var writer = new System.IO.StringWriter();
        serializer.Serialize(writer, config);
        var xml = writer.ToString();
        Assert.Contains("CanonicalLinks", xml, StringComparison.Ordinal);
        Assert.Contains("sub-secret", xml, StringComparison.Ordinal);
    }

    [Fact]
    public void OidSecret_SerializedValueIsHidden_ButStaysDeserializableAndInXml()
    {
        var config = new OidConfig { OidClientId = "client", OidSecret = "s3cr3t-value" };

        // JSON responses (API / core getPluginConfiguration) must not leak the secret VALUE. The
        // property is still emitted, but as null (write-only), so the plaintext never leaves the server.
        var json = System.Text.Json.JsonSerializer.Serialize(config);
        Assert.DoesNotContain("s3cr3t-value", json, StringComparison.Ordinal);
        Assert.Contains("\"OidSecret\":null", json, StringComparison.Ordinal);
        Assert.Contains("client", json, StringComparison.Ordinal);

        // Jellyfin core serializes the plugin config with a camelCase naming policy; the value must
        // stay hidden there too (the property name differs, the hidden-value guarantee must not).
        var camel = System.Text.Json.JsonSerializer.Serialize(
            config,
            new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase });
        Assert.DoesNotContain("s3cr3t-value", camel, StringComparison.Ordinal);

        // XML (on-disk config) must still persist the secret, so it survives a restart.
        var serializer = new XmlSerializer(typeof(OidConfig));
        using var writer = new System.IO.StringWriter();
        serializer.Serialize(writer, config);
        var xml = writer.ToString();
        Assert.Contains("OidSecret", xml, StringComparison.Ordinal);
        Assert.Contains("s3cr3t-value", xml, StringComparison.Ordinal);
    }

    [Fact]
    public void OidSecret_IsDeserializedFromJson_SoItCanBeSetAndRotated()
    {
        // The write half: unlike a bidirectional [JsonIgnore], an incoming secret on a save (config
        // PUT / OID/Add) must survive System.Text.Json deserialization — this is the exact boundary
        // the config page crosses, and the case that a bidirectional ignore silently broke.
        const string body = "{\"OidClientId\":\"client\",\"OidSecret\":\"typed-secret\"}";
        var parsed = System.Text.Json.JsonSerializer.Deserialize<OidConfig>(body);
        Assert.Equal("typed-secret", parsed!.OidSecret);
    }

    [Fact]
    public void Rotation_ThroughJsonThenPreserve_KeepsTheNewSecret()
    {
        // The realistic rotation path: a config PUT carrying a new secret is deserialized, then
        // ServerManagedFields.Preserve runs against the live config — the new secret must win.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig { OidSecret = "old-secret" };

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = System.Text.Json.JsonSerializer.Deserialize<OidConfig>(
            "{\"OidSecret\":\"rotated-secret\"}")!;

        ServerManagedFields.Preserve(incoming, live);

        Assert.Equal("rotated-secret", incoming.OidConfigs["idp"].OidSecret);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Preserve_BlankIncomingSecret_KeepsLiveSecret(string? incomingSecret)
    {
        // A save that did not set a new secret arrives blank (the value is withheld from JSON), and
        // must keep the stored one — fail closed, a blank save never wipes the live secret.
        // Whitespace-only counts as blank, to match the Trim() where the secret is consumed.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig { OidSecret = "live-secret" };
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { OidSecret = incomingSecret };

        ServerManagedFields.Preserve(incoming, live);

        Assert.Equal("live-secret", incoming.OidConfigs["idp"].OidSecret);
    }

    [Fact]
    public void Preserve_NewProviderWithBlankSecret_StaysBlank()
    {
        // A brand-new provider has no live secret to re-inject, so a blank stays blank (the OIDC
        // flow then fails closed for lack of a secret rather than adopting some other value).
        var live = new PluginConfiguration();
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["fresh"] = new OidConfig { OidSecret = null };

        ServerManagedFields.Preserve(incoming, live);

        Assert.True(string.IsNullOrEmpty(incoming.OidConfigs["fresh"].OidSecret));
    }

    [Fact]
    public void ResolveUpdatedSecret_BlankAndIdentityUnchanged_KeepsLiveSecret()
    {
        var live = new OidConfig { OidEndpoint = "https://idp/.well-known", OidClientId = "cid", OidSecret = "live" };
        var incoming = new OidConfig { OidEndpoint = "https://idp/.well-known", OidClientId = "cid", OidSecret = "  " };

        Assert.Equal("live", ServerManagedFields.ResolveUpdatedSecret(incoming, live));
    }

    [Fact]
    public void ResolveUpdatedSecret_NonBlank_IsAlwaysKept_AsRotation()
    {
        var live = new OidConfig { OidEndpoint = "https://idp/.well-known", OidClientId = "cid", OidSecret = "live" };
        var incoming = new OidConfig { OidEndpoint = "https://idp/.well-known", OidClientId = "cid", OidSecret = "rotated" };

        Assert.Equal("rotated", ServerManagedFields.ResolveUpdatedSecret(incoming, live));
    }

    [Theory]
    [InlineData("https://other-idp/.well-known", "cid")] // endpoint repointed
    [InlineData("https://idp/.well-known", "other-cid")] // client id changed
    public void ResolveUpdatedSecret_BlankButIdentityChanged_DropsSecret_FailClosed(string endpoint, string clientId)
    {
        // A blank secret is NOT carried across a provider-identity change: otherwise an admin could
        // exfiltrate the write-only secret by repointing the provider at a token endpoint they
        // control. The secret stays blank, so the login fails closed until a new one is supplied.
        var live = new OidConfig { OidEndpoint = "https://idp/.well-known", OidClientId = "cid", OidSecret = "live" };
        var incoming = new OidConfig { OidEndpoint = endpoint, OidClientId = clientId, OidSecret = null };

        Assert.True(string.IsNullOrEmpty(ServerManagedFields.ResolveUpdatedSecret(incoming, live)));
    }

    // --- SAML signing key: write-only secret + preserve-on-blank (#167) ---

    [Fact]
    public void SamlSigningKey_SerializedValueIsHidden_ButStaysDeserializableAndInXml()
    {
        var config = new SamlConfig { SamlClientId = "sp", SamlSigningKeyPfx = "pfx-secret-blob" };

        // JSON responses must not leak the private-key blob; the property is emitted as null (write-only).
        var json = System.Text.Json.JsonSerializer.Serialize(config);
        Assert.DoesNotContain("pfx-secret-blob", json, StringComparison.Ordinal);
        Assert.Contains("\"SamlSigningKeyPfx\":null", json, StringComparison.Ordinal);

        // Core serializes with a camelCase policy; the value must stay hidden there too.
        var camel = System.Text.Json.JsonSerializer.Serialize(
            config,
            new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase });
        Assert.DoesNotContain("pfx-secret-blob", camel, StringComparison.Ordinal);

        // XML (on-disk config) must still persist it, so signing survives a restart.
        var serializer = new XmlSerializer(typeof(SamlConfig));
        using var writer = new System.IO.StringWriter();
        serializer.Serialize(writer, config);
        var xml = writer.ToString();
        Assert.Contains("SamlSigningKeyPfx", xml, StringComparison.Ordinal);
        Assert.Contains("pfx-secret-blob", xml, StringComparison.Ordinal);
    }

    [Fact]
    public void SamlSigningKey_IsDeserializedFromJson_SoItCanBeSetAndRotated()
    {
        const string body = "{\"SamlClientId\":\"sp\",\"SamlSigningKeyPfx\":\"typed-pfx\"}";
        var parsed = System.Text.Json.JsonSerializer.Deserialize<SamlConfig>(body);
        Assert.Equal("typed-pfx", parsed!.SamlSigningKeyPfx);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Preserve_BlankIncomingSigningKey_KeepsLiveKey(string? incomingKey)
    {
        // A config-page save arrives with the key blank (withheld from JSON) and must keep the stored one.
        var live = new PluginConfiguration();
        live.SamlConfigs["adfs"] = new SamlConfig { SamlSigningKeyPfx = "live-pfx" };
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["adfs"] = new SamlConfig { SamlSigningKeyPfx = incomingKey };

        ServerManagedFields.Preserve(incoming, live);

        Assert.Equal("live-pfx", incoming.SamlConfigs["adfs"].SamlSigningKeyPfx);
    }

    [Fact]
    public void Preserve_NonBlankIncomingSigningKey_IsKeptAsRotation()
    {
        var live = new PluginConfiguration();
        live.SamlConfigs["adfs"] = new SamlConfig { SamlSigningKeyPfx = "old-pfx" };
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["adfs"] = new SamlConfig { SamlSigningKeyPfx = "rotated-pfx" };

        ServerManagedFields.Preserve(incoming, live);

        Assert.Equal("rotated-pfx", incoming.SamlConfigs["adfs"].SamlSigningKeyPfx);
    }

    [Fact]
    public void Preserve_NewSamlProviderWithBlankSigningKey_StaysBlank()
    {
        var live = new PluginConfiguration();
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["fresh"] = new SamlConfig { SamlSigningKeyPfx = null };

        ServerManagedFields.Preserve(incoming, live);

        Assert.True(string.IsNullOrEmpty(incoming.SamlConfigs["fresh"].SamlSigningKeyPfx));
    }

    [Fact]
    public void ValidateSamlSigningKey_GarbageKey_ThrowsNamingProvider()
    {
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["idp"] = new SamlConfig { SamlSigningKeyPfx = "QUJD" }; // valid base64, not a PKCS#12

        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
        Assert.Contains("idp", ex.Message, StringComparison.Ordinal);
    }

    // --- Base-URL override validation on save (#139) ---

    [Fact]
    public void ValidateBaseUrlOverrides_ValidOrBlankOnBothProtocols_DoesNotThrow()
    {
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { BaseUrlOverride = "https://jellyfin.example.com" };
        incoming.OidConfigs["idp-blank"] = new OidConfig { BaseUrlOverride = null };
        incoming.SamlConfigs["saml"] = new SamlConfig { BaseUrlOverride = "https://sso.example.com/jellyfin" };
        incoming.SamlConfigs["saml-blank"] = new SamlConfig { BaseUrlOverride = "   " };

        ProviderConfigValidator.Validate(incoming, new PluginConfiguration());
    }

    [Fact]
    public void ValidateBaseUrlOverrides_MalformedOidOverride_ThrowsNamingProviderAndProtocol()
    {
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { BaseUrlOverride = "not-a-url" };

        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
        Assert.Contains("idp", ex.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateBaseUrlOverrides_MalformedSamlOverride_Throws()
    {
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["saml"] = new SamlConfig { BaseUrlOverride = "ftp://example.com" };

        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
        Assert.Contains("SAML", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateBaseUrlOverrides_NullConfigMaps_DoNotThrow()
    {
        var incoming = new PluginConfiguration { OidConfigs = null, SamlConfigs = null };

        ProviderConfigValidator.Validate(incoming, new PluginConfiguration());
    }

    // --- Provider-name validation on save (#336) ---

    [Fact]
    public void ValidateProviderNames_NewOidNameWithReservedCharacter_ThrowsNamingProviderAndProtocol()
    {
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["my/realm"] = new OidConfig();

        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
        Assert.Contains("my/realm", ex.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateProviderNames_NewSamlNameWithPercent_Throws()
    {
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["prov%1"] = new SamlConfig();

        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
        Assert.Contains("SAML", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateProviderNames_ExistingReservedNames_AreExemptOnBothProtocols()
    {
        // A reserved-character name already in the live config keeps saving: its callback-URL bytes
        // are what the identity provider has registered, so rejecting it would block every subsequent
        // config save of a working deployment behind a rename.
        var live = new PluginConfiguration();
        live.OidConfigs["kc=prod"] = new OidConfig();
        live.SamlConfigs["adfs (legacy)"] = new SamlConfig();
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["kc=prod"] = new OidConfig();
        incoming.SamlConfigs["adfs (legacy)"] = new SamlConfig();

        ProviderConfigValidator.Validate(incoming, live);
    }

    [Fact]
    public void ValidateProviderNames_SpacesAndNonAscii_StayAccepted()
    {
        // They survive the URL round-trip today (appended raw, pinned in SsoUrlBuilderTests), so the
        // registration gate rejects only what breaks the round-trip (control characters, the backslash,
        // and the URI-reserved set, #336/#360) — rejecting more would strand working names.
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["my provider"] = new OidConfig();
        incoming.SamlConfigs["käse"] = new SamlConfig();

        ProviderConfigValidator.Validate(incoming, new PluginConfiguration());
    }

    [Fact]
    public void ValidateProviderNames_NullLiveConfig_TreatsEveryNameAsNew()
    {
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["my/realm"] = new OidConfig();

        Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, null!));
    }

    [Theory]
    [InlineData(typeof(OidConfig))]
    [InlineData(typeof(SamlConfig))]
    public void BaseUrlOverride_InheritedFromProviderConfigBase_RoundTripsThroughXml(Type configType)
    {
        // BaseUrlOverride lives on the shared ProviderConfigBase (#139); confirm XmlSerializer still emits
        // and reads back the inherited property for both derived config types, so the base-class
        // extraction did not change the on-disk config contract.
        var config = (ProviderConfigBase)Activator.CreateInstance(configType)!;
        config.BaseUrlOverride = "https://jellyfin.example.com";

        var serializer = new XmlSerializer(configType);
        using var writer = new System.IO.StringWriter();
        serializer.Serialize(writer, config);
        var xml = writer.ToString();
        Assert.Contains("BaseUrlOverride", xml, StringComparison.Ordinal);
        Assert.Contains("https://jellyfin.example.com", xml, StringComparison.Ordinal);

        using var stringReader = new System.IO.StringReader(xml);
        using var xmlReader = System.Xml.XmlReader.Create(
            stringReader,
            new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null });
        var back = (ProviderConfigBase)serializer.Deserialize(xmlReader)!;
        Assert.Equal("https://jellyfin.example.com", back.BaseUrlOverride);
    }

    // --- Shared-member consolidation into ProviderConfigBase (#204) ---

    [Fact]
    public void SamlConfig_WithSharedAndSpecificMembers_RoundTripsThroughXml()
    {
        // The shared members (Enabled, roles, overrides, NewPath, CanonicalLinks, …) now live on
        // ProviderConfigBase. Serializing the concrete type must still emit and read back every one of
        // them, so the on-disk config contract is unchanged by the base-class extraction.
        var original = new SamlConfig
        {
            // Shared (base) members:
            BaseUrlOverride = "https://jellyfin.example.com",
            Enabled = true,
            EnableAuthorization = true,
            AllowExistingAccountLink = true,
            EnableAllFolders = true,
            EnabledFolders = new[] { "folder-a", "folder-b" },
            AdminRoles = new[] { "admin" },
            Roles = new[] { "user" },
            EnableFolderRoles = true,
            EnableLiveTvRoles = true,
            EnableLiveTv = true,
            EnableLiveTvManagement = true,
            LiveTvRoles = new[] { "tv" },
            LiveTvManagementRoles = new[] { "tv-admin" },
            FolderRoleMapping = new System.Collections.Generic.List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "user", Folders = new System.Collections.Generic.List<string> { "folder-a" } },
            },
            DefaultProvider = "provider",
            SchemeOverride = "https",
            PortOverride = 8443,
            NewPath = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-1"] = User },

            // Provider-specific members:
            SamlEndpoint = "https://idp/saml",
            SamlClientId = "sp-entity",
            SamlAudience = "sp-audience",
            DoNotValidateAudience = true,
            ValidateRecipient = true,
            ValidateInResponseTo = true,
            SignAuthnRequests = true,
            SamlSigningKeyPfx = "pfx-blob",
        };

        var back = RoundTripXml(original);

        Assert.Equal(original.BaseUrlOverride, back.BaseUrlOverride);
        Assert.True(back.Enabled);
        Assert.True(back.EnableAuthorization);
        Assert.True(back.AllowExistingAccountLink);
        Assert.True(back.EnableAllFolders);
        Assert.Equal(original.EnabledFolders, back.EnabledFolders);
        Assert.Equal(original.AdminRoles, back.AdminRoles);
        Assert.Equal(original.Roles, back.Roles);
        Assert.True(back.EnableFolderRoles);
        Assert.True(back.EnableLiveTvRoles);
        Assert.True(back.EnableLiveTv);
        Assert.True(back.EnableLiveTvManagement);
        Assert.Equal(original.LiveTvRoles, back.LiveTvRoles);
        Assert.Equal(original.LiveTvManagementRoles, back.LiveTvManagementRoles);
        Assert.Equal("user", back.FolderRoleMapping[0].Role);
        Assert.Equal("folder-a", back.FolderRoleMapping[0].Folders[0]);
        Assert.Equal("provider", back.DefaultProvider);
        Assert.Equal("https", back.SchemeOverride);
        Assert.Equal(8443, back.PortOverride);
        Assert.True(back.NewPath);
        Assert.Equal(User, back.CanonicalLinks["nameid-1"]);

        Assert.Equal("https://idp/saml", back.SamlEndpoint);
        Assert.Equal("sp-entity", back.SamlClientId);
        Assert.Equal("sp-audience", back.SamlAudience);
        Assert.True(back.DoNotValidateAudience);
        Assert.True(back.ValidateRecipient);
        Assert.True(back.ValidateInResponseTo);
        Assert.True(back.SignAuthnRequests);
        Assert.Equal("pfx-blob", back.SamlSigningKeyPfx);
    }

    [Fact]
    public void OidConfig_WithSharedAndSpecificMembers_RoundTripsThroughXml()
    {
        var original = new OidConfig
        {
            // Shared (base) members:
            BaseUrlOverride = "https://jellyfin.example.com",
            Enabled = true,
            SchemeOverride = "https",
            PortOverride = 8443,
            NewPath = true,
            Roles = new[] { "user" },
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User },

            // Provider-specific members:
            OidEndpoint = "https://idp/.well-known",
            OidClientId = "client",
            OidSecret = "s3cr3t",
            OidScopes = new[] { "openid", "profile" },
            RequirePkce = true,
        };

        var back = RoundTripXml(original);

        Assert.Equal(original.BaseUrlOverride, back.BaseUrlOverride);
        Assert.True(back.Enabled);
        Assert.Equal("https", back.SchemeOverride);
        Assert.Equal(8443, back.PortOverride);
        Assert.True(back.NewPath);
        Assert.Equal(original.Roles, back.Roles);
        Assert.Equal(User, back.CanonicalLinks["sub-1"]);

        Assert.Equal("https://idp/.well-known", back.OidEndpoint);
        Assert.Equal("client", back.OidClientId);
        Assert.Equal("s3cr3t", back.OidSecret);
        Assert.Equal(original.OidScopes, back.OidScopes);
        Assert.True(back.RequirePkce);
    }

    [Fact]
    public void LegacyElementOrder_StillDeserializes_AfterMembersMovedToBase()
    {
        // Existing installs wrote the config with the shared members AFTER the provider-specific ones
        // (their pre-#204 declaration order); the base-class extraction reverses that in newly written
        // XML. XML deserialization is by element name, not position, so an on-disk config in the old
        // order must still load every value. Element order here is deliberately the pre-refactor one.
        const string legacyXml = @"<?xml version=""1.0"" encoding=""utf-16""?>
<PluginConfiguration xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
  <SamlEndpoint>https://idp/saml</SamlEndpoint>
  <SamlClientId>sp-entity</SamlClientId>
  <DoNotValidateAudience>true</DoNotValidateAudience>
  <Enabled>true</Enabled>
  <EnableAuthorization>true</EnableAuthorization>
  <Roles>
    <string>user</string>
  </Roles>
  <SchemeOverride>https</SchemeOverride>
  <PortOverride>8443</PortOverride>
  <NewPath>true</NewPath>
  <CanonicalLinks>
    <item>
      <key>
        <string>nameid-1</string>
      </key>
      <value>
        <guid>11111111-1111-1111-1111-111111111111</guid>
      </value>
    </item>
  </CanonicalLinks>
  <BaseUrlOverride>https://jellyfin.example.com</BaseUrlOverride>
</PluginConfiguration>";

        var serializer = new XmlSerializer(typeof(SamlConfig));
        using var stringReader = new System.IO.StringReader(legacyXml);
        using var xmlReader = System.Xml.XmlReader.Create(
            stringReader,
            new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null });
        var back = (SamlConfig)serializer.Deserialize(xmlReader)!;

        Assert.Equal("https://idp/saml", back.SamlEndpoint);
        Assert.Equal("sp-entity", back.SamlClientId);
        Assert.True(back.DoNotValidateAudience);
        Assert.True(back.Enabled);
        Assert.True(back.EnableAuthorization);
        Assert.Equal(new[] { "user" }, back.Roles);
        Assert.Equal("https", back.SchemeOverride);
        Assert.Equal(8443, back.PortOverride);
        Assert.True(back.NewPath);
        Assert.Equal(User, back.CanonicalLinks["nameid-1"]);
        Assert.Equal("https://jellyfin.example.com", back.BaseUrlOverride);
    }

    private static T RoundTripXml<T>(T value)
    {
        var serializer = new XmlSerializer(typeof(T));
        using var writer = new System.IO.StringWriter();
        serializer.Serialize(writer, value);

        using var stringReader = new System.IO.StringReader(writer.ToString());
        using var xmlReader = System.Xml.XmlReader.Create(
            stringReader,
            new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null });
        return (T)serializer.Deserialize(xmlReader)!;
    }

    // --- SAML certificate validation on save (#206) ---

    [Fact]
    public void ValidateSamlCertificates_ValidOrBlank_DoesNotThrow()
    {
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["ok"] = new SamlConfig { SamlCertificate = SamlTestFactory.Create().CertificateBase64 };
        incoming.SamlConfigs["blank"] = new SamlConfig { SamlCertificate = null };

        ProviderConfigValidator.Validate(incoming, new PluginConfiguration());
    }

    [Fact]
    public void ValidateSamlCertificates_GarbageCertificate_ThrowsNamingProvider()
    {
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["idp"] = new SamlConfig { SamlCertificate = "QUJD" }; // valid base64, not a cert

        var ex = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
        Assert.Contains("idp", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateSamlCertificates_NullMap_DoesNotThrow()
    {
        ProviderConfigValidator.Validate(new PluginConfiguration { SamlConfigs = null }, new PluginConfiguration());
    }
}
