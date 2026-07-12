using System;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for the server-managed-field handling (#157): canonical links are preserved across a save
/// built from a stale client snapshot (<see cref="SSOPlugin.PreserveServerManagedFields"/>), are
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

        SSOPlugin.PreserveServerManagedFields(incoming, live);

        Assert.Equal(User, incoming.OidConfigs["idp"].CanonicalLinks["sub-1"]);
        Assert.Equal(User, incoming.SamlConfigs["saml"].CanonicalLinks["nameid-1"]);
    }

    [Fact]
    public void Preserve_NewProviderNotInLive_KeepsItsOwnEmptyMap()
    {
        var live = new PluginConfiguration();
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["fresh"] = new OidConfig();

        SSOPlugin.PreserveServerManagedFields(incoming, live);

        Assert.Empty(incoming.OidConfigs["fresh"].CanonicalLinks);
    }

    [Fact]
    public void Preserve_ProviderDeletedInIncoming_IsNotReAdded()
    {
        // Deleting a provider must survive the save: a provider present only in live is not resurrected.
        var live = new PluginConfiguration();
        live.OidConfigs["gone"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub"] = User } };
        var incoming = new PluginConfiguration();

        SSOPlugin.PreserveServerManagedFields(incoming, live);

        Assert.False(incoming.OidConfigs.ContainsKey("gone"));
    }

    [Fact]
    public void Preserve_NullConfigMaps_DoNotThrow()
    {
        var incoming = new PluginConfiguration { OidConfigs = null, SamlConfigs = null };
        var live = new PluginConfiguration { OidConfigs = null, SamlConfigs = null };

        // Fail-safe: a malformed config with missing maps must not NRE the save path.
        SSOPlugin.PreserveServerManagedFields(incoming, live);
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
        // PreserveServerManagedFields runs against the live config — the new secret must win.
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig { OidSecret = "old-secret" };

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = System.Text.Json.JsonSerializer.Deserialize<OidConfig>(
            "{\"OidSecret\":\"rotated-secret\"}")!;

        SSOPlugin.PreserveServerManagedFields(incoming, live);

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

        SSOPlugin.PreserveServerManagedFields(incoming, live);

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

        SSOPlugin.PreserveServerManagedFields(incoming, live);

        Assert.True(string.IsNullOrEmpty(incoming.OidConfigs["fresh"].OidSecret));
    }

    [Fact]
    public void ResolveUpdatedSecret_BlankAndIdentityUnchanged_KeepsLiveSecret()
    {
        var live = new OidConfig { OidEndpoint = "https://idp/.well-known", OidClientId = "cid", OidSecret = "live" };
        var incoming = new OidConfig { OidEndpoint = "https://idp/.well-known", OidClientId = "cid", OidSecret = "  " };

        Assert.Equal("live", SSOPlugin.ResolveUpdatedSecret(incoming, live));
    }

    [Fact]
    public void ResolveUpdatedSecret_NonBlank_IsAlwaysKept_AsRotation()
    {
        var live = new OidConfig { OidEndpoint = "https://idp/.well-known", OidClientId = "cid", OidSecret = "live" };
        var incoming = new OidConfig { OidEndpoint = "https://idp/.well-known", OidClientId = "cid", OidSecret = "rotated" };

        Assert.Equal("rotated", SSOPlugin.ResolveUpdatedSecret(incoming, live));
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

        Assert.True(string.IsNullOrEmpty(SSOPlugin.ResolveUpdatedSecret(incoming, live)));
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

        SSOPlugin.ValidateBaseUrlOverrides(incoming);
    }

    [Fact]
    public void ValidateBaseUrlOverrides_MalformedOidOverride_ThrowsNamingProviderAndProtocol()
    {
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { BaseUrlOverride = "not-a-url" };

        var ex = Assert.Throws<ArgumentException>(() => SSOPlugin.ValidateBaseUrlOverrides(incoming));
        Assert.Contains("idp", ex.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateBaseUrlOverrides_MalformedSamlOverride_Throws()
    {
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["saml"] = new SamlConfig { BaseUrlOverride = "ftp://example.com" };

        var ex = Assert.Throws<ArgumentException>(() => SSOPlugin.ValidateBaseUrlOverrides(incoming));
        Assert.Contains("SAML", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateBaseUrlOverrides_NullConfigMaps_DoNotThrow()
    {
        var incoming = new PluginConfiguration { OidConfigs = null, SamlConfigs = null };

        SSOPlugin.ValidateBaseUrlOverrides(incoming);
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
}
