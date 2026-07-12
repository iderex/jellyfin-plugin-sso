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
}
