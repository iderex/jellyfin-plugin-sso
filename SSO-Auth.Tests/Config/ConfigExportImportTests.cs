using System;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for the config export/import helpers (#161): <see cref="ConfigExport"/> produces a document whose
/// serialization redacts every secret and server-managed link (reusing the config's own JSON-boundary
/// withholding, not a second redaction), and <see cref="ConfigImport"/> validates fail-closed and merges
/// without wiping the target's secrets, links, or NewPath. The controller wiring is covered separately
/// (SSOControllerConfigTransferTests); these pin the pure logic with no plugin instance involved.
/// </summary>
public class ConfigExportImportTests
{
    private static readonly Guid TargetUser = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid SourceUser = Guid.Parse("33333333-3333-3333-3333-333333333333");

    // A round-trip through System.Text.Json, exactly as the export endpoint (serialize) and the import
    // endpoint (deserialize) do, so a test starts from the real on-the-wire (redacted) document.
    private static ConfigExportDocument WireRoundTrip(ConfigExportDocument document) =>
        JsonSerializer.Deserialize<ConfigExportDocument>(JsonSerializer.Serialize(document))!;

    [Fact]
    public void Export_SerializedDocument_ContainsNoSecretEnvelopeOrLink()
    {
        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.com/.well-known/openid-configuration",
            OidClientId = "client-1",
            OidSecret = "TOP-SECRET-OIDC-VALUE",
            EnableAuthorization = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = TargetUser },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-1"] = "https://idp.example.com" },
        };
        live.SamlConfigs["saml"] = new SamlConfig
        {
            SamlEndpoint = "https://saml.example.com/sso",
            SamlSigningKeyPfx = "TOP-SECRET-SAML-SIGNING-KEY",
            SamlRolloverSigningKeyPfx = "TOP-SECRET-SAML-ROLLOVER-KEY",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-1"] = TargetUser },
        };

        var json = JsonSerializer.Serialize(ConfigExport.Build(live));

        // The secrets and link maps are withheld by the config's own converters/[JsonIgnore] (#189/#157/#186),
        // so no secret value, no ssoenc: envelope prefix, and no canonical-link map name can appear.
        Assert.DoesNotContain("TOP-SECRET-OIDC-VALUE", json, StringComparison.Ordinal);
        Assert.DoesNotContain("TOP-SECRET-SAML-SIGNING-KEY", json, StringComparison.Ordinal);
        Assert.DoesNotContain("TOP-SECRET-SAML-ROLLOVER-KEY", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ssoenc:", json, StringComparison.Ordinal);
        Assert.DoesNotContain("CanonicalLinks", json, StringComparison.Ordinal);
        Assert.DoesNotContain("CanonicalLinkIssuers", json, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-1", json, StringComparison.Ordinal);
        Assert.DoesNotContain("nameid-1", json, StringComparison.Ordinal);

        // But the non-secret configuration IS present, so the document is a usable export.
        Assert.Contains("idp", json, StringComparison.Ordinal);
        Assert.Contains("client-1", json, StringComparison.Ordinal);
        Assert.Contains("https://saml.example.com/sso", json, StringComparison.Ordinal);
        Assert.Contains("\"FormatVersion\":1", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Import_RoundTrip_PreservesTargetSecretLinksAndNewPath_AndMergesNonSecretConfig()
    {
        // Source instance: a provider with a secret and its own links, plus a security toggle to merge.
        var source = new PluginConfiguration();
        source.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.com",
            OidClientId = "client-1",
            OidSecret = "SOURCE-SECRET",
            EnableAuthorization = true,
            NewPath = false,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-src"] = SourceUser },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-src"] = "https://idp.example.com" },
        };

        var wire = WireRoundTrip(ConfigExport.Build(source));

        // Target instance already has the provider with its OWN stored secret, links and NewPath.
        var target = new PluginConfiguration();
        target.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.com",
            OidClientId = "client-1",
            OidSecret = "TARGET-SECRET",
            NewPath = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-tgt"] = TargetUser },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-tgt"] = "https://idp.example.com" },
        };

        ConfigImport.Apply(target, wire);

        var merged = target.OidConfigs["idp"];
        // Blank (redacted) secret in the import keeps the target's stored secret (#189).
        Assert.Equal("TARGET-SECRET", merged.OidSecret);
        // Server-managed links/issuers are the target's, never wiped by the import (#157/#186).
        Assert.Equal(TargetUser, merged.CanonicalLinks["sub-tgt"]);
        Assert.Equal("https://idp.example.com", merged.CanonicalLinkIssuers["sub-tgt"]);
        Assert.False(merged.CanonicalLinks.ContainsKey("sub-src"));
        // NewPath (server-managed runtime state) is kept from the target, not overwritten by the document.
        Assert.True(merged.NewPath);
        // The non-secret config IS merged from the import.
        Assert.True(merged.EnableAuthorization);
    }

    [Fact]
    public void Import_SamlProvider_KeepsTargetSigningKeys_WhenImportRedacted()
    {
        var source = new PluginConfiguration();
        source.SamlConfigs["saml"] = new SamlConfig
        {
            SamlEndpoint = "https://saml.example.com/sso",
            SignAuthnRequests = true,
            SamlSigningKeyPfx = "SOURCE-KEY",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-src"] = SourceUser },
        };
        var wire = WireRoundTrip(ConfigExport.Build(source));

        var target = new PluginConfiguration();
        target.SamlConfigs["saml"] = new SamlConfig
        {
            SamlEndpoint = "https://old.example.com/sso",
            SamlSigningKeyPfx = "TARGET-KEY",
            SamlRolloverSigningKeyPfx = "TARGET-ROLLOVER",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-tgt"] = TargetUser },
        };

        ConfigImport.Apply(target, wire);

        var merged = target.SamlConfigs["saml"];
        Assert.Equal("TARGET-KEY", merged.SamlSigningKeyPfx);
        Assert.Equal("TARGET-ROLLOVER", merged.SamlRolloverSigningKeyPfx);
        Assert.Equal(TargetUser, merged.CanonicalLinks["nameid-tgt"]);
        // The non-secret endpoint IS merged.
        Assert.Equal("https://saml.example.com/sso", merged.SamlEndpoint);
        Assert.True(merged.SignAuthnRequests);
    }

    [Fact]
    public void Import_NewProvider_ArrivesWithBlankSecret_FailsClosed()
    {
        var source = new PluginConfiguration();
        source.OidConfigs["fresh"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.com",
            OidClientId = "client-fresh",
            OidSecret = "SOURCE-SECRET",
        };
        var wire = WireRoundTrip(ConfigExport.Build(source));

        var target = new PluginConfiguration();

        ConfigImport.Apply(target, wire);

        // The provider is added, but its secret is blank (redacted out of the export) — the login fails
        // closed until an admin re-enters it; no attacker-chosen secret was imported.
        Assert.True(target.OidConfigs.ContainsKey("fresh"));
        Assert.True(string.IsNullOrEmpty(target.OidConfigs["fresh"].OidSecret));
        Assert.Empty(target.OidConfigs["fresh"].CanonicalLinks);
    }

    [Fact]
    public void Import_LeavesTargetOnlyProvidersUntouched_ItIsAMergeNotAReplace()
    {
        var source = new PluginConfiguration();
        source.OidConfigs["from-import"] = new OidConfig { OidEndpoint = "https://idp.example.com", OidClientId = "c" };
        var wire = WireRoundTrip(ConfigExport.Build(source));

        var target = new PluginConfiguration();
        target.OidConfigs["target-only"] = new OidConfig { OidClientId = "keep-me" };

        ConfigImport.Apply(target, wire);

        Assert.True(target.OidConfigs.ContainsKey("target-only"));
        Assert.Equal("keep-me", target.OidConfigs["target-only"].OidClientId);
        Assert.True(target.OidConfigs.ContainsKey("from-import"));
    }

    [Fact]
    public void Import_DoesNotImportGlobalRateLimitSettings_KeepsTheTargetsOwn()
    {
        // Rate-limit tuning is instance-local operational config (reverse-proxy dependent); importing it
        // would let a document with rate limiting off SILENTLY disable a DoS control on a target that had it
        // on. The import keeps the target's limiter configuration.
        var source = new PluginConfiguration { EnableRateLimit = false, RateLimitMaxAttempts = 999, RateLimitWindowSeconds = 1 };
        var wire = WireRoundTrip(ConfigExport.Build(source));
        var target = new PluginConfiguration { EnableRateLimit = true, RateLimitMaxAttempts = 7, RateLimitWindowSeconds = 90 };

        ConfigImport.Apply(target, wire);

        Assert.True(target.EnableRateLimit);
        Assert.Equal(7, target.RateLimitMaxAttempts);
        Assert.Equal(90, target.RateLimitWindowSeconds);
    }

    [Fact]
    public void Export_RedactionSurvivesTheMvcCamelCaseSerializer()
    {
        // The endpoint returns Ok(document); ASP.NET Core MVC serializes with camelCase + case-insensitive
        // read. Prove the write-only secret redaction (which is attribute-, not name-, based) still holds and
        // a round-trip through those options works — the on-the-wire path the controller actually uses.
        var options = new System.Text.Json.JsonSerializerOptions
        {
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
        };

        var live = new PluginConfiguration();
        live.OidConfigs["idp"] = new OidConfig { OidEndpoint = "https://idp.example.com", OidClientId = "client-1", OidSecret = "MVC-WIRE-SECRET" };

        var json = JsonSerializer.Serialize(ConfigExport.Build(live), options);
        Assert.DoesNotContain("MVC-WIRE-SECRET", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ssoenc:", json, StringComparison.Ordinal);

        // The camelCase document deserializes back (case-insensitive) with the provider intact and the secret
        // still redacted to null.
        var wire = JsonSerializer.Deserialize<ConfigExportDocument>(json, options)!;
        Assert.Equal("client-1", wire.Configuration!.OidConfigs["idp"].OidClientId);
        Assert.True(string.IsNullOrEmpty(wire.Configuration!.OidConfigs["idp"].OidSecret));
    }

    [Fact]
    public void Import_UnsupportedVersion_Throws_AndLeavesTargetUntouched()
    {
        var target = new PluginConfiguration();
        target.OidConfigs["existing"] = new OidConfig { OidClientId = "unchanged" };
        var document = new ConfigExportDocument { FormatVersion = 999, Configuration = new PluginConfiguration() };

        Assert.Throws<ArgumentException>(() => ConfigImport.Apply(target, document));

        Assert.Single(target.OidConfigs);
        Assert.Equal("unchanged", target.OidConfigs["existing"].OidClientId);
    }

    [Fact]
    public void Import_NullPayload_Throws()
    {
        var document = new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = null };

        Assert.Throws<ArgumentException>(() => ConfigImport.Apply(new PluginConfiguration(), document));
    }

    [Fact]
    public void Import_InvalidProvider_Throws_AndPersistsNothing_FailClosed()
    {
        // A hostile document with a malformed Base URL override must be rejected by ProviderConfigValidator
        // before any provider is merged, so the target is left exactly as it was (atomic, fail-closed).
        var target = new PluginConfiguration();
        target.OidConfigs["existing"] = new OidConfig { OidClientId = "unchanged" };

        var imported = new PluginConfiguration();
        imported.OidConfigs["bad"] = new OidConfig { BaseUrlOverride = "not-a-url" };
        var document = new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported };

        Assert.Throws<ArgumentException>(() => ConfigImport.Apply(target, document));

        Assert.False(target.OidConfigs.ContainsKey("bad"));
        Assert.Single(target.OidConfigs);
        Assert.Equal("unchanged", target.OidConfigs["existing"].OidClientId);
    }

    [Fact]
    public void Import_NewProviderWithReservedName_Throws_FailClosed()
    {
        // A new provider name with URI-reserved characters becomes part of the callback URL, so the import
        // rejects it exactly as the config-page save does (#336/#360).
        var imported = new PluginConfiguration();
        imported.OidConfigs["my/realm"] = new OidConfig();
        var document = new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported };

        Assert.Throws<ArgumentException>(() => ConfigImport.Apply(new PluginConfiguration(), document));
    }

    [Fact]
    public void Import_NullConfigurationOrDocument_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ConfigImport.Apply(null!, new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = new PluginConfiguration() }));
        Assert.Throws<ArgumentNullException>(() => ConfigImport.Apply(new PluginConfiguration(), null!));
    }
}
