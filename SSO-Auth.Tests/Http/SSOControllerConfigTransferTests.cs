using System;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the config export/import endpoints (#161) via <see cref="SsoControllerHarness"/>,
/// so the export redaction and the import merge run through the REAL configuration store and secret-at-rest
/// encryption, not just the pure helpers (ConfigExportImportTests covers those). Proves: the exported
/// document leaks no secret; a round-trip import keeps the target's stored secret and links while merging
/// the non-secret config; and a malformed/invalid import is rejected fail-closed and persists nothing.
/// </summary>
[Collection("SSOController")]
public class SSOControllerConfigTransferTests
{
    private static readonly Guid TargetUser = Guid.Parse("44444444-4444-4444-4444-444444444444");

    private static ConfigExportDocument WireRoundTrip(ConfigExportDocument document) =>
        JsonSerializer.Deserialize<ConfigExportDocument>(JsonSerializer.Serialize(document))!;

    private static ConfigExportDocument ExportedDocument(SsoControllerHarness harness) =>
        Assert.IsType<ConfigExportDocument>(Assert.IsType<OkObjectResult>(harness.Controller.ExportConfig()).Value);

    [Fact]
    public void ExportConfig_SerializedResponse_LeaksNoSecret()
    {
        var harness = new SsoControllerHarness(c =>
        {
            c.OidConfigs["idp"] = new OidConfig { OidClientId = "client-1", OidSecret = "PLAINTEXT-OIDC-SECRET" };
            c.SamlConfigs["saml"] = new SamlConfig { SamlEndpoint = "https://saml.example.com", SamlSigningKeyPfx = "PLAINTEXT-SAML-KEY" };
        });

        var json = JsonSerializer.Serialize(ExportedDocument(harness));

        Assert.DoesNotContain("PLAINTEXT-OIDC-SECRET", json, StringComparison.Ordinal);
        Assert.DoesNotContain("PLAINTEXT-SAML-KEY", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ssoenc:", json, StringComparison.Ordinal);
        Assert.Contains("idp", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ImportConfig_RoundTrip_KeepsStoredSecretAndLinks_AndMergesNonSecretConfig()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["idp"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.com",
            OidClientId = "client-1",
            OidSecret = "STORED-SECRET",
            EnableAuthorization = false,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = TargetUser },
        });

        // Take the redacted document the export would hand out, flip a non-secret setting, and re-import it.
        var wire = WireRoundTrip(ExportedDocument(harness));
        wire.Configuration!.OidConfigs["idp"].EnableAuthorization = true;

        var result = harness.Controller.ImportConfig(wire);

        Assert.IsType<NoContentResult>(result);
        var merged = harness.Configuration.OidConfigs["idp"];
        // The stored secret survives the round-trip (blank-means-keep, #189) — revealed because the persist
        // path encrypts it at rest (#158).
        Assert.Equal("STORED-SECRET", SSOPlugin.Instance.Secrets.Reveal(merged.OidSecret));
        // The server-managed link is preserved (#157), and the non-secret toggle is merged from the import.
        Assert.Equal(TargetUser, merged.CanonicalLinks["sub-1"]);
        Assert.True(merged.EnableAuthorization);
    }

    [Fact]
    public void ImportConfig_NullDocument_ReturnsBadRequest_PersistsNothing()
    {
        var harness = new SsoControllerHarness();

        Assert.IsType<BadRequestObjectResult>(harness.Controller.ImportConfig(null!));

        harness.Xml.DidNotReceive().SerializeToFile(Arg.Any<object>(), Arg.Any<string>());
    }

    [Fact]
    public void ImportConfig_UnsupportedVersion_ReturnsBadRequest_PersistsNothing()
    {
        var harness = new SsoControllerHarness();
        var document = new ConfigExportDocument { FormatVersion = 999, Configuration = new PluginConfiguration() };

        Assert.IsType<BadRequestObjectResult>(harness.Controller.ImportConfig(document));

        harness.Xml.DidNotReceive().SerializeToFile(Arg.Any<object>(), Arg.Any<string>());
    }

    [Fact]
    public void ImportConfig_InvalidProvider_ReturnsBadRequest_PersistsNothing_AndLeavesConfigUntouched()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["existing"] = new OidConfig { OidClientId = "unchanged" });

        var imported = new PluginConfiguration();
        imported.OidConfigs["bad"] = new OidConfig { BaseUrlOverride = "not-a-url" };
        var document = new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported };

        Assert.IsType<BadRequestObjectResult>(harness.Controller.ImportConfig(document));

        // Fail-closed: the invalid document is rejected before anything is persisted or merged in memory.
        harness.Xml.DidNotReceive().SerializeToFile(Arg.Any<object>(), Arg.Any<string>());
        Assert.False(harness.Configuration.OidConfigs.ContainsKey("bad"));
        Assert.Equal("unchanged", harness.Configuration.OidConfigs["existing"].OidClientId);
    }

    [Fact]
    public void ImportConfig_ValidDocument_Persists()
    {
        var harness = new SsoControllerHarness();
        var imported = new PluginConfiguration();
        imported.OidConfigs["new-idp"] = new OidConfig { OidEndpoint = "https://idp.example.com", OidClientId = "c" };
        var document = new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported };

        Assert.IsType<NoContentResult>(harness.Controller.ImportConfig(document));

        harness.Xml.Received().SerializeToFile(Arg.Any<object>(), Arg.Any<string>());
        Assert.True(harness.Configuration.OidConfigs.ContainsKey("new-idp"));
    }
}
