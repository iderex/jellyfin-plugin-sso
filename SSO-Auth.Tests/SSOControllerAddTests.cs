using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the provider-add endpoints via <see cref="SsoControllerHarness"/>: a valid
/// config is stored, a malformed base-URL override is rejected fail-closed, a re-save preserves
/// the server-managed canonical links (#157) that the API body never carries, and a NEW provider
/// name containing URI-reserved characters is rejected while an existing one stays updatable (#336).
/// </summary>
[Collection("SSOController")]
public class SSOControllerAddTests
{
    private static readonly Guid User = Guid.Parse("33333333-3333-3333-3333-333333333333");

    [Fact]
    public void OidAdd_ValidConfig_StoresTheProvider()
    {
        var harness = new SsoControllerHarness();

        harness.Controller.OidAdd("keycloak", new OidConfig { OidClientId = "client-1" });

        var stored = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].OidClientId);
        Assert.Equal("client-1", stored);
    }

    [Fact]
    public void OidAdd_MalformedBaseUrlOverride_Throws_AndDoesNotPersist()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.OidAdd("keycloak", new OidConfig { BaseUrlOverride = "not-a-url" }));

        // Fail-closed: the reject runs before the write, so nothing was persisted.
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("keycloak")));
    }

    [Fact]
    public void OidAdd_ReSaveOfExisting_PreservesCanonicalLinks()
    {
        var harness = new SsoControllerHarness(c =>
            c.OidConfigs["keycloak"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User } });

        // Re-add the same provider with a fresh config carrying no links, as the [JsonIgnore] API body would.
        harness.Controller.OidAdd("keycloak", new OidConfig());

        var links = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks);
        Assert.Equal(User, links["sub-1"]);
    }

    [Fact]
    public void SamlAdd_ValidConfig_StoresTheProvider_ReturnsOk()
    {
        var harness = new SsoControllerHarness();

        Assert.IsType<OkResult>(harness.Controller.SamlAdd("adfs", new SamlConfig { SamlClientId = "client-1" }));

        var stored = SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].SamlClientId);
        Assert.Equal("client-1", stored);
    }

    [Fact]
    public void SamlAdd_MalformedBaseUrlOverride_Throws_AndDoesNotPersist()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.SamlAdd("adfs", new SamlConfig { BaseUrlOverride = "not-a-url" }));

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.ContainsKey("adfs")));
    }

    [Fact]
    public void SamlAdd_ReSaveOfExisting_PreservesCanonicalLinks()
    {
        var harness = new SsoControllerHarness(c =>
            c.SamlConfigs["adfs"] = new SamlConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-1"] = User } });

        harness.Controller.SamlAdd("adfs", new SamlConfig());

        var links = SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].CanonicalLinks);
        Assert.Equal(User, links["nameid-1"]);
    }

    // --- Provider-name validation at registration (#336) ---

    [Fact]
    public void OidAdd_NewProviderWithReservedName_Throws_AndDoesNotPersist()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.OidAdd("my/realm", new OidConfig()));

        // Fail-closed: the guard runs inside the mutation before any write, so nothing was persisted.
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("my/realm")));
    }

    [Fact]
    public void OidAdd_ExistingProviderWithReservedName_StillUpdates()
    {
        // An already-configured reserved-character name is exempt (#336): its callback-URL bytes are
        // registered at the IdP, so the update path must keep working for existing deployments.
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc=prod"] = new OidConfig());

        harness.Controller.OidAdd("kc=prod", new OidConfig { OidClientId = "client-2" });

        var stored = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["kc=prod"].OidClientId);
        Assert.Equal("client-2", stored);
    }

    [Fact]
    public void SamlAdd_NewProviderWithReservedName_Throws_AndDoesNotPersist()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.SamlAdd("prov%1", new SamlConfig()));

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.ContainsKey("prov%1")));
    }

    [Fact]
    public void SamlAdd_ExistingProviderWithReservedName_StillUpdates()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs (legacy)"] = new SamlConfig());

        Assert.IsType<OkResult>(harness.Controller.SamlAdd("adfs (legacy)", new SamlConfig { SamlClientId = "client-2" }));

        var stored = SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs (legacy)"].SamlClientId);
        Assert.Equal("client-2", stored);
    }
}
