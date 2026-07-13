using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the provider-add endpoints via <see cref="SsoControllerHarness"/>: a valid
/// config is stored, a malformed base-URL override is rejected fail-closed, and a re-save preserves
/// the server-managed canonical links (#157) that the API body never carries.
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
}
