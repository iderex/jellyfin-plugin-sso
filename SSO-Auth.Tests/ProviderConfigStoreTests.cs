using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="ProviderConfigStore"/> — the owner of configuration reads, mutations, and the
/// validated save pipeline extracted from SSOPlugin (#318). The validation and preservation rules have
/// their own suite (ConfigPreservationTests); these pin the store's orchestration: what the pipeline
/// runs for a fresh incoming config, what it skips for the live object, and what reaches the persist
/// delegate. The store is exercised directly with local delegates, so no plugin instance is involved.
/// </summary>
public class ProviderConfigStoreTests
{
    private static readonly Guid User = Guid.Parse("44444444-4444-4444-4444-444444444444");

    private static (ProviderConfigStore Store, PluginConfiguration Live, List<BasePluginConfiguration> Persisted) CreateStore(ILogger? logger = null)
    {
        var live = new PluginConfiguration();
        var persisted = new List<BasePluginConfiguration>();
        return (new ProviderConfigStore(() => live, persisted.Add, logger!), live, persisted);
    }

    [Fact]
    public void Read_ReadsTheLiveConfiguration()
    {
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["idp"] = new OidConfig { OidClientId = "client-1" };

        Assert.Equal("client-1", store.Read(c => c.OidConfigs["idp"].OidClientId));
        Assert.Empty(persisted); // A read never persists.
    }

    [Fact]
    public void Mutate_AppliesTheMutation_AndPersistsTheLiveObject()
    {
        var (store, live, persisted) = CreateStore();

        store.Mutate(c => c.OidConfigs["idp"] = new OidConfig());

        Assert.True(live.OidConfigs.ContainsKey("idp"));
        Assert.Same(live, Assert.Single(persisted));
    }

    [Fact]
    public void Mutate_WithResult_ReturnsIt_AndPersists()
    {
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["idp"] = new OidConfig();

        var removed = store.Mutate(c => c.OidConfigs.Remove("idp"));

        Assert.True(removed);
        Assert.Same(live, Assert.Single(persisted));
    }

    [Fact]
    public void Save_FreshConfigWithMalformedOverride_Throws_AndPersistsNothing()
    {
        // The fail-closed gate (#139): a replacement config is validated BEFORE anything is persisted.
        var (store, _, persisted) = CreateStore();
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig { BaseUrlOverride = "not-a-url" };

        Assert.Throws<ArgumentException>(() => store.Save(incoming));

        Assert.Empty(persisted);
    }

    [Fact]
    public void Save_FreshConfig_PreservesServerManagedFields_AndPersistsIt()
    {
        // The stale-snapshot save (#157/#189): a posted config carrying neither links nor secret must
        // get both re-injected from the live config before it reaches the persist delegate.
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["idp"] = new OidConfig
        {
            OidSecret = "live-secret",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = User },
        };
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["idp"] = new OidConfig();

        store.Save(incoming);

        Assert.Same(incoming, Assert.Single(persisted));
        Assert.Equal("live-secret", incoming.OidConfigs["idp"].OidSecret);
        Assert.Equal(User, incoming.OidConfigs["idp"].CanonicalLinks["sub-1"]);
    }

    [Fact]
    public void Save_TheLiveObject_SkipsTheFreshConfigPipeline()
    {
        // Writes that reuse the live object (Mutate, login-path link writes) are intentionally never
        // revalidated: even a malformed override already sitting in the live config must not make the
        // save throw, so the login path can never be blocked by the config-page gate.
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["idp"] = new OidConfig { BaseUrlOverride = "not-a-url" };

        store.Save(live);

        Assert.Same(live, Assert.Single(persisted));
    }

    [Fact]
    public void Save_FreshConfigWithInsecureOptions_PersistsAndAuditsThem()
    {
        // The #140 audit: saving a provider with a disabled security check emits a warning naming the
        // provider and the option — after the save, so a logging provider cannot fail a completed save.
        var logger = new CapturingLogger();
        var (store, _, persisted) = CreateStore(logger);
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["corp"] = new OidConfig { DisableHttps = true };

        store.Save(incoming);

        Assert.Single(persisted);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("corp", entry.Message, StringComparison.Ordinal);
        Assert.Contains("DisableHttps", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Save_WithoutALogger_StillPersistsInsecureOptions_WithoutThrowing()
    {
        // The audit is best-effort: a missing logger must never turn a valid save into a failure.
        var (store, _, persisted) = CreateStore(logger: null);
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["corp"] = new OidConfig { DisableHttps = true };

        store.Save(incoming);

        Assert.Single(persisted);
    }

    [Fact]
    public void NullArguments_Throw()
    {
        var (store, _, _) = CreateStore();

        Assert.Throws<ArgumentNullException>(() => store.Save(null!));
        Assert.Throws<ArgumentNullException>(() => store.Read<bool>(null!));
        Assert.Throws<ArgumentNullException>(() => store.Mutate(null!));
        Assert.Throws<ArgumentNullException>(() => store.Mutate<bool>(null!));
    }
}
