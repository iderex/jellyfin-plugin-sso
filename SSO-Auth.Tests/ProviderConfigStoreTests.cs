using System;
using System.Collections.Generic;
using System.Threading.Tasks;
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
    public void Save_FreshConfigWithNewReservedName_Throws_AndPersistsNothing()
    {
        // The registration gate (#336): a name absent from the live config is validated before
        // anything is persisted.
        var (store, _, persisted) = CreateStore();
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["my/realm"] = new OidConfig();

        Assert.Throws<ArgumentException>(() => store.Save(incoming));

        Assert.Empty(persisted);
    }

    [Fact]
    public void Save_FreshConfigWithExistingReservedName_IsExempt_AndPersists()
    {
        // The store hands its live config to the validator, so a reserved-character name that is
        // already configured keeps saving — its callback-URL bytes are what the IdP has registered,
        // and blocking the save would strand the deployment behind a rename (#336).
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["kc=prod"] = new OidConfig();
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["kc=prod"] = new OidConfig();

        store.Save(incoming);

        Assert.Same(incoming, Assert.Single(persisted));
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
    public async Task Mutate_ConcurrentReadModifyWrites_NeverLoseAnUpdate()
    {
        // Race regression for #412: the challenge flow now records the server-managed NewPath spelling
        // through Mutate instead of an unsynchronized field write, specifically so two concurrent
        // challenges cannot race a read-modify-write and lose one another's update. This pins the
        // general property that guarantee rests on: every Mutate call is a fully serialized
        // read-modify-write, so N concurrent increments through the store are never dropped — if the
        // store's lock were removed (or a caller bypassed it, as the pre-fix NewPath write did), some
        // increments would race and the final count would fall short of N.
        var (store, live, _) = CreateStore();
        live.RateLimitMaxAttempts = 0; // the constructor default (30) would otherwise fold into the count
        var ct = TestContext.Current.CancellationToken;

        const int concurrency = 64;
        var tasks = new Task[concurrency];
        for (var i = 0; i < concurrency; i++)
        {
            tasks[i] = Task.Run(() => store.Mutate(c => c.RateLimitMaxAttempts++), ct);
        }

        await Task.WhenAll(tasks);

        Assert.Equal(concurrency, live.RateLimitMaxAttempts);
    }

    [Fact]
    public async Task Mutate_ConcurrentChallengeStyleReadThenWrite_NeverThrows_AndSettlesOnADerivedSpelling()
    {
        // Mirrors ChallengeNewPathResolver.ResolveChallengeNewPath's shape (#412, unified in #670): a fast Read,
        // then a Mutate only when the derived spelling differs from what is stored — never a bare field
        // write outside the lock. Concurrent callers alternate between the two derivable spellings for
        // "kc" while OTHER concurrent callers add and remove UNRELATED provider entries — a genuine
        // structural dictionary mutation racing the "kc" reads. This is the exact hazard Read's own doc
        // comment cites (a Dictionary read-during-write is undefined behavior in .NET: throw, misread, or
        // a spin on a corrupted chain during a resize) — without the store's lock, THIS combination could
        // actually throw or corrupt state; a bool-only workload against a single already-live entry could
        // not, so it would pass whether or not the lock existed. With the lock, every call must complete
        // cleanly and the "kc" entry must survive untouched.
        var (store, live, _) = CreateStore();
        var seeded = new OidConfig { Enabled = true };
        live.OidConfigs["kc"] = seeded;
        var ct = TestContext.Current.CancellationToken;

        const int concurrency = 50;
        var tasks = new Task[concurrency * 2];
        for (var i = 0; i < concurrency; i++)
        {
            var derived = i % 2 == 0;
            tasks[i] = Task.Run(
                () =>
                {
                    var stored = store.Read(c => c.OidConfigs["kc"].NewPath);
                    if (stored != derived)
                    {
                        store.Mutate(c => c.OidConfigs["kc"].NewPath = derived);
                    }
                },
                ct);

            // Concurrent structural churn on an unrelated key, racing the "kc" reads/writes above on the
            // SAME dictionary — added and removed within the same task so the map ends the test with only
            // "kc" left in it.
            var churnKey = "churn-" + i;
            tasks[concurrency + i] = Task.Run(
                () =>
                {
                    store.Mutate(c => c.OidConfigs[churnKey] = new OidConfig());
                    store.Mutate(c => c.OidConfigs.Remove(churnKey));
                },
                ct);
        }

        await Task.WhenAll(tasks); // throws if any callback threw or the store deadlocked/corrupted the map

        // Either NewPath spelling is a legitimate race outcome, but the map itself must have survived the
        // structural churn intact: exactly the "kc" entry left (every churn key fully cleaned up, none
        // leaked or half-written), the SAME object instance (never replaced or duplicated by an
        // interleaved write), with every OTHER field untouched by the race.
        Assert.Equal(1, store.Read(c => c.OidConfigs.Count));
        Assert.Same(seeded, store.Read(c => c.OidConfigs["kc"]));
        Assert.True(store.Read(c => c.OidConfigs["kc"].Enabled));
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
