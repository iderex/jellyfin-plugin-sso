using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="AuthStateStore"/> — expiry pruning of the in-flight OpenID
/// authorize-state store, including the concurrency regression that motivated the move to
/// <see cref="ConcurrentDictionary{TKey,TValue}"/> (adds racing enumeration/pruning threw
/// InvalidOperationException on the previous plain Dictionary).
/// </summary>
public class AuthStateStoreTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(1);

    private static ConcurrentDictionary<string, TimedAuthorizeState> StoreWith(params (string Key, DateTime Created)[] entries)
    {
        var store = new ConcurrentDictionary<string, TimedAuthorizeState>();
        foreach (var (key, created) in entries)
        {
            store.TryAdd(key, new TimedAuthorizeState(new Duende.IdentityModel.OidcClient.AuthorizeState(), created));
        }

        return store;
    }

    [Fact]
    public void InvalidateExpired_RemovesOnlyExpiredEntries()
    {
        var now = new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc);
        var store = StoreWith(
            ("expired", now.AddMinutes(-5)),
            ("fresh", now.AddSeconds(-10)));

        AuthStateStore.InvalidateExpired(store, now, Lifetime);

        Assert.False(store.ContainsKey("expired"));
        Assert.True(store.ContainsKey("fresh"));
    }

    [Fact]
    public void InvalidateExpired_ExactlyAtLifetime_IsKept()
    {
        // Pins the strict ">" comparison of the original implementation: an entry aged exactly
        // one lifetime is still accepted; one tick beyond is not.
        var now = new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc);
        var store = StoreWith(
            ("at-boundary", now.Subtract(Lifetime)),
            ("past-boundary", now.Subtract(Lifetime).AddTicks(-1)));

        AuthStateStore.InvalidateExpired(store, now, Lifetime);

        Assert.True(store.ContainsKey("at-boundary"));
        Assert.False(store.ContainsKey("past-boundary"));
    }

    [Fact]
    public async Task InvalidateExpired_ConcurrentWithAdds_DoesNotThrowAndKeepsFreshEntries()
    {
        // Regression for the login-path race: one request pruning while others add states.
        // On the previous plain Dictionary this interleaving threw InvalidOperationException.
        var now = new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc);
        var store = StoreWith(("seed-expired", now.AddMinutes(-5)));

        var adder = Task.Run(
            () =>
            {
                for (var i = 0; i < 5000; i++)
                {
                    store.TryAdd("fresh-" + i, new TimedAuthorizeState(new Duende.IdentityModel.OidcClient.AuthorizeState(), now));
                }
            },
            TestContext.Current.CancellationToken);
        var pruner = Task.Run(
            () =>
            {
                for (var i = 0; i < 200; i++)
                {
                    AuthStateStore.InvalidateExpired(store, now, Lifetime);
                }
            },
            TestContext.Current.CancellationToken);

        await Task.WhenAll(adder, pruner);

        Assert.False(store.ContainsKey("seed-expired"));
        Assert.Equal(5000, store.Count);
    }
}
