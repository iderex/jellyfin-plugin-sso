using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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

    private static readonly DateTime Now = new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc);

    private static TimedAuthorizeState State(string provider, string stateValue, bool valid, DateTime created)
        => new TimedAuthorizeState(new Duende.IdentityModel.OidcClient.AuthorizeState { State = stateValue }, created)
        {
            Provider = provider,
            Valid = valid,
        };

    // --- IsCurrentFor (OidPost precondition): provider-bound + unexpired ---

    [Fact]
    public void IsCurrentFor_SameProviderWithinLifetime_True()
        => Assert.True(AuthStateStore.IsCurrentFor(State("p", "s", false, Now), "p", Now, Lifetime));

    [Fact]
    public void IsCurrentFor_DifferentProvider_False()
        => Assert.False(AuthStateStore.IsCurrentFor(State("p", "s", false, Now), "other", Now, Lifetime));

    [Fact]
    public void IsCurrentFor_Expired_False()
        => Assert.False(AuthStateStore.IsCurrentFor(State("p", "s", false, Now.AddMinutes(-2)), "p", Now, Lifetime));

    [Fact]
    public void IsCurrentFor_Null_False()
        => Assert.False(AuthStateStore.IsCurrentFor(null, "p", Now, Lifetime));

    [Fact]
    public void IsCurrentFor_CreatedInFuture_False()
        // A backward clock step (Created ahead of now) must not make a state effectively never expire.
        => Assert.False(AuthStateStore.IsCurrentFor(State("p", "s", false, Now.AddMinutes(5)), "p", Now, Lifetime));

    // --- IsRedeemableBy (OidAuth/OidLink): valid + response match + provider + unexpired ---

    [Fact]
    public void IsRedeemableBy_AllConditionsMet_True()
        => Assert.True(AuthStateStore.IsRedeemableBy(State("p", "tok", true, Now), "tok", "p", Now, Lifetime));

    [Fact]
    public void IsRedeemableBy_NotValid_False()
        => Assert.False(AuthStateStore.IsRedeemableBy(State("p", "tok", false, Now), "tok", "p", Now, Lifetime));

    [Fact]
    public void IsRedeemableBy_CrossProviderReplay_False()
        => Assert.False(AuthStateStore.IsRedeemableBy(State("low-trust", "tok", true, Now), "tok", "high-trust", Now, Lifetime));

    [Fact]
    public void IsRedeemableBy_ResponseMismatch_False()
        => Assert.False(AuthStateStore.IsRedeemableBy(State("p", "tok", true, Now), "other", "p", Now, Lifetime));

    [Fact]
    public void IsRedeemableBy_Expired_False()
        => Assert.False(AuthStateStore.IsRedeemableBy(State("p", "tok", true, Now.AddMinutes(-2)), "tok", "p", Now, Lifetime));

    // --- Single-use / invalidate-immediately (#138: upstream 9p4 v4.0.0.4 fix, PR #343 / 5b3d70d) ---
    // Upstream v4.0.0.3 invalidated the OpenID authorize state only by expiry (Invalidate()) after a
    // successful auth, leaving the consumed `state` redeemable again within its ~15-min lifetime — a
    // replay. The fix removed the consumed state immediately; here OidAuth removes it atomically as the
    // redemption gate (TryRemove(KeyValuePair), #133), so it is single-use even under concurrent replay.
    // These pin that invariant so a future refactor cannot silently reintroduce the replay window.

    [Fact]
    public void ConsumedState_AtomicClaimSucceedsOnce_ThenReplayIsRejected()
    {
        var store = new ConcurrentDictionary<string, TimedAuthorizeState>();
        var state = State("p", "tok", true, Now);
        store.TryAdd("tok", state);

        var claim = new KeyValuePair<string, TimedAuthorizeState>("tok", state);
        Assert.True(store.TryRemove(claim)); // the redeeming request wins the atomic claim
        Assert.False(store.TryRemove(claim)); // a replay of the same state finds it already consumed
        Assert.False(store.TryGetValue("tok", out _)); // and it is gone from the store
    }

    [Fact]
    public void ConsumedState_IsNoLongerRedeemable()
    {
        var store = new ConcurrentDictionary<string, TimedAuthorizeState>();
        var state = State("p", "tok", true, Now);
        store.TryAdd("tok", state);
        store.TryRemove(new KeyValuePair<string, TimedAuthorizeState>("tok", state));

        // A replay looks the state up (now absent) and the redemption gate fails closed on the null.
        store.TryGetValue("tok", out var afterConsume);
        Assert.Null(afterConsume);
        Assert.False(AuthStateStore.IsRedeemableBy(afterConsume, "tok", "p", Now, Lifetime));
    }

    [Fact]
    public async Task ConcurrentRedemption_OfSameState_ClaimsExactlyOnce()
    {
        // Two requests racing to redeem the same state: the atomic TryRemove(KeyValuePair) must let
        // exactly one win, so a doubled callback cannot mint two sessions from one authorize state.
        var store = new ConcurrentDictionary<string, TimedAuthorizeState>();
        var state = State("p", "tok", true, Now);
        store.TryAdd("tok", state);
        var claim = new KeyValuePair<string, TimedAuthorizeState>("tok", state);

        var a = Task.Run(() => store.TryRemove(claim), TestContext.Current.CancellationToken);
        var b = Task.Run(() => store.TryRemove(claim), TestContext.Current.CancellationToken);
        var results = await Task.WhenAll(a, b);

        Assert.Single(results, redeemed => redeemed); // exactly one request claimed the state
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
