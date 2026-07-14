using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcStateStore"/> — the consolidated in-flight OpenID authorize-state store
/// (#318). Every behavior is pinned through the public surface (Seed + PeekCurrent / TryRedeem /
/// TryAdd / PruneExpired), where the idiom now lives. Carries forward the invariants pinned by the
/// predecessor AuthStateStore tests: provider-bound peek (#289), the single-use atomic claim
/// (#138/#133 — the upstream replay fix), the clock-anomaly expiry, the cap that refuses new states
/// instead of evicting in-flight ones (#246), and the concurrency regression that motivated the
/// ConcurrentDictionary (adds racing the prune sweep threw on a plain Dictionary).
/// </summary>
public class OidcStateStoreTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan PruneInterval = TimeSpan.FromMinutes(1);
    private static readonly DateTime Now = new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc);

    private static OidcStateStore Store(int maxEntries = 100, TimeSpan? pruneInterval = null) =>
        new(maxEntries, Lifetime, pruneInterval ?? PruneInterval);

    private static TimedAuthorizeState Entry(string provider, string stateValue, bool valid, DateTime created)
        => new(new AuthorizeState { State = stateValue }, created)
        {
            Provider = provider,
            Valid = valid,
        };

    // --- PeekCurrent (OidPost precondition): provider-bound + unexpired, non-consuming ---

    [Fact]
    public void PeekCurrent_SameProviderWithinLifetime_ReturnsThePendingState()
    {
        var store = Store();
        store.Seed("s", Entry("p", "s", false, Now));

        Assert.NotNull(store.PeekCurrent("s", "p", Now));
        Assert.Equal(1, store.Count); // non-consuming: the entry stays for the redeem leg
    }

    [Fact]
    public void PeekCurrent_DifferentProvider_ReturnsNull()
    {
        var store = Store();
        store.Seed("s", Entry("p", "s", false, Now));

        Assert.Null(store.PeekCurrent("s", "other", Now));
    }

    [Fact]
    public void PeekCurrent_Expired_ReturnsNull()
    {
        var store = Store();
        store.Seed("s", Entry("p", "s", false, Now.AddMinutes(-2)));

        Assert.Null(store.PeekCurrent("s", "p", Now));
    }

    [Fact]
    public void PeekCurrent_NullEntry_ReturnsNull()
    {
        // The null belt survives the consolidation: a seeded null can never peek or redeem.
        var store = Store();
        store.Seed("t", null);

        Assert.Null(store.PeekCurrent("t", "p", Now));
        Assert.Null(store.TryRedeem("t", "p", Now));
    }

    [Fact]
    public void PeekCurrent_CreatedInFuture_ReturnsNull()
    {
        // A backward clock step (Created ahead of now) must not make a state effectively never expire.
        var store = Store();
        store.Seed("s", Entry("p", "s", false, Now.AddMinutes(5)));

        Assert.Null(store.PeekCurrent("s", "p", Now));
    }

    // --- TryRedeem (OidAuth/OidLink): valid + response match + provider + unexpired, one-time ---

    [Fact]
    public void TryRedeem_AllConditionsMet_ReturnsTheSnapshotFields()
    {
        var store = Store();
        var entry = Entry("p", "tok", true, Now);
        entry.Subject = "sub-1";
        entry.Username = "alice";
        entry.Admin = true;
        entry.Folders = new List<string> { "movies" };
        entry.EnableLiveTv = true;
        entry.EnableLiveTvManagement = false;
        entry.AvatarURL = "https://idp.example.com/a.png";
        store.Seed("tok", entry);

        var redeemed = store.TryRedeem("tok", "p", Now);

        Assert.NotNull(redeemed);
        Assert.Equal("sub-1", redeemed.Subject);
        Assert.Equal("alice", redeemed.Username);
        Assert.True(redeemed.Admin);
        Assert.Equal(new[] { "movies" }, redeemed.Folders);
        Assert.True(redeemed.EnableLiveTv);
        Assert.False(redeemed.EnableLiveTvManagement);
        Assert.Equal("https://idp.example.com/a.png", redeemed.AvatarUrl);
    }

    [Fact]
    public void TryRedeem_NotValid_ReturnsNullAndDoesNotConsume()
    {
        // Sharper than the predecessor pin: a failed redeem must not burn the entry — the role gate
        // has not passed yet, and the callback leg may still promote it.
        var store = Store();
        store.Seed("tok", Entry("p", "tok", false, Now));

        Assert.Null(store.TryRedeem("tok", "p", Now));
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void TryRedeem_CrossProviderReplay_ReturnsNullAndEntrySurvives()
    {
        // The state-scoping guard: a state validated at a low-trust provider must not be replayable
        // against a higher-trust provider's endpoint, bypassing that provider's login/role gate.
        var store = Store();
        store.Seed("tok", Entry("low-trust", "tok", true, Now));

        Assert.Null(store.TryRedeem("tok", "high-trust", Now));
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void TryRedeem_ResponseMismatch_ReturnsNull()
    {
        // The stored authorize-state value must match the presented one even when the key does.
        var store = Store();
        store.Seed("a", Entry("p", "b", true, Now));

        Assert.Null(store.TryRedeem("a", "p", Now));
    }

    [Fact]
    public void TryRedeem_Expired_ReturnsNull()
    {
        var store = Store();
        store.Seed("tok", Entry("p", "tok", true, Now.AddMinutes(-2)));

        Assert.Null(store.TryRedeem("tok", "p", Now));
    }

    // --- Single-use / invalidate-immediately (#138: upstream 9p4 v4.0.0.4 fix) ---
    // Upstream v4.0.0.3 invalidated the OpenID authorize state only by expiry after a successful
    // auth, leaving the consumed state redeemable again within its ~15-min lifetime — a replay. The
    // fix removed the consumed state immediately; TryRedeem claims it atomically (#133), so it is
    // single-use even under concurrent replay. These pin that invariant so a future refactor cannot
    // silently reintroduce the replay window.

    [Fact]
    public void TryRedeem_ClaimSucceedsOnce_ThenReplayIsRejected()
    {
        var store = Store();
        store.Seed("tok", Entry("p", "tok", true, Now));

        Assert.NotNull(store.TryRedeem("tok", "p", Now)); // the redeeming request wins the claim
        Assert.Null(store.TryRedeem("tok", "p", Now));    // a replay finds it already consumed
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public void ConsumedState_IsNoLongerPeekable()
    {
        var store = Store();
        store.Seed("tok", Entry("p", "tok", true, Now));
        Assert.NotNull(store.TryRedeem("tok", "p", Now));

        Assert.Null(store.PeekCurrent("tok", "p", Now));
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public async Task ConcurrentRedemption_OfSameState_ClaimsExactlyOnce()
    {
        // Two requests racing to redeem the same state: the atomic claim must let exactly one win,
        // so a doubled callback cannot mint two sessions from one authorize state.
        var store = Store();
        store.Seed("tok", Entry("p", "tok", true, Now));

        var a = Task.Run(() => store.TryRedeem("tok", "p", Now), TestContext.Current.CancellationToken);
        var b = Task.Run(() => store.TryRedeem("tok", "p", Now), TestContext.Current.CancellationToken);
        var results = await Task.WhenAll(a, b);

        Assert.Single(results, redeemed => redeemed != null); // exactly one request claimed the state
    }

    // --- PruneExpired: throttled memory reclamation, never a grant/deny decision ---

    [Fact]
    public void PruneExpired_RemovesOnlyExpiredEntries()
    {
        // The gate's cursor starts at MinValue, so the first sweep on a fresh store always enters.
        var store = Store();
        store.Seed("expired", Entry("p", "expired", false, Now.AddMinutes(-5)));
        store.Seed("fresh", Entry("p", "fresh", false, Now.AddSeconds(-10)));

        store.PruneExpired(Now);

        Assert.Equal(1, store.Count);
        Assert.NotNull(store.PeekCurrent("fresh", "p", Now));
    }

    [Fact]
    public void PruneExpired_ExactlyAtLifetime_IsKept()
    {
        // Pins the strict ">" sweep comparison matching the "<=" acceptance in the predicates: an
        // entry aged exactly one lifetime is still accepted; one tick beyond is not.
        var store = Store();
        store.Seed("at-boundary", Entry("p", "at-boundary", false, Now.Subtract(Lifetime)));
        store.Seed("past-boundary", Entry("p", "past-boundary", false, Now.Subtract(Lifetime).AddTicks(-1)));

        store.PruneExpired(Now);

        Assert.Equal(1, store.Count);
        Assert.NotNull(store.PeekCurrent("at-boundary", "p", Now));
    }

    [Fact]
    public void PruneExpired_WithinTheInterval_IsThrottled_AndTheUnsweptEntryIsStillRejected()
    {
        // The throttle only defers memory reclamation: a suppressed sweep leaves the expired entry in
        // the store, but the peek/redeem predicates reject it independently — fail closed either way.
        var store = Store();
        store.PruneExpired(Now); // anchors the gate
        store.Seed("expired", Entry("p", "expired", true, Now.AddMinutes(-5)));

        store.PruneExpired(Now.AddSeconds(1)); // inside the interval: suppressed, no sweep
        Assert.Equal(1, store.Count);
        Assert.Null(store.PeekCurrent("expired", "p", Now.AddSeconds(1)));
        Assert.Null(store.TryRedeem("expired", "p", Now.AddSeconds(1)));

        store.PruneExpired(Now + PruneInterval + TimeSpan.FromSeconds(1)); // next interval: swept
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public async Task PruneExpired_ConcurrentWithAdds_DoesNotThrowAndKeepsFreshEntries()
    {
        // Regression for the login-path race: one request pruning while others add states. On the
        // plain Dictionary predecessor this interleaving threw InvalidOperationException. Each pruner
        // iteration advances 'now' by one tick — one full (tiny) prune interval — so every iteration
        // re-enters the gate and the enumeration genuinely races the adds; the advance stays far
        // below the lifetime, so the fresh entries never expire mid-test.
        var store = new OidcStateStore(10_000, Lifetime, TimeSpan.FromTicks(1));
        store.Seed("seed-expired", Entry("p", "seed-expired", false, Now.AddMinutes(-5)));

        var adder = Task.Run(
            () =>
            {
                for (var i = 0; i < 5000; i++)
                {
                    store.TryAdd(new AuthorizeState { State = "fresh-" + i }, "p", false, Now, out _);
                }
            },
            TestContext.Current.CancellationToken);
        var pruner = Task.Run(
            () =>
            {
                for (var i = 1; i <= 200; i++)
                {
                    store.PruneExpired(Now.AddTicks(i));
                }
            },
            TestContext.Current.CancellationToken);

        await Task.WhenAll(adder, pruner);
        store.PruneExpired(Now.AddTicks(201)); // one final guaranteed sweep for the seed entry

        Assert.Equal(5000, store.Count);
        Assert.Null(store.PeekCurrent("seed-expired", "p", Now));
    }

    // --- TryAdd cap (#246): bound the store; refuse a new state at capacity, never evict in-flight ---

    [Fact]
    public void TryAdd_BelowCap_AddsTheState()
    {
        var store = Store(maxEntries: 2);

        Assert.True(store.TryAdd(new AuthorizeState { State = "a" }, "p", false, Now, out var warnA));
        Assert.True(store.TryAdd(new AuthorizeState { State = "b" }, "p", false, Now, out var warnB));
        Assert.False(warnA);
        Assert.False(warnB);
        Assert.Equal(2, store.Count);
    }

    [Fact]
    public void TryAdd_AtCap_RefusesANewKeyAndKeepsTheInFlightState()
    {
        var store = Store(maxEntries: 1);
        Assert.True(store.TryAdd(new AuthorizeState { State = "in-flight" }, "p", false, Now, out _));

        // At the cap, a fresh challenge is refused rather than evicting the user already mid-login.
        Assert.False(store.TryAdd(new AuthorizeState { State = "new" }, "p", false, Now, out _));
        Assert.Equal(1, store.Count);
        Assert.NotNull(store.PeekCurrent("in-flight", "p", Now));
    }

    [Fact]
    public void TryAdd_DuplicateKey_ReturnsFalse()
    {
        var store = Store(maxEntries: 10);
        Assert.True(store.TryAdd(new AuthorizeState { State = "a" }, "p", false, Now, out _));
        Assert.False(store.TryAdd(new AuthorizeState { State = "a" }, "p", false, Now, out _));
    }

    [Fact]
    public void TryAdd_Refused_SignalsTheCapacityWarningOncePerInterval()
    {
        // The warning signal is bounded exactly like the sweeps: the first refusal signals, further
        // refusals inside the interval stay silent, so a flood cannot amplify into log volume.
        var store = Store(maxEntries: 1);
        Assert.True(store.TryAdd(new AuthorizeState { State = "a" }, "p", false, Now, out _));

        Assert.False(store.TryAdd(new AuthorizeState { State = "b" }, "p", false, Now, out var firstWarn));
        Assert.True(firstWarn);

        Assert.False(store.TryAdd(new AuthorizeState { State = "c" }, "p", false, Now.AddSeconds(1), out var secondWarn));
        Assert.False(secondWarn);

        Assert.False(store.TryAdd(new AuthorizeState { State = "d" }, "p", false, Now + PruneInterval, out var nextIntervalWarn));
        Assert.True(nextIntervalWarn);
    }

    [Fact]
    public async Task TryAdd_UnderContention_StaysBoundedAndRejectsSome()
    {
        const int cap = 50;
        const int taskCount = 8;
        const int perTask = 30;
        var store = Store(maxEntries: cap);
        var rejected = 0;

        var tasks = new Task[taskCount];
        for (var t = 0; t < taskCount; t++)
        {
            var id = t;
            tasks[t] = Task.Run(
                () =>
                {
                    for (var i = 0; i < perTask; i++)
                    {
                        if (!store.TryAdd(new AuthorizeState { State = $"t{id}-k{i}" }, "p", false, Now, out _))
                        {
                            Interlocked.Increment(ref rejected);
                        }
                    }
                },
                TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        // The unsynchronized check-then-add can transiently overshoot by at most the in-flight thread
        // count, so the invariant is BOUNDED (not "never exceeds cap"): the cap is reached, the store
        // stays within cap + taskCount, and once full some inserts are rejected — the concurrent
        // rejection path.
        Assert.True(store.Count >= cap);
        Assert.True(store.Count <= cap + taskCount);
        Assert.True(rejected > 0);
    }

    [Fact]
    public void PendingStateComplete_CopiesEveryDerivedFieldOntoTheStoredState()
    {
        // Pins the relocated pending-to-ready promotion field-for-field: a redeem after Complete must
        // see exactly the role-gate result (the in-place copy is today's behavior; the atomic variant
        // swap is the follow-up).
        var store = Store();
        store.Seed("tok", Entry("p", "tok", false, Now));
        var pending = store.PeekCurrent("tok", "p", Now);
        Assert.NotNull(pending);

        pending.Complete(new OidcAuthorizeStateBuilder.OidcAuthorizeState(
            Username: "alice",
            Subject: "sub-1",
            Valid: true,
            Admin: true,
            EnableLiveTv: true,
            EnableLiveTvManagement: true,
            Folders: new List<string> { "movies" },
            AvatarUrl: "https://idp.example.com/a.png"));

        var redeemed = store.TryRedeem("tok", "p", Now);
        Assert.NotNull(redeemed);
        Assert.Equal("alice", redeemed.Username);
        Assert.Equal("sub-1", redeemed.Subject);
        Assert.True(redeemed.Admin);
        Assert.True(redeemed.EnableLiveTv);
        Assert.True(redeemed.EnableLiveTvManagement);
        Assert.Equal(new[] { "movies" }, redeemed.Folders);
        Assert.Equal("https://idp.example.com/a.png", redeemed.AvatarUrl);
    }

    // --- The production defaults and the non-secret projection ---

    [Fact]
    public void Defaults_PinTheProductionConfiguration()
    {
        // The endpoints run the parameterless store; these literals are the values the whole
        // interactive leg (challenge -> IdP -> callback -> mint) is sized by.
        Assert.Equal(100_000, OidcStateStore.DefaultMaxEntries);
        Assert.Equal(TimeSpan.FromMinutes(15), OidcStateStore.DefaultLifetime);
        Assert.Equal(TimeSpan.FromMinutes(1), OidcStateStore.DefaultPruneInterval);
    }

    [Fact]
    public void Summaries_ProjectExactlyTheNonSecretFields()
    {
        // Structural redaction: the Summary record carries Provider/Created/Valid/IsLinking and
        // nothing else — the authorize-state token and PKCE code_verifier / nonce cannot leak
        // through it, even to an admin.
        var store = Store();
        var entry = Entry("p", "secret-token", true, Now);
        entry.IsLinking = true;
        store.Seed("secret-token", entry);

        var summary = Assert.Single(store.Summaries());
        Assert.Equal("p", summary.Provider);
        Assert.Equal(Now, summary.Created);
        Assert.True(summary.Valid);
        Assert.True(summary.IsLinking);
    }
}
