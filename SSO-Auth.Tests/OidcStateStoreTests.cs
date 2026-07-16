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
/// ConcurrentDictionary (adds racing the prune sweep threw on a plain Dictionary). Since #326 every
/// peek/redeem also carries the browser-binding gate: the presented binding id (the callback's cookie
/// value) must match the id recorded on the state, so a state started in one browser cannot be
/// completed in another (forced-login / session-fixation defense). The pre-#326 semantics tests pass
/// a matching <see cref="Binding"/> so the binding gate is transparent to them; the dedicated
/// mismatch/absent tests below prove the gate itself.
/// </summary>
public class OidcStateStoreTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan PruneInterval = TimeSpan.FromMinutes(1);
    private static readonly DateTime Now = new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc);

    // The browser-binding id every Entry() records and the pre-#326 semantics tests present; a matching
    // value keeps the binding gate transparent so those tests pin only the provider/expiry/replay/cap
    // behavior they were written for.
    private const string Binding = "browser-A-binding";

    private static OidcStateStore Store(int maxEntries = 100, TimeSpan? pruneInterval = null) =>
        new(maxEntries, Lifetime, pruneInterval ?? PruneInterval);

    private static TimedAuthorizeState Entry(string provider, string stateValue, bool valid, DateTime created)
        => new(new AuthorizeState { State = stateValue }, created)
        {
            Provider = provider,
            Valid = valid,
            BindingId = Binding,
        };

    // --- PeekCurrent (OidPost precondition): provider-bound + unexpired, non-consuming ---

    [Fact]
    public void PeekCurrent_SameProviderWithinLifetime_ReturnsThePendingState()
    {
        var store = Store();
        store.Seed("s", Entry("p", "s", false, Now));

        Assert.NotNull(store.PeekCurrent("s", "p", Now, Binding));
        Assert.Equal(1, store.Count); // non-consuming: the entry stays for the redeem leg
    }

    [Fact]
    public void PeekCurrent_DifferentProvider_ReturnsNull()
    {
        var store = Store();
        store.Seed("s", Entry("p", "s", false, Now));

        Assert.Null(store.PeekCurrent("s", "other", Now, Binding));
    }

    [Fact]
    public void PeekCurrent_Expired_ReturnsNull()
    {
        var store = Store();
        store.Seed("s", Entry("p", "s", false, Now.AddMinutes(-2)));

        Assert.Null(store.PeekCurrent("s", "p", Now, Binding));
    }

    [Fact]
    public void PeekCurrent_NullEntry_ReturnsNull()
    {
        // The null belt survives the consolidation: a seeded null can never peek or redeem.
        var store = Store();
        store.Seed("t", null);

        Assert.Null(store.PeekCurrent("t", "p", Now, Binding));
        Assert.Null(store.TryRedeem("t", "p", Now, Binding));
    }

    [Fact]
    public void PeekCurrent_CreatedInFuture_ReturnsNull()
    {
        // A backward clock step (Created ahead of now) must not make a state effectively never expire.
        var store = Store();
        store.Seed("s", Entry("p", "s", false, Now.AddMinutes(5)));

        Assert.Null(store.PeekCurrent("s", "p", Now, Binding));
    }

    // --- Browser-binding gate (#326): the callback must present the id recorded at challenge ---

    [Fact]
    public void PeekCurrent_MismatchedBinding_ReturnsNull()
    {
        // A state started in browser A cannot be peeked from browser B: the presented binding id does
        // not match the recorded one, so the forced-login callback is refused before any token exchange.
        var store = Store();
        var entry = Entry("p", "s", false, Now);
        entry.BindingId = "browser-A";
        store.Seed("s", entry);

        Assert.Null(store.PeekCurrent("s", "p", Now, "browser-B"));
        Assert.Equal(1, store.Count); // non-consuming: a wrong-browser peek must not drop the entry
    }

    [Fact]
    public void TryRedeem_MismatchedBinding_ReturnsNull_AndDoesNotConsume()
    {
        // The key property of #326: a wrong-browser redeem is refused BEFORE the atomic remove, so an
        // attacker (or a lured victim) cannot burn a legitimate user's in-flight state — the right
        // browser can still complete the login afterward.
        var store = Store();
        var entry = Entry("p", "tok", true, Now);
        entry.BindingId = "browser-A";
        store.Seed("tok", entry);

        Assert.Null(store.TryRedeem("tok", "p", Now, "browser-B"));
        Assert.Equal(1, store.Count); // the mismatched attempt did not consume the state

        // The browser that started the flow still redeems it: the state survived the wrong-browser hit.
        var redeemed = store.TryRedeem("tok", "p", Now, "browser-A");
        Assert.NotNull(redeemed);
        Assert.Equal(0, store.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void PeekCurrent_AbsentPresentedBinding_ReturnsNull(string? presentedBindingId)
    {
        // Fail closed: a callback with no binding cookie (missing or empty) never matches a bound state,
        // even though the token and provider are correct.
        var store = Store();
        store.Seed("s", Entry("p", "s", false, Now));

        Assert.Null(store.PeekCurrent("s", "p", Now, presentedBindingId));
        Assert.Equal(1, store.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void TryRedeem_AbsentPresentedBinding_ReturnsNull(string? presentedBindingId)
    {
        // Fail closed on the redeem leg too, and without consuming: a missing/empty cookie must not
        // burn the state either.
        var store = Store();
        store.Seed("tok", Entry("p", "tok", true, Now));

        Assert.Null(store.TryRedeem("tok", "p", Now, presentedBindingId));
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void TryRedeem_EntryWithNoBindingId_ReturnsNull()
    {
        // Fail closed on the stored side: a state that recorded no binding id (e.g. a legacy or
        // hand-seeded entry) is never redeemable — not even by presenting an empty or arbitrary id, so
        // an unbound state cannot be a bypass.
        var store = Store();
        store.Seed("tok", new TimedAuthorizeState(new AuthorizeState { State = "tok" }, Now)
        {
            Provider = "p",
            Valid = true,
            // BindingId deliberately left null.
        });

        Assert.Null(store.TryRedeem("tok", "p", Now, "anything"));
        Assert.Null(store.TryRedeem("tok", "p", Now, null));
        Assert.Equal(1, store.Count); // none of the fail-closed attempts consumed the entry
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

        var redeemed = store.TryRedeem("tok", "p", Now, Binding);

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

        Assert.Null(store.TryRedeem("tok", "p", Now, Binding));
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void TryRedeem_CrossProviderReplay_ReturnsNullAndEntrySurvives()
    {
        // The state-scoping guard: a state validated at a low-trust provider must not be replayable
        // against a higher-trust provider's endpoint, bypassing that provider's login/role gate.
        var store = Store();
        store.Seed("tok", Entry("low-trust", "tok", true, Now));

        Assert.Null(store.TryRedeem("tok", "high-trust", Now, Binding));
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void TryRedeem_ResponseMismatch_ReturnsNull()
    {
        // The stored authorize-state value must match the presented one even when the key does.
        var store = Store();
        store.Seed("a", Entry("p", "b", true, Now));

        Assert.Null(store.TryRedeem("a", "p", Now, Binding));
    }

    [Fact]
    public void TryRedeem_Expired_ReturnsNull()
    {
        var store = Store();
        store.Seed("tok", Entry("p", "tok", true, Now.AddMinutes(-2)));

        Assert.Null(store.TryRedeem("tok", "p", Now, Binding));
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

        Assert.NotNull(store.TryRedeem("tok", "p", Now, Binding)); // the redeeming request wins the claim
        Assert.Null(store.TryRedeem("tok", "p", Now, Binding));    // a replay finds it already consumed
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public void ConsumedState_IsNoLongerPeekable()
    {
        var store = Store();
        store.Seed("tok", Entry("p", "tok", true, Now));
        Assert.NotNull(store.TryRedeem("tok", "p", Now, Binding));

        Assert.Null(store.PeekCurrent("tok", "p", Now, Binding));
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public async Task ConcurrentRedemption_OfSameState_ClaimsExactlyOnce()
    {
        // Two requests racing to redeem the same state: the atomic claim must let exactly one win,
        // so a doubled callback cannot mint two sessions from one authorize state.
        var store = Store();
        store.Seed("tok", Entry("p", "tok", true, Now));

        var a = Task.Run(() => store.TryRedeem("tok", "p", Now, Binding), TestContext.Current.CancellationToken);
        var b = Task.Run(() => store.TryRedeem("tok", "p", Now, Binding), TestContext.Current.CancellationToken);
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
        Assert.NotNull(store.PeekCurrent("fresh", "p", Now, Binding));
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
        Assert.NotNull(store.PeekCurrent("at-boundary", "p", Now, Binding));
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
        Assert.Null(store.PeekCurrent("expired", "p", Now.AddSeconds(1), Binding));
        Assert.Null(store.TryRedeem("expired", "p", Now.AddSeconds(1), Binding));

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
                    store.TryAdd(new AuthorizeState { State = "fresh-" + i }, "p", false, Now, Binding, clientKey: null, out _);
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
        Assert.Null(store.PeekCurrent("seed-expired", "p", Now, Binding));
    }

    // --- TryAdd cap (#246): bound the store; refuse a new state at capacity, never evict in-flight ---

    [Fact]
    public void TryAdd_BelowCap_AddsTheState()
    {
        var store = Store(maxEntries: 2);

        Assert.True(store.TryAdd(new AuthorizeState { State = "a" }, "p", false, Now, Binding, clientKey: null, out var warnA));
        Assert.True(store.TryAdd(new AuthorizeState { State = "b" }, "p", false, Now, Binding, clientKey: null, out var warnB));
        Assert.False(warnA);
        Assert.False(warnB);
        Assert.Equal(2, store.Count);
    }

    [Fact]
    public void TryAdd_AtCap_RefusesANewKeyAndKeepsTheInFlightState()
    {
        var store = Store(maxEntries: 1);
        Assert.True(store.TryAdd(new AuthorizeState { State = "in-flight" }, "p", false, Now, Binding, clientKey: null, out _));

        // At the cap, a fresh challenge is refused rather than evicting the user already mid-login.
        Assert.False(store.TryAdd(new AuthorizeState { State = "new" }, "p", false, Now, Binding, clientKey: null, out _));
        Assert.Equal(1, store.Count);
        Assert.NotNull(store.PeekCurrent("in-flight", "p", Now, Binding));
    }

    [Fact]
    public void TryAdd_DuplicateKey_ReturnsFalse()
    {
        var store = Store(maxEntries: 10);
        Assert.True(store.TryAdd(new AuthorizeState { State = "a" }, "p", false, Now, Binding, clientKey: null, out _));
        Assert.False(store.TryAdd(new AuthorizeState { State = "a" }, "p", false, Now, Binding, clientKey: null, out _));
    }

    [Fact]
    public void TryAdd_Refused_SignalsTheCapacityWarningOncePerInterval()
    {
        // The warning signal is bounded exactly like the sweeps: the first refusal signals, further
        // refusals inside the interval stay silent, so a flood cannot amplify into log volume.
        var store = Store(maxEntries: 1);
        Assert.True(store.TryAdd(new AuthorizeState { State = "a" }, "p", false, Now, Binding, clientKey: null, out _));

        Assert.False(store.TryAdd(new AuthorizeState { State = "b" }, "p", false, Now, Binding, clientKey: null, out var firstWarn));
        Assert.True(firstWarn);

        Assert.False(store.TryAdd(new AuthorizeState { State = "c" }, "p", false, Now.AddSeconds(1), Binding, clientKey: null, out var secondWarn));
        Assert.False(secondWarn);

        Assert.False(store.TryAdd(new AuthorizeState { State = "d" }, "p", false, Now + PruneInterval, Binding, clientKey: null, out var nextIntervalWarn));
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
                        if (!store.TryAdd(new AuthorizeState { State = $"t{id}-k{i}" }, "p", false, Now, Binding, clientKey: null, out _))
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
    public void PendingStateComplete_SecondCompletion_OverwritesTheFirst_TheDocumentedResidual()
    {
        // Characterizes today's in-place promotion: a second completion overwrites the first
        // (last-writer-wins), exactly as the pre-consolidation inline copy behaved. Reaching a second
        // completion in production requires the IdP to accept a reused authorization code (the token
        // exchange fails on replay for conforming IdPs), so the window is theoretical; making the
        // promotion an atomic single-winner swap is #341, and this pin documents what it will change.
        var store = Store();
        store.Seed("tok", Entry("p", "tok", false, Now));
        var pending = store.PeekCurrent("tok", "p", Now, Binding);
        Assert.NotNull(pending);

        pending.Complete(new OidcAuthorizeStateBuilder.OidcAuthorizeState(
            Username: "alice", Subject: "sub-1", Valid: true, Admin: false,
            EnableLiveTv: false, EnableLiveTvManagement: false, Folders: new List<string>(), AvatarUrl: null));
        pending.Complete(new OidcAuthorizeStateBuilder.OidcAuthorizeState(
            Username: "bob", Subject: "sub-2", Valid: true, Admin: true,
            EnableLiveTv: true, EnableLiveTvManagement: true, Folders: new List<string> { "all" }, AvatarUrl: null));

        var redeemed = store.TryRedeem("tok", "p", Now, Binding);
        Assert.NotNull(redeemed);
        Assert.Equal("bob", redeemed.Username);
        Assert.Equal("sub-2", redeemed.Subject);
        Assert.True(redeemed.Admin);
    }

    [Fact]
    public void PendingStateComplete_CopiesEveryDerivedFieldOntoTheStoredState()
    {
        // Pins the relocated pending-to-ready promotion field-for-field: a redeem after Complete must
        // see exactly the role-gate result (the in-place copy is today's behavior; the atomic variant
        // swap is the follow-up).
        var store = Store();
        store.Seed("tok", Entry("p", "tok", false, Now));
        var pending = store.PeekCurrent("tok", "p", Now, Binding);
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

        var redeemed = store.TryRedeem("tok", "p", Now, Binding);
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

    // --- Per-client sub-cap (#327): global 200 -> per-key 2 unless noted ---

    private static AuthorizeState State(string s) => new AuthorizeState { State = s };

    // Promotes a just-added (Valid=false) state to redeemable via the production path (peek + Complete),
    // so TryRedeem — which requires a validated state — can exercise the per-client release.
    private static void Validate(OidcStateStore store, string token) =>
        store.PeekCurrent(token, "p", Now, Binding)!.Complete(
            new OidcAuthorizeStateBuilder.OidcAuthorizeState("u", "sub", true, false, false, false, new System.Collections.Generic.List<string>(), null));

    [Fact]
    public void TryAdd_FloodFromOneKey_DoesNotRefuseADifferentKey()
    {
        // The core fairness property: filling client "A" to its per-key share must not deny "B".
        var store = Store(maxEntries: 200); // per-key cap 2
        Assert.True(store.TryAdd(State("a1"), "p", false, Now, Binding, clientKey: "A", out _));
        Assert.True(store.TryAdd(State("a2"), "p", false, Now, Binding, clientKey: "A", out _));
        Assert.False(store.TryAdd(State("a3"), "p", false, Now, Binding, clientKey: "A", out var warn)); // A at share
        Assert.True(warn); // the throttled capacity warning fires for the first per-client refusal

        Assert.True(store.TryAdd(State("b1"), "p", false, Now, Binding, clientKey: "B", out _)); // B unaffected
    }

    [Fact]
    public void TryAdd_ReleaseOnRedeem_ReadmitsTheSameKey()
    {
        var store = Store(maxEntries: 200); // per-key cap 2
        store.TryAdd(State("a1"), "p", false, Now, Binding, clientKey: "A", out _);
        store.TryAdd(State("a2"), "p", false, Now, Binding, clientKey: "A", out _);
        Assert.False(store.TryAdd(State("a3"), "p", false, Now, Binding, clientKey: "A", out _)); // full

        Validate(store, "a1");
        Assert.NotNull(store.TryRedeem("a1", "p", Now, Binding)); // frees one A slot
        Assert.True(store.TryAdd(State("a3"), "p", false, Now, Binding, clientKey: "A", out _));
    }

    [Fact]
    public void TryAdd_ReleaseOnExpirySweep_ReadmitsTheSameKey()
    {
        var store = Store(maxEntries: 200); // per-key cap 2
        store.TryAdd(State("a1"), "p", false, Now, Binding, clientKey: "A", out _);
        store.TryAdd(State("a2"), "p", false, Now, Binding, clientKey: "A", out _);

        // Past the lifetime and the prune interval, the sweep removes both A entries and releases their
        // slots, so A can add again. (Lifetime and PruneInterval are the test fixture's small values.)
        var later = Now + Lifetime + PruneInterval + TimeSpan.FromSeconds(1);
        store.PruneExpired(later);
        Assert.True(store.TryAdd(State("a3"), "p", false, later, Binding, clientKey: "A", out _));
    }

    [Fact]
    public void TryAdd_ReleaseOnFailedGlobalInsert_DoesNotLeakTheClientSlot()
    {
        // Global cap 2 -> per-key cap 1. Fill the store to the global cap with exempt (null) keys, then
        // a "A" add reserves A's slot but is refused by the GLOBAL cap and must roll back. After a slot
        // frees, "A" must still admit — a leaked reservation would leave A at its cap of 1.
        var store = Store(maxEntries: 2);
        Assert.True(store.TryAdd(State("n1"), "p", false, Now, Binding, clientKey: null, out _));
        Assert.True(store.TryAdd(State("n2"), "p", false, Now, Binding, clientKey: null, out _));

        Assert.False(store.TryAdd(State("a1"), "p", false, Now, Binding, clientKey: "A", out _)); // global cap
        Validate(store, "n1");
        Assert.NotNull(store.TryRedeem("n1", "p", Now, Binding)); // free one global slot
        Assert.True(store.TryAdd(State("a1"), "p", false, Now, Binding, clientKey: "A", out _)); // no leak
    }

    [Fact]
    public void TryAdd_NullKeyIsExempt_BoundedOnlyByTheGlobalCap()
    {
        // Global cap 2 -> per-key cap 1. A null (proxy/unattributable) key is never sub-capped: null adds
        // succeed past a per-key cap of 1 up to the GLOBAL cap, then are refused by the global cap.
        var store = Store(maxEntries: 2);
        Assert.True(store.TryAdd(State("n1"), "p", false, Now, Binding, clientKey: null, out _));
        Assert.True(store.TryAdd(State("n2"), "p", false, Now, Binding, clientKey: null, out _)); // past per-key 1
        Assert.False(store.TryAdd(State("n3"), "p", false, Now, Binding, clientKey: null, out _)); // global cap
    }

    [Fact]
    public void TryAdd_DistinctKeys_FillToGlobalCap_ThenRefuseNotEvict()
    {
        // The per-key cap must not block distinct keys: fill the store to the global cap with one entry
        // each per distinct key, then a further distinct key is refused (global cap) and the existing
        // entries survive (refuse-not-evict).
        var store = Store(maxEntries: 3); // per-key cap 1
        Assert.True(store.TryAdd(State("k1"), "p", false, Now, Binding, clientKey: "K1", out _));
        Assert.True(store.TryAdd(State("k2"), "p", false, Now, Binding, clientKey: "K2", out _));
        Assert.True(store.TryAdd(State("k3"), "p", false, Now, Binding, clientKey: "K3", out _));
        Assert.False(store.TryAdd(State("k4"), "p", false, Now, Binding, clientKey: "K4", out _)); // global cap
        Assert.NotNull(store.PeekCurrent("k1", "p", Now, Binding)); // not evicted
    }
}
