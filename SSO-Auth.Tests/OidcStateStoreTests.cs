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
/// (#318, #341). Every behavior is pinned through the public surface (Seed + TryAdd / PeekCurrent /
/// Promote / TryRedeem / PruneExpired), where the idiom now lives. The store holds a closed sum
/// <see cref="AuthorizeSession"/>: a <see cref="AuthorizeSession.Pending"/> registered at the challenge,
/// atomically swapped for a <see cref="AuthorizeSession.Ready"/> at the callback once the role gate
/// passes — so "the login is valid" is which variant the entry is, never a mutable flag, and the swap is
/// torn-read-free (#341). Carries forward the invariants pinned by the predecessor tests: provider-bound
/// peek (#289), the single-use atomic claim (#138/#133 — the upstream replay fix), the clock-anomaly
/// expiry, the cap that refuses new states instead of evicting in-flight ones (#246), and the concurrency
/// regression that motivated the ConcurrentDictionary (adds racing the prune sweep threw on a plain
/// Dictionary). Since #326 every peek/redeem also carries the browser-binding gate: the presented binding
/// id (the callback's cookie value) must match the id recorded on the state, so a state started in one
/// browser cannot be completed in another (forced-login / session-fixation defense). The pre-#326
/// semantics tests pass a matching <see cref="Binding"/> so the binding gate is transparent to them; the
/// dedicated mismatch/absent tests below prove the gate itself.
/// </summary>
public class OidcStateStoreTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan PruneInterval = TimeSpan.FromMinutes(1);
    private static readonly DateTime Now = new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc);

    // The browser-binding id every Pending()/Ready() records and the pre-#326 semantics tests present; a
    // matching value keeps the binding gate transparent so those tests pin only the provider/expiry/
    // replay/cap behavior they were written for.
    private const string Binding = "browser-A-binding";

    private static OidcStateStore Store(int maxEntries = 100, TimeSpan? pruneInterval = null) =>
        new(maxEntries, Lifetime, pruneInterval ?? PruneInterval);

    // A challenge-time Pending: the not-yet-promoted variant a callback peeks. ProviderInformation and the
    // response-iss requirement are folded in at construction (#341), mirroring the production challenge.
    private static AuthorizeSession.Pending Pending(
        string provider,
        string stateValue,
        DateTime created,
        string? binding = Binding,
        bool isLinking = false,
        ProviderInformation? info = null,
        bool responseIssuerRequired = false,
        string? clientKey = null)
        => new(new AuthorizeState { State = stateValue }, provider, isLinking, created, binding, clientKey, info, responseIssuerRequired);

    // A promoted Ready: the redeemable variant the callback produces once the role gate passes. Building it
    // from a Pending + a valid role-gate result is exactly the production promotion path.
    private static AuthorizeSession.Ready Ready(
        string provider,
        string stateValue,
        DateTime created,
        string? binding = Binding,
        string subject = "sub",
        string username = "u",
        bool admin = false,
        List<string>? folders = null,
        bool enableLiveTv = false,
        bool enableLiveTvManagement = false,
        string? avatar = null,
        bool? emailVerified = null,
        bool isLinking = false,
        string? clientKey = null)
        => new(
            Pending(provider, stateValue, created, binding, isLinking, clientKey: clientKey),
            new OidcAuthorizeStateBuilder.OidcAuthorizeState(username, subject, null, emailVerified, true, admin, enableLiveTv, enableLiveTvManagement, folders ?? new List<string>(), avatar));

    // A fully-populated role-gate result, so a redeemed Ready can be asserted field-for-field.
    private static OidcAuthorizeStateBuilder.OidcAuthorizeState FullDerived() =>
        new("alice", "sub-full", "https://idp.example", null, true, true, false, false, new List<string> { "movies" }, "https://idp.example/a.png");

    // --- PeekCurrent (OidPost precondition): provider-bound + unexpired + still pending, non-consuming ---

    [Fact]
    public void PeekCurrent_SameProviderWithinLifetime_ReturnsThePending()
    {
        var store = Store();
        store.Seed("s", Pending("p", "s", Now));

        Assert.NotNull(store.PeekCurrent("s", "p", Now, Binding));
        Assert.Equal(1, store.Count); // non-consuming: the entry stays for the redeem leg
    }

    [Fact]
    public void PeekCurrent_DifferentProvider_ReturnsNull()
    {
        var store = Store();
        store.Seed("s", Pending("p", "s", Now));

        Assert.Null(store.PeekCurrent("s", "other", Now, Binding));
    }

    [Fact]
    public void PeekCurrent_Expired_ReturnsNull()
    {
        var store = Store();
        store.Seed("s", Pending("p", "s", Now.AddMinutes(-2)));

        Assert.Null(store.PeekCurrent("s", "p", Now, Binding));
    }

    [Fact]
    public void PeekCurrent_AlreadyPromoted_ReturnsNull()
    {
        // Once the callback promoted the state to a Ready, a second callback must not peek it again as a
        // pending state to re-run a token exchange — PeekCurrent returns only the Pending variant (#341).
        var store = Store();
        store.Seed("s", Ready("p", "s", Now));

        Assert.Null(store.PeekCurrent("s", "p", Now, Binding));
        Assert.Equal(1, store.Count); // non-consuming: the promoted state still awaits its redeem
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
        store.Seed("s", Pending("p", "s", Now.AddMinutes(5)));

        Assert.Null(store.PeekCurrent("s", "p", Now, Binding));
    }

    // --- Browser-binding gate (#326): the callback must present the id recorded at challenge ---

    [Fact]
    public void PeekCurrent_MismatchedBinding_ReturnsNull()
    {
        // A state started in browser A cannot be peeked from browser B: the presented binding id does
        // not match the recorded one, so the forced-login callback is refused before any token exchange.
        var store = Store();
        store.Seed("s", Pending("p", "s", Now, binding: "browser-A"));

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
        store.Seed("tok", Ready("p", "tok", Now, binding: "browser-A"));

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
        store.Seed("s", Pending("p", "s", Now));

        Assert.Null(store.PeekCurrent("s", "p", Now, presentedBindingId));
        Assert.Equal(1, store.Count);
    }

    // --- ProviderInformation reuse (#247) + response-iss requirement (#210): folded into the Pending ---

    [Fact]
    public void PeekCurrent_CarriesTheProviderInformationTheChallengeCaptured()
    {
        // The challenge builds the Pending complete with the discovery metadata it already fetched and
        // validated; the store round-trips it to the peek the OidPost callback reads, so
        // ProcessResponseAsync reuses it instead of re-running discovery + JWKS (#247, #341).
        var store = Store();
        var info = new ProviderInformation { IssuerName = "https://idp.example" };
        Assert.True(store.TryAdd(Pending("p", "s", Now, info: info), out _));

        var pending = store.PeekCurrent("s", "p", Now, Binding);
        Assert.NotNull(pending);
        Assert.Same(info, pending.ProviderInformation);
    }

    [Fact]
    public void PeekWithoutProviderInformation_ExposesNull_SoTheCallbackFallsBackToDiscovery()
    {
        // A state whose challenge captured no discovery (a flow that predates the capture) exposes null,
        // so the callback's CreateOidcClient runs a fresh discovery — never a broken login.
        var store = Store();
        Assert.True(store.TryAdd(Pending("p", "s", Now), out _));

        var pending = store.PeekCurrent("s", "p", Now, Binding);
        Assert.NotNull(pending);
        Assert.Null(pending.ProviderInformation);
    }

    [Fact]
    public void PeekCurrent_CarriesTheResponseIssuerRequiredFlag()
    {
        // The challenge marks a state (at construction) when discovery advertises the RFC 9207 response-iss
        // parameter; the store round-trips the flag to the peek the OidPost callback reads so it requires
        // iss to be present (#210).
        var store = Store();
        Assert.True(store.TryAdd(Pending("p", "s", Now, responseIssuerRequired: true), out _));

        var pending = store.PeekCurrent("s", "p", Now, Binding);
        Assert.NotNull(pending);
        Assert.True(pending.ResponseIssuerRequired);
    }

    [Fact]
    public void ResponseIssuerRequired_DefaultsFalse_WhenNotMarked()
    {
        // The tolerant default: a state whose provider did not advertise the parameter exposes false, so
        // the callback keeps tolerating an absent iss — no lockout of older IdPs.
        var store = Store();
        Assert.True(store.TryAdd(Pending("p", "s", Now), out _));

        var pending = store.PeekCurrent("s", "p", Now, Binding);
        Assert.NotNull(pending);
        Assert.False(pending.ResponseIssuerRequired);
    }

    // --- Promote (OidPost): the atomic Pending -> Ready swap that makes a state redeemable (#341) ---

    [Fact]
    public void Promote_SwapsPendingToReady_MakingItRedeemableWithTheDerivedFields()
    {
        // The callback derives the role-gate result and promotes the peeked Pending; the redeem then sees
        // exactly that result. This replaces the old in-place field copy with a single atomic swap.
        var store = Store();
        Assert.True(store.TryAdd(Pending("p", "tok", Now), out _));
        var pending = store.PeekCurrent("tok", "p", Now, Binding);
        Assert.NotNull(pending);

        Assert.True(store.Promote(pending, FullDerived()));

        var redeemed = store.TryRedeem("tok", "p", Now, Binding);
        Assert.NotNull(redeemed);
        Assert.Equal("alice", redeemed.Identity.Username);
        Assert.Equal("sub-full", redeemed.Identity.Subject);
        Assert.True(redeemed.Identity.Admin);
        Assert.Equal(new[] { "movies" }, redeemed.Identity.Folders);
        Assert.Equal("https://idp.example/a.png", redeemed.Identity.AvatarUrl);
    }

    [Fact]
    public void Promote_BeforePromotion_TheStateIsNotYetRedeemable()
    {
        // A redeem arriving before the callback promotes the state finds a Pending (role gate not passed),
        // so it is refused without consuming — the callback can still promote it afterwards.
        var store = Store();
        Assert.True(store.TryAdd(Pending("p", "tok", Now), out _));

        Assert.Null(store.TryRedeem("tok", "p", Now, Binding));
        Assert.Equal(1, store.Count);

        var pending = store.PeekCurrent("tok", "p", Now, Binding);
        Assert.NotNull(pending);
        Assert.True(store.Promote(pending, FullDerived()));
        Assert.NotNull(store.TryRedeem("tok", "p", Now, Binding));
    }

    [Fact]
    public void Promote_SecondPromote_IsRejected_SingleWinner()
    {
        // The atomic swap is single-winner: two callbacks racing to promote the same peeked Pending can
        // only succeed once (the second's compare-and-set fails because the value is already a Ready), so
        // one authorize state yields at most one redeemable session.
        var store = Store();
        Assert.True(store.TryAdd(Pending("p", "tok", Now), out _));
        var pending = store.PeekCurrent("tok", "p", Now, Binding);
        Assert.NotNull(pending);

        Assert.True(store.Promote(pending, FullDerived()));
        Assert.False(store.Promote(pending, FullDerived())); // already a Ready; the swap comparand no longer matches
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void Promote_AfterRedeem_IsRejected()
    {
        // Promotion loses to a redeem that already claimed and removed the entry: the compare-and-set
        // finds no matching value, so it is a no-op — no resurrected, re-redeemable state.
        var store = Store();
        store.Seed("tok", Ready("p", "tok", Now));
        var alreadyReady = store.PeekCurrent("tok", "p", Now, Binding); // null: it is a Ready, not a Pending
        Assert.Null(alreadyReady);

        Assert.NotNull(store.TryRedeem("tok", "p", Now, Binding));
        Assert.Equal(0, store.Count);

        // A promote for a Pending that was never in the store (or is gone) simply does nothing.
        Assert.False(store.Promote(Pending("p", "tok", Now), FullDerived()));
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public async Task PromoteRacingRedeem_YieldsEitherNothingOrACompleteReady_NeverAPartialOne()
    {
        // The core #341 property: a redeem racing the promotion observes either the whole Pending (not
        // redeemable) or the whole Ready with every derived field present — never a half-applied field
        // set, because the swap replaces one immutable value with another atomically. Many rounds exercise
        // the interleaving; any redeemed Ready must be fully populated.
        for (var round = 0; round < 200; round++)
        {
            var store = Store();
            var token = "tok-" + round;
            Assert.True(store.TryAdd(Pending("p", token, Now), out _));
            var pending = store.PeekCurrent(token, "p", Now, Binding);
            Assert.NotNull(pending);

            var promote = Task.Run(() => store.Promote(pending, FullDerived()), TestContext.Current.CancellationToken);
            var redeem = Task.Run(() => store.TryRedeem(token, "p", Now, Binding), TestContext.Current.CancellationToken);
            await Task.WhenAll(promote, redeem);

            var redeemed = await redeem;
            if (redeemed != null)
            {
                Assert.Equal("alice", redeemed.Identity.Username);
                Assert.Equal("sub-full", redeemed.Identity.Subject);
                Assert.True(redeemed.Identity.Admin);
                Assert.Equal(new[] { "movies" }, redeemed.Identity.Folders);
                Assert.Equal("https://idp.example/a.png", redeemed.Identity.AvatarUrl);
            }
        }
    }

    // --- TryRedeem (OidAuth/OidLink): promoted + response match + provider + unexpired, one-time ---

    [Fact]
    public void TryRedeem_AllConditionsMet_ReturnsTheSnapshotFields()
    {
        var store = Store();
        store.Seed("tok", Ready(
            "p", "tok", Now,
            subject: "sub-1", username: "alice", admin: true,
            folders: new List<string> { "movies" }, enableLiveTv: true, enableLiveTvManagement: false,
            avatar: "https://idp.example.com/a.png"));

        var redeemed = store.TryRedeem("tok", "p", Now, Binding);

        Assert.NotNull(redeemed);
        Assert.Equal("sub-1", redeemed.Identity.Subject);
        Assert.Equal("alice", redeemed.Identity.Username);
        Assert.True(redeemed.Identity.Admin);
        Assert.Equal(new[] { "movies" }, redeemed.Identity.Folders);
        Assert.True(redeemed.Identity.EnableLiveTv);
        Assert.False(redeemed.Identity.EnableLiveTvManagement);
        Assert.Equal("https://idp.example.com/a.png", redeemed.Identity.AvatarUrl);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void TryRedeem_AbsentPresentedBinding_ReturnsNull(string? presentedBindingId)
    {
        // Fail closed on the redeem leg too, and without consuming: a missing/empty cookie must not
        // burn the state either.
        var store = Store();
        store.Seed("tok", Ready("p", "tok", Now));

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
        store.Seed("tok", Ready("p", "tok", Now, binding: null));

        Assert.Null(store.TryRedeem("tok", "p", Now, "anything"));
        Assert.Null(store.TryRedeem("tok", "p", Now, null));
        Assert.Equal(1, store.Count); // none of the fail-closed attempts consumed the entry
    }

    [Fact]
    public void TryRedeem_NotPromoted_ReturnsNullAndDoesNotConsume()
    {
        // A still-pending state (the role gate has not passed) is not redeemable, and a failed redeem must
        // not burn it — the callback leg may still promote it.
        var store = Store();
        store.Seed("tok", Pending("p", "tok", Now));

        Assert.Null(store.TryRedeem("tok", "p", Now, Binding));
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void TryRedeem_CrossProviderReplay_ReturnsNullAndEntrySurvives()
    {
        // The state-scoping guard: a state validated at a low-trust provider must not be replayable
        // against a higher-trust provider's endpoint, bypassing that provider's login/role gate.
        var store = Store();
        store.Seed("tok", Ready("low-trust", "tok", Now));

        Assert.Null(store.TryRedeem("tok", "high-trust", Now, Binding));
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void TryRedeem_ResponseMismatch_ReturnsNull()
    {
        // The stored authorize-state token must match the presented one even when the key does.
        var store = Store();
        store.Seed("a", Ready("p", "b", Now));

        Assert.Null(store.TryRedeem("a", "p", Now, Binding));
    }

    [Fact]
    public void TryRedeem_Expired_ReturnsNull()
    {
        var store = Store();
        store.Seed("tok", Ready("p", "tok", Now.AddMinutes(-2)));

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
        store.Seed("tok", Ready("p", "tok", Now));

        Assert.NotNull(store.TryRedeem("tok", "p", Now, Binding)); // the redeeming request wins the claim
        Assert.Null(store.TryRedeem("tok", "p", Now, Binding));    // a replay finds it already consumed
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public void ConsumedState_IsNoLongerPeekable()
    {
        var store = Store();
        store.Seed("tok", Ready("p", "tok", Now));
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
        store.Seed("tok", Ready("p", "tok", Now));

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
        store.Seed("expired", Pending("p", "expired", Now.AddMinutes(-5)));
        store.Seed("fresh", Pending("p", "fresh", Now.AddSeconds(-10)));

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
        store.Seed("at-boundary", Pending("p", "at-boundary", Now.Subtract(Lifetime)));
        store.Seed("past-boundary", Pending("p", "past-boundary", Now.Subtract(Lifetime).AddTicks(-1)));

        store.PruneExpired(Now);

        Assert.Equal(1, store.Count);
        Assert.NotNull(store.PeekCurrent("at-boundary", "p", Now, Binding));
    }

    [Fact]
    public void PruneExpired_WithinTheInterval_IsThrottled_AndTheUnsweptEntryIsStillRejected()
    {
        // The throttle only defers memory reclamation: a suppressed sweep leaves the expired entry in
        // the store, but the redeem predicate rejects it independently on expiry — fail closed either way.
        var store = Store();
        store.PruneExpired(Now); // anchors the gate
        store.Seed("expired", Ready("p", "expired", Now.AddMinutes(-5)));

        store.PruneExpired(Now.AddSeconds(1)); // inside the interval: suppressed, no sweep
        Assert.Equal(1, store.Count);
        Assert.Null(store.TryRedeem("expired", "p", Now.AddSeconds(1), Binding)); // rejected on expiry, not consumed

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
        store.Seed("seed-expired", Pending("p", "seed-expired", Now.AddMinutes(-5)));

        var adder = Task.Run(
            () =>
            {
                for (var i = 0; i < 5000; i++)
                {
                    store.TryAdd(Pending("p", "fresh-" + i, Now), out _);
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

        Assert.True(store.TryAdd(Pending("p", "a", Now), out var warnA));
        Assert.True(store.TryAdd(Pending("p", "b", Now), out var warnB));
        Assert.False(warnA);
        Assert.False(warnB);
        Assert.Equal(2, store.Count);
    }

    [Fact]
    public void TryAdd_AtCap_RefusesANewKeyAndKeepsTheInFlightState()
    {
        var store = Store(maxEntries: 1);
        Assert.True(store.TryAdd(Pending("p", "in-flight", Now), out _));

        // At the cap, a fresh challenge is refused rather than evicting the user already mid-login.
        Assert.False(store.TryAdd(Pending("p", "new", Now), out _));
        Assert.Equal(1, store.Count);
        Assert.NotNull(store.PeekCurrent("in-flight", "p", Now, Binding));
    }

    [Fact]
    public void TryAdd_DuplicateKey_ReturnsFalse()
    {
        var store = Store(maxEntries: 10);
        Assert.True(store.TryAdd(Pending("p", "a", Now), out _));
        Assert.False(store.TryAdd(Pending("p", "a", Now), out _));
    }

    [Fact]
    public void TryAdd_Refused_SignalsTheCapacityWarningOncePerInterval()
    {
        // The warning signal is bounded exactly like the sweeps: the first refusal signals, further
        // refusals inside the interval stay silent, so a flood cannot amplify into log volume. The gate
        // is driven by the Pending's Created instant (which is the challenge's DateTime.Now).
        var store = Store(maxEntries: 1);
        Assert.True(store.TryAdd(Pending("p", "a", Now), out _));

        Assert.False(store.TryAdd(Pending("p", "b", Now), out var firstWarn));
        Assert.True(firstWarn);

        Assert.False(store.TryAdd(Pending("p", "c", Now.AddSeconds(1)), out var secondWarn));
        Assert.False(secondWarn);

        Assert.False(store.TryAdd(Pending("p", "d", Now + PruneInterval), out var nextIntervalWarn));
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
                        if (!store.TryAdd(Pending("p", $"t{id}-k{i}", Now), out _))
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
    public void Summaries_ProjectExactlyTheNonSecretFields_AndMapTheVariantToValid()
    {
        // Structural redaction: the Summary record carries Provider/Created/Valid/IsLinking and
        // nothing else — the authorize-state token and PKCE code_verifier / nonce cannot leak through it,
        // even to an admin. "Valid" is now which variant the entry is: a promoted Ready is valid.
        var store = Store();
        store.Seed("secret-ready", Ready("p", "secret-ready", Now, isLinking: true));
        store.Seed("secret-pending", Pending("q", "secret-pending", Now));

        var summaries = store.Summaries().ToList();

        var ready = Assert.Single(summaries, s => s.Provider == "p");
        Assert.Equal(Now, ready.Created);
        Assert.True(ready.Valid); // a Ready is a verified login
        Assert.True(ready.IsLinking);

        var pending = Assert.Single(summaries, s => s.Provider == "q");
        Assert.False(pending.Valid); // a Pending has not passed the role gate
        Assert.False(pending.IsLinking);
    }

    // --- Per-client sub-cap (#327): global 200 -> per-key 2 unless noted ---

    // Promotes a just-added (still pending) state to redeemable via the production path (peek + Promote),
    // so TryRedeem — which requires a promoted state — can exercise the per-client release.
    private static void Validate(OidcStateStore store, string token) =>
        store.Promote(
            store.PeekCurrent(token, "p", Now, Binding),
            new OidcAuthorizeStateBuilder.OidcAuthorizeState("u", "sub", null, null, true, false, false, false, new List<string>(), null));

    [Fact]
    public void TryAdd_FloodFromOneKey_DoesNotRefuseADifferentKey()
    {
        // The core fairness property: filling client "A" to its per-key share must not deny "B".
        var store = Store(maxEntries: 200); // per-key cap 2
        Assert.True(store.TryAdd(Pending("p", "a1", Now, clientKey: "A"), out _));
        Assert.True(store.TryAdd(Pending("p", "a2", Now, clientKey: "A"), out _));
        Assert.False(store.TryAdd(Pending("p", "a3", Now, clientKey: "A"), out var warn)); // A at share
        Assert.True(warn); // the throttled capacity warning fires for the first per-client refusal

        Assert.True(store.TryAdd(Pending("p", "b1", Now, clientKey: "B"), out _)); // B unaffected
    }

    [Fact]
    public void TryAdd_ReleaseOnRedeem_ReadmitsTheSameKey()
    {
        var store = Store(maxEntries: 200); // per-key cap 2
        store.TryAdd(Pending("p", "a1", Now, clientKey: "A"), out _);
        store.TryAdd(Pending("p", "a2", Now, clientKey: "A"), out _);
        Assert.False(store.TryAdd(Pending("p", "a3", Now, clientKey: "A"), out _)); // full

        Validate(store, "a1");
        Assert.NotNull(store.TryRedeem("a1", "p", Now, Binding)); // frees one A slot
        Assert.True(store.TryAdd(Pending("p", "a3", Now, clientKey: "A"), out _));
    }

    [Fact]
    public void TryAdd_ReleaseOnExpirySweep_ReadmitsTheSameKey()
    {
        var store = Store(maxEntries: 200); // per-key cap 2
        store.TryAdd(Pending("p", "a1", Now, clientKey: "A"), out _);
        store.TryAdd(Pending("p", "a2", Now, clientKey: "A"), out _);

        // Past the lifetime and the prune interval, the sweep removes both A entries and releases their
        // slots, so A can add again. (Lifetime and PruneInterval are the test fixture's small values.)
        var later = Now + Lifetime + PruneInterval + TimeSpan.FromSeconds(1);
        store.PruneExpired(later);
        Assert.True(store.TryAdd(Pending("p", "a3", later, clientKey: "A"), out _));
    }

    [Fact]
    public void TryAdd_ReleaseOnFailedGlobalInsert_DoesNotLeakTheClientSlot()
    {
        // Global cap 2 -> per-key cap 1. Fill the store to the global cap with exempt (null) keys, then
        // a "A" add reserves A's slot but is refused by the GLOBAL cap and must roll back. After a slot
        // frees, "A" must still admit — a leaked reservation would leave A at its cap of 1.
        var store = Store(maxEntries: 2);
        Assert.True(store.TryAdd(Pending("p", "n1", Now, clientKey: null), out _));
        Assert.True(store.TryAdd(Pending("p", "n2", Now, clientKey: null), out _));

        Assert.False(store.TryAdd(Pending("p", "a1", Now, clientKey: "A"), out _)); // global cap
        Validate(store, "n1");
        Assert.NotNull(store.TryRedeem("n1", "p", Now, Binding)); // free one global slot
        Assert.True(store.TryAdd(Pending("p", "a1", Now, clientKey: "A"), out _)); // no leak
    }

    [Fact]
    public void TryAdd_NullKeyIsExempt_BoundedOnlyByTheGlobalCap()
    {
        // Global cap 2 -> per-key cap 1. A null (proxy/unattributable) key is never sub-capped: null adds
        // succeed past a per-key cap of 1 up to the GLOBAL cap, then are refused by the global cap.
        var store = Store(maxEntries: 2);
        Assert.True(store.TryAdd(Pending("p", "n1", Now, clientKey: null), out _));
        Assert.True(store.TryAdd(Pending("p", "n2", Now, clientKey: null), out _)); // past per-key 1
        Assert.False(store.TryAdd(Pending("p", "n3", Now, clientKey: null), out _)); // global cap
    }

    [Fact]
    public void TryAdd_DistinctKeys_FillToGlobalCap_ThenRefuseNotEvict()
    {
        // The per-key cap must not block distinct keys: fill the store to the global cap with one entry
        // each per distinct key, then a further distinct key is refused (global cap) and the existing
        // entries survive (refuse-not-evict).
        var store = Store(maxEntries: 3); // per-key cap 1
        Assert.True(store.TryAdd(Pending("p", "k1", Now, clientKey: "K1"), out _));
        Assert.True(store.TryAdd(Pending("p", "k2", Now, clientKey: "K2"), out _));
        Assert.True(store.TryAdd(Pending("p", "k3", Now, clientKey: "K3"), out _));
        Assert.False(store.TryAdd(Pending("p", "k4", Now, clientKey: "K4"), out _)); // global cap
        Assert.NotNull(store.PeekCurrent("k1", "p", Now, Binding)); // not evicted
    }
}
