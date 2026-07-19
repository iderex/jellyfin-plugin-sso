using System;
using System.Collections.Generic;
using System.Globalization;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlOutcomeStore"/> — the one-time SAML login-outcome store (#251): an outcome
/// registered at the ACS callback is redeemable exactly once at the mint leg, is scoped to its own
/// provider so a token cannot be replayed against another's endpoint, expires with its lifetime, and
/// bounds per-client occupancy so one source cannot fill it. This is the SAML analogue of the OpenID
/// authorize-state store's one-time redeem; the properties mirror <see cref="SamlRequestCache"/>'s.
/// </summary>
public class SamlOutcomeStoreTests
{
    private static readonly DateTime Now = new DateTime(2026, 7, 18, 12, 0, 0, DateTimeKind.Utc);

    // A store whose per-key sub-cap is small and reachable (global 200 -> per-key 2).
    private static SamlOutcomeStore SmallStore() => new SamlOutcomeStore(200, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(1));

    // A verified identity is opaque to the store; any real one will do. Built through the SAML factory so
    // the test does not forge one (its constructor is private).
    private static VerifiedIdentity Identity(string provider = "adfs") =>
        TestIdentities.Saml(provider, "alice", SamlAuthorizeStateBuilder.Build(new List<string>(), new SamlConfig()));

    private static SamlLoginOutcome Outcome(string token, string provider = "adfs", string inResponseTo = "", string? clientKey = null, DateTime? created = null) =>
        new SamlLoginOutcome(token, provider, Identity(provider), inResponseTo, clientKey, created ?? Now);

    [Fact]
    public void Add_ThenRedeem_SucceedsOnce_ThenReplayReturnsNull()
    {
        var store = new SamlOutcomeStore();
        Assert.True(store.TryAdd(Outcome("tok-1"), out _));

        var redeemed = store.TryRedeem("tok-1", "adfs", Now);
        Assert.NotNull(redeemed);
        Assert.Equal("alice", redeemed!.Identity.Username);

        // Single-use: a replay of the same token finds nothing (the atomic redeem removed it).
        Assert.Null(store.TryRedeem("tok-1", "adfs", Now));
    }

    [Fact]
    public void Redeem_UnknownToken_ReturnsNull()
    {
        var store = new SamlOutcomeStore();
        Assert.Null(store.TryRedeem("never-issued", "adfs", Now));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Redeem_BlankToken_ReturnsNull(string? token)
    {
        var store = new SamlOutcomeStore();
        Assert.Null(store.TryRedeem(token!, "adfs", Now));
    }

    [Fact]
    public void Redeem_WrongProvider_ReturnsNull_AndDoesNotConsumeTheOutcome()
    {
        // Cross-provider replay guard: an outcome verified for one provider is not redeemable on another's
        // mint endpoint, and the failed attempt must NOT consume it — the correct provider still redeems.
        var store = new SamlOutcomeStore();
        store.TryAdd(Outcome("tok-1", provider: "adfs"), out _);

        Assert.Null(store.TryRedeem("tok-1", "other", Now));
        Assert.NotNull(store.TryRedeem("tok-1", "adfs", Now));
    }

    [Fact]
    public void Redeem_AfterExpiry_ReturnsNull()
    {
        var store = new SamlOutcomeStore(200, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(1));
        store.TryAdd(Outcome("tok-1", created: Now), out _);

        // Past the lifetime the outcome is no longer redeemable, even though the sweep may not have run.
        Assert.Null(store.TryRedeem("tok-1", "adfs", Now.AddMinutes(16)));
    }

    [Fact]
    public void Redeem_NegativeAge_ReturnsNull()
    {
        // A backward clock step (Created in the future relative to now) must not make an outcome
        // effectively never expire — it is rejected as out of its window.
        var store = new SamlOutcomeStore();
        store.TryAdd(Outcome("tok-1", created: Now.AddMinutes(5)), out _);

        Assert.Null(store.TryRedeem("tok-1", "adfs", Now));
    }

    [Fact]
    public void PruneExpired_RemovesExpired_KeepsLive()
    {
        var store = new SamlOutcomeStore(200, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(1));
        store.TryAdd(Outcome("old", created: Now), out _);
        store.TryAdd(Outcome("fresh", created: Now.AddMinutes(20)), out _);

        store.PruneExpired(Now.AddMinutes(20));

        Assert.Null(store.TryRedeem("old", "adfs", Now.AddMinutes(20)));
        Assert.NotNull(store.TryRedeem("fresh", "adfs", Now.AddMinutes(20)));
    }

    [Fact]
    public void Add_FloodFromOneKey_DoesNotRefuseADifferentKey()
    {
        // Fairness: filling client "A" to its per-key share must not deny a login from client "B".
        var store = SmallStore(); // per-key cap 2
        Assert.True(store.TryAdd(Outcome("a1", clientKey: "A"), out _));
        Assert.True(store.TryAdd(Outcome("a2", clientKey: "A"), out _));
        Assert.False(store.TryAdd(Outcome("a3", clientKey: "A"), out var warn)); // A at its share
        Assert.True(warn); // the throttled capacity warning fires for the first refusal in the interval

        Assert.True(store.TryAdd(Outcome("b1", clientKey: "B"), out _)); // B is unaffected
    }

    [Fact]
    public void Add_ReleaseOnRedeem_ReadmitsTheSameKey()
    {
        var store = SmallStore(); // per-key cap 2
        store.TryAdd(Outcome("a1", clientKey: "A"), out _);
        store.TryAdd(Outcome("a2", clientKey: "A"), out _);
        Assert.False(store.TryAdd(Outcome("a3", clientKey: "A"), out _)); // full

        Assert.NotNull(store.TryRedeem("a1", "adfs", Now)); // frees one A slot
        Assert.True(store.TryAdd(Outcome("a3", clientKey: "A"), out _));
    }

    [Fact]
    public void Add_OverflowCap_DoesNotThrow_AndPreservesInFlightOutcome()
    {
        // At the cap a fresh outcome is refused rather than evicting an in-flight one; a flood cannot
        // displace a user mid-login, and registration never throws under the overflow path.
        var store = new SamlOutcomeStore();
        store.TryAdd(Outcome("_inflight", clientKey: null), out _);

        var exception = Record.Exception(() =>
        {
            for (var i = 0; i < 100_050; i++)
            {
                store.TryAdd(Outcome("_flood-" + i.ToString(CultureInfo.InvariantCulture), clientKey: null), out _);
            }
        });

        Assert.Null(exception);
        Assert.NotNull(store.TryRedeem("_inflight", "adfs", Now));
    }

    [Fact]
    public void Reserve_ThenCommit_StoresARedeemableOutcome()
    {
        // The two-phase path the ACS callback uses (#539): reserve capacity first, then commit the built
        // outcome once the assertion is consumed. The committed outcome redeems exactly like a TryAdd one.
        var store = SmallStore();
        Assert.True(store.TryReserve(clientKey: "A", Now, out var warn));
        Assert.False(warn);
        Assert.True(store.CommitReserved(Outcome("tok-1", clientKey: "A")));

        Assert.NotNull(store.TryRedeem("tok-1", "adfs", Now));
    }

    [Fact]
    public void Reserve_AtGlobalCap_Refuses_SoTheCallerNeverConsumesTheAssertion()
    {
        // #539: a full store refuses the reservation BEFORE the caller would consume the one-time replay
        // cache, so a capacity refusal never burns the assertion. A null (exempt) key isolates the GLOBAL cap
        // from the per-client sub-cap, so this proves the global-cap branch, not the per-client one.
        var store = new SamlOutcomeStore(1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(1));
        Assert.True(store.TryAdd(Outcome("filler", clientKey: null), out _)); // occupies the one global slot

        Assert.False(store.TryReserve(clientKey: null, Now, out var warn));
        Assert.True(warn); // the throttled capacity warning fires for the first refusal in the interval
    }

    [Fact]
    public void Release_AfterReserveWithoutCommit_FreesThePerClientSlot()
    {
        // A reservation that is not committed — a replayed or otherwise invalid assertion at the callback —
        // must release its per-client slot, or the sub-cap would leak on every refused login and eventually
        // lock the client out for real.
        var store = SmallStore(); // per-key cap 2
        Assert.True(store.TryReserve("A", Now, out _));
        Assert.True(store.TryReserve("A", Now, out _)); // A holds its full share, all uncommitted
        Assert.False(store.TryReserve("A", Now, out _)); // at the sub-cap

        store.ReleaseReservation("A"); // abandon one reservation
        Assert.True(store.TryReserve("A", Now, out _)); // the freed slot readmits A
    }

    [Fact]
    public void NewToken_IsUnguessableAndDistinct()
    {
        // A CSPRNG token: two mints never collide. A token that misses the store falls through to the
        // deprecation validation, which fails closed either way — the hex may Base64-decode, but its bytes
        // are not a SAML response, so the XML parse rejects it (covered end-to-end by UnknownToken_Rejects).
        var a = SamlOutcomeStore.NewToken();
        var b = SamlOutcomeStore.NewToken();
        Assert.NotEqual(a, b);
        Assert.Equal(64, a.Length); // 32 CSPRNG bytes, hex-encoded
    }
}
