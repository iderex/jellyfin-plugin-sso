using System;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlReplayCache"/> — one-time-use of SAML assertion IDs, and the retention
/// window that keeps a consumed id long enough that it cannot be replayed while still acceptable.
/// </summary>
public class SamlReplayCacheTests
{
    private static readonly DateTime Now = new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void TryConsume_FirstUse_Succeeds_SecondUse_IsReplay()
    {
        var cache = new SamlReplayCache();
        var expiry = Now.AddMinutes(10);

        Assert.True(cache.TryConsume("_assertion-1", expiry, Now, out _));
        Assert.False(cache.TryConsume("_assertion-1", expiry, Now, out _));
    }

    [Fact]
    public void TryConsume_DistinctIds_EachSucceedOnce()
    {
        var cache = new SamlReplayCache();
        var expiry = Now.AddMinutes(10);

        Assert.True(cache.TryConsume("_a", expiry, Now, out _));
        Assert.True(cache.TryConsume("_b", expiry, Now, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void TryConsume_MissingId_FailsClosed(string? id)
    {
        var cache = new SamlReplayCache();
        Assert.False(cache.TryConsume(id!, Now.AddMinutes(10), Now, out _));
    }

    [Fact]
    public void TryConsume_AfterEntryExpires_IdCanBeUsedAgain()
    {
        // Once retention has elapsed the entry is evicted; a fresh assertion reusing the id (a new
        // login, not a replay of the same still-valid assertion) is accepted again.
        var cache = new SamlReplayCache();
        Assert.True(cache.TryConsume("_a", Now.AddMinutes(10), Now, out _));

        var later = Now.AddMinutes(20);
        Assert.True(cache.TryConsume("_a", later.AddMinutes(10), later, out _));
    }

    // --- Hard cap + throttled prune + throttled cap-refusal warning (#452, #470) ---

    // A cache whose cap is small and reachable (production 100k is not).
    private static SamlReplayCache SmallCache(int cap = 3) => new SamlReplayCache(cap, TimeSpan.FromMinutes(1));

    [Fact]
    public void TryConsume_ReplayStillRejected_UnderCapPressure()
    {
        // The security regression: a live consumed assertion must NEVER be evicted to make room, or its
        // replay would be re-admitted. Record X (live), fill the rest of the cap with other live logins,
        // then push a new distinct login (refused fail-closed), then replay X — X must still be rejected,
        // proving its live entry survived the cap pressure.
        var cache = SmallCache(cap: 3);
        var expiry = Now.AddMinutes(10);

        Assert.True(cache.TryConsume("_x", expiry, Now, out _));
        Assert.True(cache.TryConsume("_f1", expiry, Now, out _));
        Assert.True(cache.TryConsume("_f2", expiry, Now, out _)); // cache now full of live entries

        Assert.False(cache.TryConsume("_new", expiry, Now, out _)); // fail closed: no live entry evicted
        Assert.False(cache.TryConsume("_x", expiry, Now, out _)); // X still recorded -> replay still caught
    }

    [Fact]
    public void TryConsume_AtCap_NewDistinctLogin_IsRejectedFailClosed()
    {
        var cache = SmallCache(cap: 2);
        var expiry = Now.AddMinutes(10);
        Assert.True(cache.TryConsume("_a", expiry, Now, out _));
        Assert.True(cache.TryConsume("_b", expiry, Now, out _)); // at cap with live entries

        Assert.False(cache.TryConsume("_c", expiry, Now, out _));
        Assert.Equal(2, cache.Count); // the refusal did not grow or evict
    }

    [Fact]
    public void TryConsume_Refused_SignalsTheCapacityWarningOncePerInterval()
    {
        // The cap-refusal warning is bounded exactly like the sweeps and the sibling caches (#470): the
        // first refusal in an interval signals, further refusals inside the interval stay silent (so a
        // burst of refusals cannot amplify into log volume), and the next interval signals again. It rides
        // its OWN gate, so filling the cache and refusing never touches the prune gate.
        var cache = SmallCache(cap: 1);
        var expiry = Now.AddMinutes(10);

        Assert.True(cache.TryConsume("_a", expiry, Now, out var admitWarn));
        Assert.False(admitWarn); // an admitted consume never warns

        Assert.False(cache.TryConsume("_b", expiry, Now, out var firstWarn));
        Assert.True(firstWarn); // first cap refusal in the interval signals

        Assert.False(cache.TryConsume("_c", expiry, Now.AddSeconds(1), out var secondWarn));
        Assert.False(secondWarn); // a second refusal within the interval stays silent

        var nextInterval = Now.AddMinutes(1);
        Assert.False(cache.TryConsume("_d", nextInterval.AddMinutes(10), nextInterval, out var nextWarn));
        Assert.True(nextWarn); // the next interval signals again
    }

    [Fact]
    public void TryConsume_ReplayAndMissingId_DoNotSignalCapacityWarning()
    {
        // The warning is scoped to genuine capacity pressure only. A replay refusal and a missing-id
        // refusal both still fail closed (the reject semantics are byte-identical to #452), but neither is
        // capacity pressure, so neither signals — a hot replay attempt or a stream of id-less assertions
        // cannot masquerade as a full cache. Production cap here, so the cap path never fires.
        var cache = new SamlReplayCache();
        var expiry = Now.AddMinutes(10);

        Assert.True(cache.TryConsume("_a", expiry, Now, out var firstWarn));
        Assert.False(firstWarn);

        // A replay: rejected, but not a capacity signal.
        Assert.False(cache.TryConsume("_a", expiry, Now, out var replayWarn));
        Assert.False(replayWarn);

        // A missing id: fails closed, and not a capacity signal.
        Assert.False(cache.TryConsume(string.Empty, expiry, Now, out var missingWarn));
        Assert.False(missingWarn);
    }

    [Fact]
    public void TryConsume_AtCap_WithExpiredEntries_ReclaimsThenAdmits()
    {
        // At the cap but full of EXPIRED (not yet swept) entries: the unthrottled reclaim at the cap frees
        // the slots and the fresh login is admitted, even though the routine sweep is still throttled.
        var cache = SmallCache(cap: 3);
        var shortExpiry = Now.AddSeconds(30);
        Assert.True(cache.TryConsume("_a", shortExpiry, Now, out _)); // first call enters the prune gate
        Assert.True(cache.TryConsume("_b", shortExpiry, Now, out _));
        Assert.True(cache.TryConsume("_c", shortExpiry, Now, out _)); // at cap

        // 40s later: past the entries' expiry but within the 1-minute prune interval, so the routine sweep
        // is throttled. The cap path must still reclaim the expired entries and admit the new login.
        var later = Now.AddSeconds(40);
        Assert.True(cache.TryConsume("_d", later.AddMinutes(10), later, out _));
        Assert.Equal(1, cache.Count); // only _d remains
    }

    [Fact]
    public void PruneExpired_IsIntervalGateThrottled_NotRunEveryCall()
    {
        // The sweep must be throttled, not run on every consume. Add an entry that expires, then a consume
        // WITHIN the prune interval must leave the expired entry in place (an unthrottled sweep would drop
        // it) — proving the IntervalGate throttle is in effect.
        var cache = new SamlReplayCache(); // production cap: the cap path never fires here
        Assert.True(cache.TryConsume("_a", Now.AddSeconds(30), Now, out _)); // enters the gate

        var within = Now.AddSeconds(40); // past _a's expiry, within the 1-minute interval
        Assert.True(cache.TryConsume("_b", within.AddMinutes(10), within, out _));
        Assert.Equal(2, cache.Count); // _a NOT swept -> prune is throttled

        var beyond = Now.AddSeconds(80); // past the interval: the sweep runs and reclaims _a
        Assert.True(cache.TryConsume("_c", beyond.AddMinutes(10), beyond, out _));
        Assert.Equal(2, cache.Count); // _a reclaimed; _b and _c remain
    }

    [Fact]
    public void TryConsume_ExpiredEntry_ReclaimedByThrottledPrune()
    {
        var cache = new SamlReplayCache();
        Assert.True(cache.TryConsume("_a", Now.AddMinutes(1), Now, out _));

        // A later consume past the prune interval sweeps the expired _a.
        var later = Now.AddMinutes(2);
        Assert.True(cache.TryConsume("_b", later.AddMinutes(10), later, out _));
        Assert.Equal(1, cache.Count); // _a reclaimed, only _b remains
    }

    [Fact]
    public void ComputeRetention_NoExpiry_UsesOneHourFloor()
    {
        Assert.Equal(Now.AddHours(1), SamlReplayCache.ComputeRetention(Now, null));
    }

    [Fact]
    public void ComputeRetention_ShortExpiry_UsesFloor()
    {
        // A 5-minute assertion expiry (+skew) is below the one-hour floor, so the floor wins.
        Assert.Equal(Now.AddHours(1), SamlReplayCache.ComputeRetention(Now, Now.AddMinutes(5)));
    }

    [Fact]
    public void ComputeRetention_LongExpiry_UsesExpiryPlusSkew()
    {
        var expiry = Now.AddHours(3);
        Assert.Equal(expiry + SamlAssertionTime.ClockSkew, SamlReplayCache.ComputeRetention(Now, expiry));
    }
}
