// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests pinning IntervalGate's once-per-interval semantics — the shared throttle the
/// anonymous-path sweeps and log signals rely on to not amplify a flood into CPU or log volume (#246,
/// #195). The wall-clock cases (boundary, backward step) are the primary evidence for the #318 step 2b
/// unification because CI cannot move real time. The guard suppresses a sub-interval span in either
/// direction (|now - last| &lt; interval), then a single CAS winner enters per interval: a genuine
/// correction (backward span &ge; interval) self-heals, while a stale sub-interval sample is suppressed
/// rather than re-admitted (#334), closing the original fail-open residual without opening a stall.
/// </summary>
public class IntervalGateTests
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    private static DateTime At(int hour, int minute, int second = 0) =>
        new DateTime(2026, 1, 1, hour, minute, second, DateTimeKind.Utc);

    [Fact]
    public void TryEnter_FirstCall_Enters()
    {
        // Cursor starts at MinValue, so the onset always sees a full interval and enters at once.
        Assert.True(new IntervalGate(Interval).TryEnter(At(0, 0)));
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    public void Ctor_NonPositiveInterval_ThrowsInsteadOfSilentlyDisablingTheThrottle(long ticks)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new IntervalGate(TimeSpan.FromTicks(ticks)));
    }

    [Fact]
    public void TryEnter_SecondCallWithinInterval_IsThrottled()
    {
        var gate = new IntervalGate(Interval);
        Assert.True(gate.TryEnter(At(0, 0)));
        Assert.False(gate.TryEnter(At(0, 0, 59)));
    }

    [Fact]
    public void TryEnter_AtExactlyTheInterval_Enters()
    {
        // Elapsed == interval fails the strict sub-interval guard, so the next call enters.
        var gate = new IntervalGate(Interval);
        var t0 = At(0, 0);
        Assert.True(gate.TryEnter(t0));
        Assert.True(gate.TryEnter(t0 + Interval));
    }

    [Fact]
    public void TryEnter_OneTickBeforeTheInterval_IsThrottled()
    {
        var gate = new IntervalGate(Interval);
        var t0 = At(0, 0);
        Assert.True(gate.TryEnter(t0));
        Assert.False(gate.TryEnter(t0 + Interval - TimeSpan.FromTicks(1)));
    }

    [Fact]
    public void TryEnter_BackwardClockStepOfAtLeastTheInterval_EntersAndReAnchors()
    {
        // #246 self-heal: a genuine wall-clock correction — a backward span of at least the interval (DST
        // fall-back, NTP step) — must not stall the gate. It enters and re-anchors to the earlier time, so
        // throttling then resumes from there. Only sub-interval backward spans are treated as stale (#334).
        var gate = new IntervalGate(Interval);
        Assert.True(gate.TryEnter(At(12, 0)));

        var backward = At(11, 30);                                // 30 min back, well over the 1-min interval
        Assert.True(gate.TryEnter(backward));                     // large correction enters (self-heal)
        Assert.False(gate.TryEnter(backward.AddSeconds(30)));     // re-anchored to 11:30: throttled again
        Assert.True(gate.TryEnter(backward + Interval));          // a full interval past the new anchor: enters
    }

    [Fact]
    public void TryEnter_BackwardStepOfExactlyTheInterval_EntersAndReAnchors()
    {
        // The suppression guard is strict (|span| < interval), so a backward span of exactly one interval is
        // a correction, not a stale sample: it enters and re-anchors — the backward mirror of the forward
        // exactly-the-interval case, keeping the self-heal boundary symmetric.
        var gate = new IntervalGate(Interval);
        var t0 = At(12, 0);
        Assert.True(gate.TryEnter(t0));
        Assert.True(gate.TryEnter(t0 - Interval));                // exactly one interval back: self-heals
    }

    [Fact]
    public void TryEnter_StaleSubIntervalOlderSample_IsSuppressed()
    {
        // A caller whose captured 'now' is merely stale — descheduled between reading the clock and entering,
        // so it lands just behind the cursor (a sub-interval backward span) — is now suppressed, closing the
        // #334 fail-open second admission. The cursor is left untouched, so throttling still lifts exactly one
        // interval after the real entry; a stale blip can neither re-admit nor stall the gate.
        var gate = new IntervalGate(Interval);
        var t0 = At(12, 0);
        Assert.True(gate.TryEnter(t0));

        var stale = At(11, 59, 59);
        Assert.False(gate.TryEnter(stale));                       // stale sub-interval sample is suppressed
        Assert.False(gate.TryEnter(At(12, 0, 58)));               // cursor stayed at 12:00: still throttled
        Assert.True(gate.TryEnter(t0 + Interval));                // and opens exactly one interval after the entry
    }

    [Fact]
    public void TryEnter_RepeatedSubIntervalBackwardBlips_NeverStallBeyondOneInterval()
    {
        // The dangerous direction is a stall — a capped store refusing forever. Suppressing sub-interval
        // backward blips leaves the cursor untouched, so admission is still guaranteed one interval after the
        // last real entry no matter how many stale blips arrive; the wait can never exceed one interval.
        var gate = new IntervalGate(Interval);
        var t0 = At(12, 0);
        Assert.True(gate.TryEnter(t0));

        Assert.False(gate.TryEnter(At(11, 59, 30)));              // sub-interval backward blip: suppressed, no re-anchor
        Assert.False(gate.TryEnter(At(11, 59, 45)));              // another blip: still suppressed, cursor still 12:00
        Assert.True(gate.TryEnter(t0 + Interval));                // guaranteed open one interval after the real entry
    }

    [Fact]
    public void TryEnter_AfterEntering_ReAnchorsToTheEntryTime()
    {
        var gate = new IntervalGate(Interval);
        var t0 = At(0, 0);
        Assert.True(gate.TryEnter(t0));
        Assert.True(gate.TryEnter(t0 + Interval));                // enters, re-anchors to t0 + interval
        Assert.False(gate.TryEnter(t0 + Interval + TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public async Task TryEnter_ConcurrentCallersInOneInterval_AdmitExactlyOne()
    {
        // The CAS guarantees a single winner per interval, so a flood of concurrent anonymous hits runs the
        // throttled action at most once — the property that makes it a DoS-safe throttle at every call site.
        var gate = new IntervalGate(Interval);
        var now = At(0, 0);
        var winners = 0;
        var token = TestContext.Current.CancellationToken;
        using var start = new ManualResetEventSlim(false);

        var tasks = new Task[32];
        for (var i = 0; i < tasks.Length; i++)
        {
            tasks[i] = Task.Run(
                () =>
                {
                    start.Wait(token);
                    if (gate.TryEnter(now))
                    {
                        Interlocked.Increment(ref winners);
                    }
                },
                token);
        }

        start.Set();
        await Task.WhenAll(tasks);
        Assert.Equal(1, winners);
    }
}
