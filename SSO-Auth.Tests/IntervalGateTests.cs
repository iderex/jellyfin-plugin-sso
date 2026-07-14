using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests pinning IntervalGate's once-per-interval semantics — the shared throttle the
/// anonymous-path sweeps and log signals rely on to not amplify a flood into CPU or log volume (#246,
/// #195). The wall-clock cases (boundary, backward step) are the primary evidence for the #318 step 2b
/// unification because CI cannot move real time, and each adopting site's Interlocked original had exactly
/// these semantics: guard on a non-negative sub-interval span, then a single CAS winner per interval.
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
    public void TryEnter_BackwardClockStep_EntersAndReAnchors()
    {
        // #246 self-heal: a wall-clock correction (now earlier than the last entry) must not stall the
        // gate. It enters and re-anchors to the earlier time, so throttling then resumes from there.
        var gate = new IntervalGate(Interval);
        Assert.True(gate.TryEnter(At(12, 0)));

        var backward = At(11, 30);
        Assert.True(gate.TryEnter(backward));                     // backward step enters (self-heal)
        Assert.False(gate.TryEnter(backward.AddSeconds(30)));     // re-anchored to 11:30: throttled again
        Assert.True(gate.TryEnter(backward + Interval));          // a full interval past the new anchor: enters
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
