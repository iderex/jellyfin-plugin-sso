using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="PerClientBudgetLimiter"/> — the per-client occupancy sub-cap the in-flight state
/// stores use so one source cannot fill the global budget (#327). Reserve is a single CAS, so a per-key
/// count can never race past the cap; release is idempotent and drops the empty bucket; a null key is
/// always exempt.
/// </summary>
public class PerClientBudgetLimiterTests
{
    [Fact]
    public void Reserve_UpToCap_Succeeds_ThenRefuses()
    {
        var limiter = new PerClientBudgetLimiter(3);
        Assert.True(limiter.TryReserve("A"));
        Assert.True(limiter.TryReserve("A"));
        Assert.True(limiter.TryReserve("A"));
        Assert.False(limiter.TryReserve("A")); // at cap
    }

    [Fact]
    public void FromGlobalCap_DerivesTheHundredthShare_WithAFloorOfOne()
    {
        Assert.Equal(1000, PerClientBudgetLimiter.FromGlobalCap(100_000).PerKeyCap);
        Assert.Equal(1, PerClientBudgetLimiter.FromGlobalCap(50).PerKeyCap); // Max(1, 50/100)
    }

    [Fact]
    public void Release_ReadmitsAfterCap()
    {
        var limiter = new PerClientBudgetLimiter(2);
        limiter.TryReserve("A");
        limiter.TryReserve("A");
        Assert.False(limiter.TryReserve("A"));

        limiter.Release("A");
        Assert.True(limiter.TryReserve("A"));
    }

    [Fact]
    public void Release_ToZero_DropsTheBucket()
    {
        var limiter = new PerClientBudgetLimiter(3);
        limiter.TryReserve("A");
        limiter.TryReserve("A");
        Assert.Equal(1, limiter.TrackedKeys);

        limiter.Release("A");
        limiter.Release("A");
        Assert.Equal(0, limiter.TrackedKeys); // empty bucket removed, map stays bounded
    }

    [Fact]
    public void NullKey_AlwaysReserves_AndIsNeverTracked()
    {
        var limiter = new PerClientBudgetLimiter(1);
        for (var i = 0; i < 100; i++)
        {
            Assert.True(limiter.TryReserve(null)); // exempt, never at cap
        }

        Assert.Equal(0, limiter.TrackedKeys);
        limiter.Release(null); // no throw, no-op
    }

    [Fact]
    public void Release_OfUnknownKey_IsANoOp_NeverNegative()
    {
        var limiter = new PerClientBudgetLimiter(2);
        limiter.Release("never-reserved"); // no throw
        Assert.Equal(0, limiter.TrackedKeys);

        // A stray extra release must not push the count negative and let the bucket over-admit.
        limiter.TryReserve("A");
        limiter.Release("A");
        limiter.Release("A"); // over-release
        Assert.True(limiter.TryReserve("A"));
        Assert.True(limiter.TryReserve("A")); // still exactly cap-2 headroom, not more
        Assert.False(limiter.TryReserve("A"));
    }

    [Fact]
    public async Task Reserve_UnderContentionOnOneKey_GrantsExactlyTheCap()
    {
        // The crux: N threads hammer TryReserve on the same key; the CAS makes the cap-check+increment
        // one atom, so EXACTLY cap reservations succeed — zero overshoot.
        const int Cap = 50;
        var limiter = new PerClientBudgetLimiter(Cap);
        var granted = 0;

        var tasks = new Task[16];
        for (var t = 0; t < tasks.Length; t++)
        {
            tasks[t] = Task.Run(() =>
            {
                for (var i = 0; i < 100; i++)
                {
                    if (limiter.TryReserve("A"))
                    {
                        Interlocked.Increment(ref granted);
                    }
                }
            },
            TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);
        Assert.Equal(Cap, granted); // never more than the cap, even under 16-way contention
    }

    [Fact]
    public async Task ReserveRelease_Interleaved_StaysWithinBounds()
    {
        var limiter = new PerClientBudgetLimiter(4);
        var exception = await Record.ExceptionAsync(async () =>
        {
            var tasks = new Task[8];
            for (var t = 0; t < tasks.Length; t++)
            {
                tasks[t] = Task.Run(() =>
                {
                    for (var i = 0; i < 500; i++)
                    {
                        if (limiter.TryReserve("A"))
                        {
                            limiter.Release("A");
                        }
                    }
                },
                TestContext.Current.CancellationToken);
            }

            await Task.WhenAll(tasks);
        });

        Assert.Null(exception);
        Assert.True(limiter.TrackedKeys <= 1); // 0 or 1, never corrupt
    }
}
