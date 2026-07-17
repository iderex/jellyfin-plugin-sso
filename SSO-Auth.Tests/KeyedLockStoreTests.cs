using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="KeyedLockStore"/> — the per-key async mutual-exclusion primitive the avatar store
/// serializes on (#400). The overlap tests are deterministic: a held handle keeps the second acquirer
/// parked by construction, never by timing. The collectible property (a key's holder is dropped once its
/// last acquirer leaves) is what keeps the map from leaking a semaphore per key ever seen.
/// </summary>
public class KeyedLockStoreTests
{
    [Fact]
    public async Task AcquireAsync_SameKey_ParksTheSecondUntilTheFirstReleases()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new KeyedLockStore(StringComparer.Ordinal);

        var first = await store.AcquireAsync("A", ct);
        var second = store.AcquireAsync("A", ct);

        // The permit is held, so the second acquire cannot complete — deterministic, not a timing race.
        Assert.False(second.IsCompleted);

        first.Dispose();

        var secondHandle = await second; // now the permit is free
        secondHandle.Dispose();
        Assert.Equal(0, store.TrackedKeys);
    }

    [Fact]
    public async Task AcquireAsync_DifferentKeys_DoNotBlockEachOther()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new KeyedLockStore(StringComparer.Ordinal);

        using var a = await store.AcquireAsync("A", ct);
        using var b = await store.AcquireAsync("B", ct); // must not wait on A's holder

        Assert.Equal(2, store.TrackedKeys);
    }

    [Fact]
    public async Task Release_DropsTheHolder_SoTheMapStaysBounded()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new KeyedLockStore(StringComparer.Ordinal);

        (await store.AcquireAsync("A", ct)).Dispose();
        (await store.AcquireAsync("A", ct)).Dispose();

        // Each key's holder is collected on its last release, so churning many one-shot keys leaks nothing.
        Assert.Equal(0, store.TrackedKeys);
    }

    [Fact]
    public async Task Dispose_IsIdempotent_ReleasingThePermitExactlyOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new KeyedLockStore(StringComparer.Ordinal);

        var handle = await store.AcquireAsync("A", ct);
        handle.Dispose();
        handle.Dispose(); // a double dispose must not over-release the semaphore

        // If the double dispose had leaked a permit, two acquirers could hold "A" at once. Prove it did
        // not: while one handle is held, a second acquire stays parked.
        using var held = await store.AcquireAsync("A", ct);
        var contender = store.AcquireAsync("A", ct);
        Assert.False(contender.IsCompleted);

        held.Dispose();
        (await contender).Dispose();
        Assert.Equal(0, store.TrackedKeys);
    }

    [Fact]
    public async Task AcquireAsync_CancelledWait_AcquiresNothingAndLeaksNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new KeyedLockStore(StringComparer.Ordinal);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        using (await store.AcquireAsync("A", ct))
        {
            // A wait cancelled while the permit is held must throw and drop its reference, not leave a
            // dangling waiter that pins the holder forever.
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.AcquireAsync("A", cancelled.Token));
            Assert.Equal(1, store.TrackedKeys); // only the live holder remains
        }

        Assert.Equal(0, store.TrackedKeys); // holder collected once released
    }

    [Fact]
    public async Task AcquireAsync_UnderContentionOnOneKey_NeverAdmitsTwoAtOnce()
    {
        // The crux, mirroring PerClientBudgetLimiter's contention test: many tasks race the same key; the
        // per-key semaphore admits exactly one at a time, so the observed occupancy never exceeds one.
        var store = new KeyedLockStore(StringComparer.Ordinal);
        var active = 0;
        var maxActive = 0;
        var sync = new object();

        var tasks = new Task[16];
        for (var t = 0; t < tasks.Length; t++)
        {
            tasks[t] = Task.Run(
                async () =>
                {
                    for (var i = 0; i < 50; i++)
                    {
                        using (await store.AcquireAsync("A", TestContext.Current.CancellationToken))
                        {
                            var n = Interlocked.Increment(ref active);
                            lock (sync)
                            {
                                maxActive = Math.Max(maxActive, n);
                            }

                            Interlocked.Decrement(ref active);
                        }
                    }
                },
                TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        Assert.Equal(1, maxActive); // never two holders of one key at once
        Assert.Equal(0, store.TrackedKeys); // fully collected once uncontended
    }
}
