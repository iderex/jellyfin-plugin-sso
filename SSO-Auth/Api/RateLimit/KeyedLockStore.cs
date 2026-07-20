#nullable enable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Jellyfin.Plugin.SSO_Auth.Api.RateLimit;

/// <summary>
/// A per-key async mutual-exclusion primitive: at most one holder per key at a time, while unrelated
/// keys never block each other. Each key's semaphore is reference-counted and dropped the moment its
/// last holder leaves, so the map stays bounded by the keys contending RIGHT NOW — not by the number of
/// distinct keys ever seen. That is what keeps a churn of one-shot keys (e.g. a login flood over many
/// usernames) from leaking one <see cref="SemaphoreSlim"/> per key without bound. Acquire returns a
/// disposable whose disposal releases the key; the lock is not reentrant.
/// </summary>
internal sealed class KeyedLockStore
{
    // key -> its live holder; a key is present only while at least one acquirer references it (dropped
    // at zero, under the holder's own lock), so |_holders| <= keys contended now. The comparer decides
    // key identity: the avatar store passes Ordinal so the key is exactly the profile-path determinant.
    private readonly ConcurrentDictionary<string, Holder> _holders;

    internal KeyedLockStore(IEqualityComparer<string> comparer)
    {
        _holders = new ConcurrentDictionary<string, Holder>(comparer ?? throw new ArgumentNullException(nameof(comparer)));
    }

    /// <summary>Gets the number of keys currently contended (live holders). Test-only: proves the map stays bounded.</summary>
    internal int TrackedKeys => _holders.Count;

    /// <summary>
    /// Acquires exclusive access for <paramref name="key"/>, waiting until any current holder releases.
    /// Dispose the returned handle to release it; unrelated keys are never blocked.
    /// </summary>
    /// <param name="key">The key to serialize on.</param>
    /// <param name="cancellationToken">Cancels the wait; a cancelled wait acquires nothing and leaks nothing.</param>
    /// <returns>A handle whose disposal releases the key.</returns>
    internal async Task<IDisposable> AcquireAsync(string key, CancellationToken cancellationToken = default)
    {
        var holder = Claim(key);
        try
        {
            await holder.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // The wait was cancelled before it took the permit (SemaphoreSlim.WaitAsync is atomic: it
            // either returns having taken a permit or throws having taken none), so drop only the
            // reference — releasing the gate here would hand out a permit we never held.
            Unclaim(key, holder);
            throw;
        }

        return new Releaser(this, key, holder);
    }

    // Attaches this acquirer to the key's live holder, creating one if none exists. Retries when it
    // races a Release that is retiring the holder it just observed, so it can never attach to a holder
    // already removed from the map (which would give two acquirers of one key two different semaphores).
    private Holder Claim(string key)
    {
        while (true)
        {
            var holder = _holders.GetOrAdd(key, _ => new Holder());
            lock (holder)
            {
                if (!holder.Retired)
                {
                    holder.Waiters++;
                    return holder;
                }
            }
        }
    }

    // Detaches one acquirer from the key's holder and, when it was the last, retires and removes the
    // holder so the map does not accumulate idle semaphores. Retire + remove happen under the holder's
    // lock, atomically against Claim's Retired check, so no acquirer keeps a reference to a removed
    // holder. The conditional TryRemove only deletes while the key still maps to this exact holder.
    private void Unclaim(string key, Holder holder)
    {
        lock (holder)
        {
            if (--holder.Waiters == 0)
            {
                holder.Retired = true;
                _holders.TryRemove(new KeyValuePair<string, Holder>(key, holder));
            }
        }
    }

    // One key's mutual-exclusion state: the semaphore plus the reference count and retirement flag that
    // govern its collectible lifetime. Accessed only under its own monitor lock (brief, per-key — no
    // global contention), the same per-key lock idiom SsoRateLimiter.Counter uses.
    private sealed class Holder
    {
        // Never Dispose()d: SemaphoreSlim allocates an OS wait handle only if AvailableWaitHandle is
        // accessed (it never is here), so a retired/GC'd holder is pure managed garbage — the same
        // reason SsoRateLimiter.Counter needs no disposal.
        internal SemaphoreSlim Gate { get; } = new SemaphoreSlim(1, 1);

        internal int Waiters { get; set; }

        internal bool Retired { get; set; }
    }

    // The acquired-lock handle. Disposal releases the semaphore and detaches the acquirer; idempotent,
    // so a double dispose (or a using plus an explicit Dispose) releases exactly once — a second release
    // would let two holders into one key's critical section.
    private sealed class Releaser : IDisposable
    {
        private readonly KeyedLockStore _owner;
        private readonly string _key;
        private readonly Holder _holder;
        private int _disposed;

        internal Releaser(KeyedLockStore owner, string key, Holder holder)
        {
            _owner = owner;
            _key = key;
            _holder = holder;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _holder.Gate.Release();
            _owner.Unclaim(_key, _holder);
        }
    }
}
