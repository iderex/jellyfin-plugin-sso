using System;
using System.Threading;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// A once-per-interval throttle cursor shared by the anonymous-path sweeps and log signals that must
/// not amplify a flood into CPU or log volume (#246, #195). <see cref="TryEnter"/> returns true for at
/// most one caller per interval — chosen by an atomic compare-and-swap — and false for every other
/// caller in that interval; it decides only <em>whether</em>, so the throttled action (sweep, log line,
/// tally drain) stays at the call site. The caller owns the clock: pass one consistent source per gate
/// (all-UTC or all-local), since the gate compares only ticks.
/// </summary>
internal sealed class IntervalGate
{
    private readonly long _intervalTicks;

    // Atomic cursor holding the last entry time as ticks, read/written via Interlocked (a long is not
    // torn-read-safe). Starts at MinValue so the first call always sees a full interval and enters.
    private long _cursor = DateTime.MinValue.Ticks;

    internal IntervalGate(TimeSpan interval)
    {
        // A non-positive interval would silently disable the throttle (every call enters), turning the
        // gate into the flood amplifier it exists to prevent — e.g. via a field-ordering mistake that
        // passes default(TimeSpan). Fail loudly at construction instead.
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(interval.Ticks, nameof(interval));
        _intervalTicks = interval.Ticks;
    }

    /// <summary>
    /// Reports whether the caller may run the throttled action now, entering the interval if so.
    /// </summary>
    /// <param name="now">The current time, from a source consistent with prior calls on this gate.</param>
    /// <returns>True for the single CAS winner per interval; false when throttled.</returns>
    internal bool TryEnter(DateTime now)
    {
        var nowTicks = now.Ticks;
        var last = Interlocked.Read(ref _cursor);

        // Suppress only when a non-negative, sub-interval span has elapsed. A backward wall-clock step
        // (nowTicks < last) fails the first term, so it does NOT suppress — it enters and re-anchors the
        // cursor below, so a clock correction can never stall the gate and leave a capped store refusing.
        if (nowTicks >= last && nowTicks - last < _intervalTicks)
        {
            return false;
        }

        // Exactly one CAS winner enters per interval; a loser reads false and is throttled, matching the
        // CAS-lose = skip behavior of every call site the gate replaces.
        return Interlocked.CompareExchange(ref _cursor, nowTicks, last) == last;
    }
}
