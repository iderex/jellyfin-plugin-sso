using System;
using System.Threading;

namespace Jellyfin.Plugin.SSO_Auth.Api.RateLimit;

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
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(interval.Ticks);
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

        // Suppress a sub-interval span in EITHER direction: |now - last| < interval. A forward span shorter
        // than the interval is the normal throttle. A backward span shorter than the interval is a stale
        // sample — a thread descheduled between reading the clock and entering, landing just behind the
        // cursor — and must NOT re-admit (#334): leaving the cursor untouched keeps the next admission at
        // last + interval, so a stale blip opens no second admission yet can never stall the gate either
        // (the wait is capped at one interval from the real entry). A backward span of at least the interval
        // is a genuine wall-clock correction (DST fall-back, NTP step): it fails the guard, so it enters and
        // re-anchors below, preserving the #246 self-heal that stops a correction from stranding a capped store.
        if (Math.Abs(nowTicks - last) < _intervalTicks)
        {
            return false;
        }

        // Exactly one CAS winner enters per interval; a loser reads false and is throttled, matching the
        // CAS-lose = skip behavior of every call site the gate replaces.
        return Interlocked.CompareExchange(ref _cursor, nowTicks, last) == last;
    }
}
