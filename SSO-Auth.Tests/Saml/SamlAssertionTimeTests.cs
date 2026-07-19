using System;
using System.Globalization;
using Jellyfin.Plugin.SSO_Auth;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlAssertionTime"/> — the fail-closed time-window check. The upper
/// bound (NotOnOrAfter) is required and absent/unparseable bounds are rejections, closing the
/// F-2 fail-open (a missing time bound previously meant "valid forever").
/// </summary>
public class SamlAssertionTimeTests
{
    private static readonly DateTime Now = new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc);
    // Use the production skew so the tests exercise the real acceptance window.
    private static readonly TimeSpan Skew = SamlAssertionTime.ClockSkew;

    private static string At(int minutesFromNow) =>
        Now.AddMinutes(minutesFromNow).ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

    private static bool Valid(string? subjectNotOnOrAfter, string? condNotBefore, string? condNotOnOrAfter) =>
        SamlAssertionTime.IsWithinValidity(subjectNotOnOrAfter, condNotBefore, condNotOnOrAfter, Now, Skew);

    [Fact]
    public void NoUpperBoundAtAll_IsRejected()
    {
        Assert.False(Valid(null, null, null));
    }

    [Fact]
    public void SubjectUpperBoundInFuture_IsAccepted()
    {
        Assert.True(Valid(At(5), null, null));
    }

    [Fact]
    public void SubjectUpperBoundInPastBeyondSkew_IsRejected()
    {
        Assert.False(Valid(At(-10), null, null));
    }

    [Fact]
    public void SubjectUpperBoundJustPastButWithinSkew_IsAccepted()
    {
        // Expired by two minutes, tolerated by the five-minute skew.
        Assert.True(Valid(At(-2), null, null));
    }

    [Fact]
    public void UnparseableUpperBound_IsRejected()
    {
        Assert.False(Valid("not-a-date", null, null));
    }

    [Fact]
    public void ConditionsUpperBoundOnly_IsEnforced()
    {
        Assert.True(Valid(null, null, At(5)));
        Assert.False(Valid(null, null, At(-10)));
    }

    [Fact]
    public void ConditionsNotBeforeInFutureBeyondSkew_IsRejected()
    {
        Assert.False(Valid(At(5), At(30), null));
    }

    [Fact]
    public void ConditionsNotBeforeJustAheadWithinSkew_IsAccepted()
    {
        Assert.True(Valid(At(5), At(1), null));
    }

    [Fact]
    public void PresentButUnparseableNotBefore_IsRejected()
    {
        Assert.False(Valid(At(5), "garbage", null));
    }

    [Fact]
    public void BothBoundsPresentAndNowInside_IsAccepted()
    {
        Assert.True(Valid(At(5), At(-5), At(5)));
    }

    // --- xsd:dateTime-faithful parsing (#677): XmlConvert replaces DateTime.TryParse ---

    [Fact]
    public void TryParseUtc_BasicXsdDateTime_ParsesToCorrectUtcInstant()
    {
        Assert.True(SamlAssertionTime.TryParseUtc("2026-07-11T12:00:00Z", out var parsed));
        Assert.Equal(new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc), parsed);
        Assert.Equal(DateTimeKind.Utc, parsed.Kind);
    }

    [Fact]
    public void TryParseUtc_OffsetForm_IsNormalizedToUtc()
    {
        // An explicit +02:00 offset must be converted to UTC (14:30+02:00 == 12:30Z), not read as local.
        Assert.True(SamlAssertionTime.TryParseUtc("2026-07-11T14:30:00+02:00", out var parsed));
        Assert.Equal(new DateTime(2026, 7, 11, 12, 30, 0, DateTimeKind.Utc), parsed);
        Assert.Equal(DateTimeKind.Utc, parsed.Kind);
    }

    [Fact]
    public void TryParseUtc_MoreThanSevenFractionalDigits_IsAccepted()
    {
        // xsd:dateTime permits unbounded fractional-second digits; some IdPs emit high precision. The old
        // DateTime.TryParse path caps at 7 digits and rejected these, wrongly failing a valid assertion —
        // XmlConvert tolerates them (truncating to tick precision). This is the #677 regression, now fixed.
        Assert.True(SamlAssertionTime.TryParseUtc("2026-07-11T12:00:00.123456789012345Z", out var parsed));
        Assert.Equal(DateTimeKind.Utc, parsed.Kind);
        // Truncated to the same second; the sub-second tail is below the assertion window's resolution.
        Assert.Equal(new DateTime(2026, 7, 11, 12, 0, 0, DateTimeKind.Utc), new DateTime(parsed.Year, parsed.Month, parsed.Day, parsed.Hour, parsed.Minute, parsed.Second, DateTimeKind.Utc));
    }

    [Fact]
    public void TryParseUtc_HighPrecisionUpperBound_IsAcceptedEndToEnd()
    {
        // The same high-precision value flows through the window check as a valid future upper bound.
        var highPrecision = Now.AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture) + ".123456789012345Z";
        Assert.True(Valid(highPrecision, null, null));
    }

    [Theory]
    [InlineData("not-a-date")]
    [InlineData("")]
    [InlineData("2026-13-99T99:99:99Z")]
    [InlineData("2026-07-11 12:00:00")]
    public void TryParseUtc_MalformedValue_ReturnsFalseFailClosed(string raw)
    {
        Assert.False(SamlAssertionTime.TryParseUtc(raw, out _));
    }

    [Fact]
    public void TryParseUtc_Null_ReturnsFalse()
    {
        Assert.False(SamlAssertionTime.TryParseUtc(null, out _));
    }
}
