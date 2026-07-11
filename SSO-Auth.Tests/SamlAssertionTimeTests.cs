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
    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(3);

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
}
