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

        Assert.True(cache.TryConsume("_assertion-1", expiry, Now));
        Assert.False(cache.TryConsume("_assertion-1", expiry, Now));
    }

    [Fact]
    public void TryConsume_DistinctIds_EachSucceedOnce()
    {
        var cache = new SamlReplayCache();
        var expiry = Now.AddMinutes(10);

        Assert.True(cache.TryConsume("_a", expiry, Now));
        Assert.True(cache.TryConsume("_b", expiry, Now));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void TryConsume_MissingId_FailsClosed(string? id)
    {
        var cache = new SamlReplayCache();
        Assert.False(cache.TryConsume(id!, Now.AddMinutes(10), Now));
    }

    [Fact]
    public void TryConsume_AfterEntryExpires_IdCanBeUsedAgain()
    {
        // Once retention has elapsed the entry is evicted; a fresh assertion reusing the id (a new
        // login, not a replay of the same still-valid assertion) is accepted again.
        var cache = new SamlReplayCache();
        Assert.True(cache.TryConsume("_a", Now.AddMinutes(10), Now));

        var later = Now.AddMinutes(20);
        Assert.True(cache.TryConsume("_a", later.AddMinutes(10), later));
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
