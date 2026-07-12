using System;
using System.Net;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SsoRateLimiter"/> — the opt-in fixed-window limiter over the anonymous SSO
/// endpoints (#128). The availability contract matters as much as the throttling: unattributable
/// clients, non-public sources (a reverse proxy's loopback/private address would otherwise pool
/// the whole userbase into one bucket), and a full table must all fail OPEN, and IPv6 must key on
/// the /64 so an attacker cannot evade by rotating within one allocation.
/// </summary>
public class SsoRateLimiterTests
{
    private static readonly DateTime Now = new DateTime(2026, 7, 12, 12, 0, 0, DateTimeKind.Utc);
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(60);

    [Fact]
    public void IsAllowed_WithinLimit_Allows_ThenRefusesWithRetryAfter()
    {
        var limiter = new SsoRateLimiter();
        for (var i = 0; i < 3; i++)
        {
            Assert.True(limiter.IsAllowed("1.2.3.4", 3, Window, Now, out _));
        }

        Assert.False(limiter.IsAllowed("1.2.3.4", 3, Window, Now.AddSeconds(10), out var retryAfter));
        // 10s into a 60s window, the client should be told to come back when it expires.
        Assert.Equal(50, retryAfter);
    }

    [Fact]
    public void IsAllowed_AfterWindowExpires_ResetsAndAllows()
    {
        var limiter = new SsoRateLimiter();
        for (var i = 0; i < 4; i++)
        {
            limiter.IsAllowed("1.2.3.4", 3, Window, Now, out _);
        }

        Assert.False(limiter.IsAllowed("1.2.3.4", 3, Window, Now, out _));
        Assert.True(limiter.IsAllowed("1.2.3.4", 3, Window, Now + Window, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void IsAllowed_MaxAttemptsBelowOne_DisablesLimiter_NeverBlocksAll(int maxAttempts)
    {
        // A misconfigured 0/negative limit must fail OPEN (disabled), never mean "block everything".
        var limiter = new SsoRateLimiter();
        for (var i = 0; i < 10; i++)
        {
            Assert.True(limiter.IsAllowed("1.2.3.4", maxAttempts, Window, Now, out _));
        }
    }

    [Fact]
    public void IsAllowed_StaysRefusedAcrossManyHits_WithinWindow_NoReadmit()
    {
        // Once over the limit the count is clamped, so a long burst inside one window keeps being
        // refused rather than ever wrapping back under the threshold.
        var limiter = new SsoRateLimiter();
        Assert.True(limiter.IsAllowed("1.2.3.4", 1, Window, Now, out _));
        for (var i = 0; i < 1000; i++)
        {
            Assert.False(limiter.IsAllowed("1.2.3.4", 1, Window, Now, out _));
        }
    }

    [Fact]
    public void IsAllowed_DistinctKeys_HaveIndependentBudgets()
    {
        var limiter = new SsoRateLimiter();
        Assert.True(limiter.IsAllowed("1.2.3.4", 1, Window, Now, out _));
        Assert.False(limiter.IsAllowed("1.2.3.4", 1, Window, Now, out _));
        Assert.True(limiter.IsAllowed("5.6.7.8", 1, Window, Now, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsAllowed_BlankKey_AlwaysAllows_FailOpen(string? key)
    {
        var limiter = new SsoRateLimiter();
        for (var i = 0; i < 10; i++)
        {
            Assert.True(limiter.IsAllowed(key, 1, Window, Now, out _));
        }
    }

    [Fact]
    public void IsAllowed_AtEntryCap_NewKeysAllowed_FailOpen_AndKnownKeysStillThrottled()
    {
        var limiter = new SsoRateLimiter(maxEntries: 2);
        Assert.True(limiter.IsAllowed("known-a", 1, Window, Now, out _));
        Assert.True(limiter.IsAllowed("known-b", 1, Window, Now, out _));

        // The table is full: a new client is never refused (availability over throttling)...
        for (var i = 0; i < 5; i++)
        {
            Assert.True(limiter.IsAllowed("new-c", 1, Window, Now, out _));
        }

        // ...while an already-tracked abuser stays throttled.
        Assert.False(limiter.IsAllowed("known-a", 1, Window, Now, out _));
    }

    [Fact]
    public void IsAllowed_PruneReclaimsLongQuietEntries_FreeingCapSlots()
    {
        var limiter = new SsoRateLimiter(maxEntries: 2);
        var window = TimeSpan.FromSeconds(10);
        limiter.IsAllowed("a", 1, window, Now, out _);
        limiter.IsAllowed("b", 1, window, Now, out _);

        // Both entries have been quiet for more than two windows when the (once-per-minute) sweep
        // next runs, so "c" gets a real, tracked slot instead of the at-cap fail-open path —
        // proven by it being refused once it exceeds the limit.
        var later = Now.AddMinutes(3);
        Assert.True(limiter.IsAllowed("c", 1, window, later, out _));
        Assert.False(limiter.IsAllowed("c", 1, window, later, out _));
    }

    [Fact]
    public void IsAllowed_PruneKeepsRecentEntries_ActiveAbuserStaysThrottled()
    {
        var limiter = new SsoRateLimiter(maxEntries: 1);
        var window = TimeSpan.FromSeconds(120);
        limiter.IsAllowed("abuser", 1, window, Now, out _);

        // 70s later the sweep interval has passed but the abuser has been quiet for less than two
        // windows, so it must survive the sweep: the table stays full (the newcomer fails open,
        // untracked) and the abuser's still-open window keeps refusing.
        var later = Now.AddSeconds(70);
        Assert.True(limiter.IsAllowed("newcomer", 1, window, later, out _));
        Assert.False(limiter.IsAllowed("abuser", 1, window, later, out _));
    }

    [Fact]
    public void NormalizeClientKey_PublicIpv4_UsesFullAddress()
    {
        Assert.Equal("1.2.3.4", SsoRateLimiter.NormalizeClientKey(IPAddress.Parse("1.2.3.4")));
    }

    [Fact]
    public void NormalizeClientKey_PublicIpv6_KeysOnSlash64_SoRotationWithinAllocationCannotEvade()
    {
        var a = SsoRateLimiter.NormalizeClientKey(IPAddress.Parse("2001:db8:aaaa:bbbb::1"));
        var b = SsoRateLimiter.NormalizeClientKey(IPAddress.Parse("2001:db8:aaaa:bbbb:ffff:ffff:ffff:ffff"));
        var other = SsoRateLimiter.NormalizeClientKey(IPAddress.Parse("2001:db8:aaaa:cccc::1"));

        Assert.Equal("2001:db8:aaaa:bbbb::/64", a);
        Assert.Equal(a, b);
        Assert.NotEqual(a, other);
    }

    [Fact]
    public void NormalizeClientKey_Ipv4MappedIpv6_KeysAsIpv4()
    {
        Assert.Equal("1.2.3.4", SsoRateLimiter.NormalizeClientKey(IPAddress.Parse("::ffff:1.2.3.4")));
    }

    [Fact]
    public void NormalizeClientKey_NullRemote_ReturnsNull_FailOpen()
    {
        Assert.Null(SsoRateLimiter.NormalizeClientKey(null));
    }

    [Theory]
    [InlineData("127.0.0.1")] // loopback — a local reverse proxy's source address
    [InlineData("10.1.2.3")] // RFC1918
    [InlineData("172.16.0.9")] // RFC1918
    [InlineData("192.168.1.50")] // RFC1918
    [InlineData("100.64.0.1")] // CGNAT client-side range
    [InlineData("169.254.10.10")] // IPv4 link-local
    [InlineData("::1")] // IPv6 loopback
    [InlineData("fe80::1")] // IPv6 link-local
    [InlineData("fd00::1")] // IPv6 unique-local
    [InlineData("::ffff:192.168.1.50")] // IPv4-mapped private
    public void NormalizeClientKey_NonPublicSource_ReturnsNull_NeverThrottled(string ip)
    {
        // THE structural mass-lockout defense (#128): when a reverse proxy in front of Jellyfin is
        // the socket peer (loopback/private/CGNAT), every user would share its one bucket — so no
        // bucket is created at all for non-public sources.
        Assert.Null(SsoRateLimiter.NormalizeClientKey(IPAddress.Parse(ip)));
    }
}
