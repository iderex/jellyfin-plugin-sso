using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlRequestCache"/> — the outstanding-AuthnRequest tracking that lets the
/// callback accept only solicited responses (#156): a response's InResponseTo must match a request
/// this server issued, each request answers at most once, and an unknown/expired/blank id fails closed.
/// </summary>
public class SamlRequestCacheTests
{
    private static readonly DateTime Now = new DateTime(2026, 7, 12, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Register_ThenConsume_SucceedsOnce_ThenReplayFails()
    {
        var cache = new SamlRequestCache();
        cache.Register("_req-1", Now.AddMinutes(15), Now);

        Assert.True(cache.TryConsume("_req-1", Now));
        Assert.False(cache.TryConsume("_req-1", Now));
    }

    [Fact]
    public void Consume_UnregisteredId_FailsClosed_Unsolicited()
    {
        var cache = new SamlRequestCache();
        Assert.False(cache.TryConsume("_never-issued", Now));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Consume_BlankId_FailsClosed(string? id)
    {
        var cache = new SamlRequestCache();
        // A blank id is never registered and can never be consumed (an unsolicited response with no
        // InResponseTo maps to a blank key).
        cache.Register(id!, Now.AddMinutes(15), Now);
        Assert.False(cache.TryConsume(id!, Now));
    }

    [Fact]
    public void Consume_AfterExpiry_FailsClosed()
    {
        var cache = new SamlRequestCache();
        cache.Register("_req-1", Now.AddMinutes(15), Now);

        // The request was never answered within its lifetime; a late response is refused.
        Assert.False(cache.TryConsume("_req-1", Now.AddMinutes(20)));
    }

    [Fact]
    public void DistinctRequests_EachConsumeOnce()
    {
        var cache = new SamlRequestCache();
        cache.Register("_a", Now.AddMinutes(15), Now);
        cache.Register("_b", Now.AddMinutes(15), Now);

        Assert.True(cache.TryConsume("_a", Now));
        Assert.True(cache.TryConsume("_b", Now));
        Assert.False(cache.TryConsume("_a", Now));
    }

    [Fact]
    public void Register_ExpiredEntriesArePrunedOnLaterOperation()
    {
        var cache = new SamlRequestCache();
        cache.Register("_old", Now.AddMinutes(1), Now);

        // A later registration prunes the expired entry; the old id is gone (would fail consume).
        // (TryConsume also rejects it on expiry, so this additionally relies on it not being present.)
        cache.Register("_new", Now.AddMinutes(35), Now.AddMinutes(20));
        Assert.False(cache.TryConsume("_old", Now.AddMinutes(20)));
        Assert.True(cache.TryConsume("_new", Now.AddMinutes(20)));
    }

    [Fact]
    public void OverflowCap_DoesNotThrow_AndPreservesInFlightEntry()
    {
        // The cap is the reason the eviction code exists; it was the untested path that threw an
        // ArgumentException under concurrent LINQ eviction. Register an early "in-flight" id, then
        // flood well past the cap: registration must never throw, and the pre-existing in-flight id
        // must NOT be evicted (a flood of fresh challenges cannot displace a user mid-login).
        var cache = new SamlRequestCache();
        var expiry = Now.AddMinutes(15);
        cache.Register("_inflight", expiry, Now);

        var exception = Record.Exception(() =>
        {
            for (var i = 0; i < 100_050; i++)
            {
                cache.Register("_flood-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture), expiry, Now);
            }
        });

        Assert.Null(exception);
        Assert.True(cache.TryConsume("_inflight", Now));
    }
}
