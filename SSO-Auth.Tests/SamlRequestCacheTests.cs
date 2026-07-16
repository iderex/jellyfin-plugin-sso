using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlRequestCache"/> — the outstanding-AuthnRequest tracking that lets the
/// callback accept only solicited responses (#156) and carries the browser-binding id minted at the
/// challenge (#415): a response's InResponseTo must match a request this server issued, each request
/// answers at most once, an unknown/expired/blank id fails closed, and a successful consume yields the
/// binding id recorded with the request.
/// </summary>
public class SamlRequestCacheTests
{
    private static readonly DateTime Now = new DateTime(2026, 7, 12, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Register_ThenConsume_SucceedsOnce_ThenReplayFails()
    {
        var cache = new SamlRequestCache();
        cache.Register("_req-1", "binding-1", Now.AddMinutes(15), Now);

        Assert.True(cache.TryConsume("_req-1", Now, out var bindingId));
        Assert.Equal("binding-1", bindingId); // the binding id round-trips to the consumer
        Assert.False(cache.TryConsume("_req-1", Now, out _));
    }

    [Fact]
    public void Consume_UnregisteredId_FailsClosed_Unsolicited()
    {
        var cache = new SamlRequestCache();
        Assert.False(cache.TryConsume("_never-issued", Now, out var bindingId));
        Assert.Equal(string.Empty, bindingId); // no binding surfaces for an unsolicited response
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Consume_BlankId_FailsClosed(string? id)
    {
        var cache = new SamlRequestCache();
        // A blank id is never registered and can never be consumed (an unsolicited response with no
        // InResponseTo maps to a blank key).
        cache.Register(id!, "binding", Now.AddMinutes(15), Now);
        Assert.False(cache.TryConsume(id!, Now, out _));
    }

    [Fact]
    public void Consume_AfterExpiry_FailsClosed()
    {
        var cache = new SamlRequestCache();
        cache.Register("_req-1", "binding-1", Now.AddMinutes(15), Now);

        // The request was never answered within its lifetime; a late response is refused.
        Assert.False(cache.TryConsume("_req-1", Now.AddMinutes(20), out _));
    }

    [Fact]
    public void Consume_EntryWithoutBindingId_SucceedsWithEmptyBinding()
    {
        // A pre-#415 in-flight entry (or any registration with no binding id) still consumes as
        // solicited but yields an empty binding, which the caller treats as unbound rather than a
        // mismatch — so an upgrade does not break a login already in flight.
        var cache = new SamlRequestCache();
        cache.Register("_req-1", null!, Now.AddMinutes(15), Now);

        Assert.True(cache.TryConsume("_req-1", Now, out var bindingId));
        Assert.Equal(string.Empty, bindingId);
    }

    [Fact]
    public void DistinctRequests_EachConsumeOnce_WithTheirOwnBinding()
    {
        var cache = new SamlRequestCache();
        cache.Register("_a", "binding-a", Now.AddMinutes(15), Now);
        cache.Register("_b", "binding-b", Now.AddMinutes(15), Now);

        Assert.True(cache.TryConsume("_a", Now, out var a));
        Assert.Equal("binding-a", a);
        Assert.True(cache.TryConsume("_b", Now, out var b));
        Assert.Equal("binding-b", b); // each request keeps its own binding, not the other's
        Assert.False(cache.TryConsume("_a", Now, out _));
    }

    [Fact]
    public void Register_ExpiredEntriesArePrunedOnLaterOperation()
    {
        var cache = new SamlRequestCache();
        cache.Register("_old", "binding-old", Now.AddMinutes(1), Now);

        // A later registration prunes the expired entry; the old id is gone (would fail consume).
        // (TryConsume also rejects it on expiry, so this additionally relies on it not being present.)
        cache.Register("_new", "binding-new", Now.AddMinutes(35), Now.AddMinutes(20));
        Assert.False(cache.TryConsume("_old", Now.AddMinutes(20), out _));
        Assert.True(cache.TryConsume("_new", Now.AddMinutes(20), out _));
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
        cache.Register("_inflight", "binding-inflight", expiry, Now);

        var exception = Record.Exception(() =>
        {
            for (var i = 0; i < 100_050; i++)
            {
                cache.Register("_flood-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture), "b", expiry, Now);
            }
        });

        Assert.Null(exception);
        Assert.True(cache.TryConsume("_inflight", Now, out _));
    }
}
