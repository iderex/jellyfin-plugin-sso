// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlRequestCache"/> — the outstanding-AuthnRequest tracking that lets the
/// callback accept only solicited responses (#156), carries the browser-binding id minted at the
/// challenge (#415), and bounds per-client occupancy so one source cannot fill the cache (#327): a
/// response's InResponseTo must match a request this server issued, each request answers at most once,
/// an unknown/expired/blank id fails closed, a successful consume yields the binding id recorded with
/// the request, and one client key may hold at most its per-key share.
/// </summary>
public class SamlRequestCacheTests
{
    private static readonly DateTime Now = new DateTime(2026, 7, 12, 12, 0, 0, DateTimeKind.Utc);

    // A cache whose per-key sub-cap is small and reachable (global 200 -> per-key 2).
    private static SamlRequestCache SmallCache() => new SamlRequestCache(200, TimeSpan.FromMinutes(1));

    [Fact]
    public void Register_ThenConsume_SucceedsOnce_ThenReplayFails()
    {
        var cache = new SamlRequestCache();
        cache.Register("_req-1", "binding-1", Now.AddMinutes(15), Now, clientKey: null, out _);

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
    public void Register_BlankId_ReturnsFalse_AndConsumeFails(string? id)
    {
        var cache = new SamlRequestCache();
        // A blank id is never registered and can never be consumed (an unsolicited response with no
        // InResponseTo maps to a blank key).
        Assert.False(cache.Register(id!, "binding", Now.AddMinutes(15), Now, clientKey: null, out _));
        Assert.False(cache.TryConsume(id!, Now, out _));
    }

    [Fact]
    public void Consume_AfterExpiry_FailsClosed()
    {
        var cache = new SamlRequestCache();
        cache.Register("_req-1", "binding-1", Now.AddMinutes(15), Now, clientKey: null, out _);

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
        cache.Register("_req-1", null!, Now.AddMinutes(15), Now, clientKey: null, out _);

        Assert.True(cache.TryConsume("_req-1", Now, out var bindingId));
        Assert.Equal(string.Empty, bindingId);
    }

    [Fact]
    public void DistinctRequests_EachConsumeOnce_WithTheirOwnBinding()
    {
        var cache = new SamlRequestCache();
        cache.Register("_a", "binding-a", Now.AddMinutes(15), Now, clientKey: null, out _);
        cache.Register("_b", "binding-b", Now.AddMinutes(15), Now, clientKey: null, out _);

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
        cache.Register("_old", "binding-old", Now.AddMinutes(1), Now, clientKey: null, out _);

        // A later registration prunes the expired entry; the old id is gone (would fail consume).
        // (TryConsume also rejects it on expiry, so this additionally relies on it not being present.)
        cache.Register("_new", "binding-new", Now.AddMinutes(35), Now.AddMinutes(20), clientKey: null, out _);
        Assert.False(cache.TryConsume("_old", Now.AddMinutes(20), out _));
        Assert.True(cache.TryConsume("_new", Now.AddMinutes(20), out _));
    }

    [Fact]
    public void OverflowCap_DoesNotThrow_AndPreservesInFlightEntry()
    {
        // The cap is the reason the eviction code exists; it was the untested path that threw an
        // ArgumentException under concurrent LINQ eviction. Register an early "in-flight" id, then
        // flood well past the cap with exempt (null) keys: registration must never throw, and the
        // pre-existing in-flight id must NOT be evicted (a flood cannot displace a user mid-login).
        var cache = new SamlRequestCache();
        var expiry = Now.AddMinutes(15);
        cache.Register("_inflight", "binding-inflight", expiry, Now, clientKey: null, out _);

        var exception = Record.Exception(() =>
        {
            for (var i = 0; i < 100_050; i++)
            {
                cache.Register("_flood-" + i.ToString(CultureInfo.InvariantCulture), "b", expiry, Now, clientKey: null, out _);
            }
        });

        Assert.Null(exception);
        Assert.True(cache.TryConsume("_inflight", Now, out _));
    }

    // --- Per-client sub-cap (#327) ---

    [Fact]
    public void Register_FloodFromOneKey_DoesNotRefuseADifferentKey()
    {
        // The core fairness property: filling client "A" to its per-key share must not deny a login
        // from client "B".
        var cache = SmallCache(); // per-key cap 2
        var expiry = Now.AddMinutes(15);
        Assert.True(cache.Register("_a1", "b", expiry, Now, clientKey: "A", out _));
        Assert.True(cache.Register("_a2", "b", expiry, Now, clientKey: "A", out _));
        Assert.False(cache.Register("_a3", "b", expiry, Now, clientKey: "A", out var warn)); // A at its share
        Assert.True(warn); // the throttled capacity warning fires for the first refusal in the interval

        Assert.True(cache.Register("_b1", "b", expiry, Now, clientKey: "B", out _)); // B is unaffected
    }

    [Fact]
    public void Register_ReleaseOnConsume_ReadmitsTheSameKey()
    {
        var cache = SmallCache(); // per-key cap 2
        var expiry = Now.AddMinutes(15);
        cache.Register("_a1", "b", expiry, Now, clientKey: "A", out _);
        cache.Register("_a2", "b", expiry, Now, clientKey: "A", out _);
        Assert.False(cache.Register("_a3", "b", expiry, Now, clientKey: "A", out _)); // full

        Assert.True(cache.TryConsume("_a1", Now, out _)); // frees one A slot
        Assert.True(cache.Register("_a3", "b", expiry, Now, clientKey: "A", out _));
    }

    [Fact]
    public void Register_ReleaseOnExpiry_ReadmitsTheSameKey()
    {
        var cache = SmallCache(); // per-key cap 2
        cache.Register("_a1", "b", Now.AddMinutes(1), Now, clientKey: "A", out _);
        cache.Register("_a2", "b", Now.AddMinutes(1), Now, clientKey: "A", out _);

        // Advance past expiry and past the prune interval; the next Register prunes both expired A
        // entries (releasing their slots), so A can register again.
        var later = Now.AddMinutes(5);
        Assert.True(cache.Register("_a3", "b", later.AddMinutes(15), later, clientKey: "A", out _));
    }

    [Fact]
    public void Register_ReleaseOnFailedGlobalInsert_DoesNotLeakTheClientSlot()
    {
        // Global cap 2 -> per-key cap 1. Fill the store to the global cap with exempt (null) entries,
        // then a Register for "A" reserves A's slot but is refused by the GLOBAL cap and must roll the
        // reservation back. After freeing a global slot, "A" must still be admittable — if the rollback
        // had leaked, A would already sit at its cap of 1 and this would be refused.
        var cache = new SamlRequestCache(2, TimeSpan.FromMinutes(1));
        var expiry = Now.AddMinutes(15);
        Assert.True(cache.Register("_n1", "b", expiry, Now, clientKey: null, out _));
        Assert.True(cache.Register("_n2", "b", expiry, Now, clientKey: null, out _));

        Assert.False(cache.Register("_a1", "b", expiry, Now, clientKey: "A", out _)); // refused by the global cap
        Assert.True(cache.TryConsume("_n1", Now, out _)); // free one global slot
        Assert.True(cache.Register("_a1", "b", expiry, Now, clientKey: "A", out _)); // no leak -> A admits
    }

    [Fact]
    public void Register_NullKeyIsExempt_BoundedOnlyByTheGlobalCap()
    {
        // Global cap 2 -> per-key cap 1. A null (unattributable/proxy) key is never sub-capped: several
        // null registrations succeed up to the GLOBAL cap, then the next is refused by the global cap.
        var cache = new SamlRequestCache(2, TimeSpan.FromMinutes(1));
        var expiry = Now.AddMinutes(15);
        Assert.True(cache.Register("_n1", "b", expiry, Now, clientKey: null, out _));
        Assert.True(cache.Register("_n2", "b", expiry, Now, clientKey: null, out _)); // past a per-key cap of 1
        Assert.False(cache.Register("_n3", "b", expiry, Now, clientKey: null, out _)); // global cap
    }

    [Fact]
    public void Register_DuplicateId_IsRefused_AndLeavesTheCountLeakFree()
    {
        // The switch to TryAdd refuses a duplicate id; the refused re-register must roll its reservation
        // back so the count returns to exactly one entry, consumable once.
        var cache = SmallCache(); // per-key cap 2
        var expiry = Now.AddMinutes(15);
        Assert.True(cache.Register("_a1", "b", expiry, Now, clientKey: "A", out _));
        Assert.False(cache.Register("_a1", "b", expiry, Now, clientKey: "A", out _)); // duplicate id refused

        Assert.True(cache.TryConsume("_a1", Now, out _)); // the single entry consumes once
        Assert.True(cache.Register("_a1", "b", expiry, Now, clientKey: "A", out _)); // count was 0 -> re-admits
    }
}
