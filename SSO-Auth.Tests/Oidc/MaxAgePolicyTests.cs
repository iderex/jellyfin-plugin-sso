// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="MaxAgePolicy"/> — the fail-closed <c>max_age</c> freshness check (#961). A missing
/// <c>auth_time</c> (a provider that ignored the requested <c>max_age</c>) and an <c>auth_time</c> older than
/// the window both fail; a fresh one within the window (plus the shared clock skew) passes; a future
/// <c>auth_time</c> beyond the skew is rejected so a clock-forward IdP cannot satisfy the window forever.
/// </summary>
public class MaxAgePolicyTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_000_000);

    private static long UnixSecondsAgo(int seconds) => Now.ToUnixTimeSeconds() - seconds;

    [Fact]
    public void MissingAuthTime_IsNotFresh_FailClosed()
    {
        // The provider ignored max_age and returned no auth_time — must NOT pass.
        Assert.False(MaxAgePolicy.IsFresh(null, maxAgeSeconds: 300, Now));
    }

    [Fact]
    public void AuthTimeWithinTheWindow_IsFresh()
    {
        Assert.True(MaxAgePolicy.IsFresh(UnixSecondsAgo(120), maxAgeSeconds: 300, Now));
    }

    [Fact]
    public void AuthTimeOlderThanTheWindowPlusSkew_IsNotFresh()
    {
        // 300s window + 5min skew = 600s tolerance; 601s ago is stale.
        Assert.False(MaxAgePolicy.IsFresh(UnixSecondsAgo(601), maxAgeSeconds: 300, Now));
    }

    [Fact]
    public void AuthTimeAtTheWindowEdgeWithinSkew_IsFresh()
    {
        // Exactly at window+skew is still accepted (the tolerance is inclusive).
        Assert.True(MaxAgePolicy.IsFresh(UnixSecondsAgo(600), maxAgeSeconds: 300, Now));
    }

    [Fact]
    public void MaxAgeZero_ForcesReauthentication_OnlyAVeryRecentAuthTimePasses()
    {
        // max_age=0 means "must have authenticated just now"; only within-skew passes, an old one fails.
        Assert.True(MaxAgePolicy.IsFresh(UnixSecondsAgo(10), maxAgeSeconds: 0, Now));
        Assert.False(MaxAgePolicy.IsFresh(UnixSecondsAgo(3600), maxAgeSeconds: 0, Now));
    }

    [Fact]
    public void FutureAuthTimeBeyondSkew_IsNotFresh()
    {
        // A clock-forward IdP reporting a future auth_time must not satisfy the window indefinitely.
        Assert.False(MaxAgePolicy.IsFresh(UnixSecondsAgo(-3600), maxAgeSeconds: 300, Now));
    }
}
