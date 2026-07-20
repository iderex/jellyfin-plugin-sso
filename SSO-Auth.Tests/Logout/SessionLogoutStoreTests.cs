using System;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SessionLogoutStore"/> — the bounded, pure operations over the Single Logout session
/// store (#727): capture with TTL + cap eviction, removal, and the by-subject lookup the SAML SLO path uses.
/// </summary>
public class SessionLogoutStoreTests
{
    private static readonly DateTime Now = new DateTime(2026, 7, 20, 12, 0, 0, DateTimeKind.Utc);

    private static LogoutSession State(string provider, string subject, string sid = "", string idToken = "tok")
        => new LogoutSession { Protocol = "OID", Provider = provider, Subject = subject, SessionIndex = sid, IdToken = idToken };

    [Fact]
    public void Capture_StoresTheEntryAndStampsCaptureTime()
    {
        var config = new PluginConfiguration();
        SessionLogoutStore.Capture(config, "session-1", State("keycloak", "sub-1"), Now);

        var stored = SessionLogoutStore.Find(config, "session-1");
        Assert.NotNull(stored);
        Assert.Equal("keycloak", stored.Provider);
        Assert.Equal(Now.Ticks, stored.CapturedUtcTicks);
    }

    [Fact]
    public void Capture_EmptyKey_IsIgnored()
    {
        var config = new PluginConfiguration();
        SessionLogoutStore.Capture(config, string.Empty, State("keycloak", "sub-1"), Now);
        Assert.Empty(config.LogoutSessions);
    }

    [Fact]
    public void Capture_SameKey_ReplacesThePriorEntry()
    {
        var config = new PluginConfiguration();
        SessionLogoutStore.Capture(config, "session-1", State("keycloak", "sub-1", idToken: "old"), Now);
        SessionLogoutStore.Capture(config, "session-1", State("keycloak", "sub-1", idToken: "new"), Now);

        Assert.Single(config.LogoutSessions);
        Assert.Equal("new", SessionLogoutStore.Find(config, "session-1").IdToken);
    }

    [Fact]
    public void Remove_DropsTheEntry_AndReportsWhether()
    {
        var config = new PluginConfiguration();
        SessionLogoutStore.Capture(config, "session-1", State("keycloak", "sub-1"), Now);

        Assert.True(SessionLogoutStore.Remove(config, "session-1"));
        Assert.False(SessionLogoutStore.Remove(config, "session-1"));
        Assert.Empty(config.LogoutSessions);
    }

    [Fact]
    public void Capture_PrunesEntriesOlderThanTheTtl()
    {
        var config = new PluginConfiguration();
        // An entry captured well beyond MaxAge in the past.
        var stale = State("keycloak", "old");
        stale.CapturedUtcTicks = Now.Ticks - SessionLogoutStore.MaxAge.Ticks - TimeSpan.FromDays(1).Ticks;
        config.LogoutSessions["stale"] = stale;

        // Any fresh capture triggers the TTL sweep.
        SessionLogoutStore.Capture(config, "fresh", State("keycloak", "new"), Now);

        Assert.False(config.LogoutSessions.ContainsKey("stale"));
        Assert.True(config.LogoutSessions.ContainsKey("fresh"));
    }

    [Fact]
    public void Capture_EnforcesTheHardCap_EvictingTheOldestFirst()
    {
        var config = new PluginConfiguration();
        // Fill to the cap with entries of increasing capture time, all within the TTL.
        for (var i = 0; i < SessionLogoutStore.MaxEntries; i++)
        {
            var s = State("keycloak", "sub-" + i);
            s.CapturedUtcTicks = Now.Ticks + i; // strictly increasing, oldest = i=0
            config.LogoutSessions["key-" + i] = s;
        }

        // One more capture pushes over the cap; the single oldest (key-0) must be evicted.
        SessionLogoutStore.Capture(config, "newest", State("keycloak", "newest"), Now.AddTicks(SessionLogoutStore.MaxEntries));

        Assert.Equal(SessionLogoutStore.MaxEntries, config.LogoutSessions.Count);
        Assert.False(config.LogoutSessions.ContainsKey("key-0"));
        Assert.True(config.LogoutSessions.ContainsKey("newest"));
    }

    [Fact]
    public void FindByProviderSubject_MatchesProviderAndSubject_AndSessionIndexWhenGiven()
    {
        var config = new PluginConfiguration();
        SessionLogoutStore.Capture(config, "a", State("keycloak", "alice", sid: "s1"), Now);
        SessionLogoutStore.Capture(config, "b", State("keycloak", "alice", sid: "s2"), Now);
        SessionLogoutStore.Capture(config, "c", State("keycloak", "bob", sid: "s1"), Now);
        SessionLogoutStore.Capture(config, "d", State("authelia", "alice", sid: "s1"), Now);

        // Blank session index matches every session for the (provider, subject).
        var allAlice = SessionLogoutStore.FindByProviderSubject(config, "keycloak", "alice", string.Empty);
        Assert.Equal(2, allAlice.Count);
        Assert.All(allAlice, p => Assert.Equal("alice", p.Value.Subject));

        // A given session index narrows to the exact session.
        var oneAlice = SessionLogoutStore.FindByProviderSubject(config, "keycloak", "alice", "s2");
        Assert.Single(oneAlice);
        Assert.Equal("b", oneAlice[0].Key);

        // A different provider or subject does not match.
        Assert.Empty(SessionLogoutStore.FindByProviderSubject(config, "keycloak", "carol", string.Empty));
        Assert.Single(SessionLogoutStore.FindByProviderSubject(config, "authelia", "alice", string.Empty));
    }
}
