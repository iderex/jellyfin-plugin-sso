#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Logout;

/// <summary>
/// Pure operations over the per-session Single Logout store (#727) — the
/// <see cref="PluginConfiguration.LogoutSessions"/> map. No I/O: the login path calls <see cref="Capture"/>
/// and the logout path calls <see cref="Remove"/>/the query helpers inside a <c>MutateConfiguration</c>/
/// <c>ReadConfiguration</c> lambda, so persistence and locking stay with the config store while the
/// selection and bounding rules live here and are unit-testable.
/// </summary>
/// <remarks>
/// The store is bounded two ways so it cannot grow without limit even if session-end pruning is missed: an
/// absolute <see cref="MaxEntries"/> cap (the oldest capture is evicted first) and a <see cref="MaxAge"/>
/// time-to-live (stale entries are swept on every capture). Both run at capture time, so a busy server keeps
/// the map trimmed without a background timer.
/// </remarks>
internal static class SessionLogoutStore
{
    /// <summary>The hard cap on stored sessions; the oldest is evicted once exceeded.</summary>
    internal const int MaxEntries = 10_000;

    /// <summary>Entries older than this are swept at capture time (a session that outlives it re-captures on its next login).</summary>
    internal static readonly TimeSpan MaxAge = TimeSpan.FromDays(30);

    /// <summary>
    /// Records the logout state for a freshly minted session, then prunes expired entries and enforces the
    /// cap. A re-used key replaces the prior entry (a re-login on the same session refreshes its id_token).
    /// </summary>
    /// <param name="configuration">The live configuration (mutated in place under the config lock).</param>
    /// <param name="sessionKey">The opaque per-session key (never a secret).</param>
    /// <param name="state">The captured state; its <see cref="LogoutSession.CapturedUtcTicks"/> is set here.</param>
    /// <param name="nowUtc">The current UTC time (supplied for determinism).</param>
    internal static void Capture(PluginConfiguration configuration, string sessionKey, LogoutSession state, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(state);
        if (string.IsNullOrEmpty(sessionKey))
        {
            return;
        }

        state.CapturedUtcTicks = nowUtc.Ticks;
        configuration.LogoutSessions[sessionKey] = state;

        Prune(configuration, nowUtc);
    }

    /// <summary>Removes the entry for a session (called when a logout terminates it). A no-op if absent.</summary>
    /// <param name="configuration">The live configuration.</param>
    /// <param name="sessionKey">The session key to drop.</param>
    /// <returns><c>true</c> when an entry was removed.</returns>
    internal static bool Remove(PluginConfiguration configuration, string sessionKey)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return !string.IsNullOrEmpty(sessionKey) && configuration.LogoutSessions.Remove(sessionKey);
    }

    /// <summary>Looks up a session by its key.</summary>
    /// <param name="configuration">The live configuration.</param>
    /// <param name="sessionKey">The session key.</param>
    /// <returns>The state, or <c>null</c> when absent.</returns>
    internal static LogoutSession? Find(PluginConfiguration configuration, string sessionKey)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (string.IsNullOrEmpty(sessionKey))
        {
            return null;
        }

        return configuration.LogoutSessions.TryGetValue(sessionKey, out var state) ? state : null;
    }

    /// <summary>
    /// Returns the sessions matching an inbound SAML <c>LogoutRequest</c> — the same provider and subject,
    /// and the same session index when the request carries one (a blank <paramref name="sessionIndex"/>
    /// matches any). Ordinal comparison; used by the SAML SLO path to resolve which sessions to revoke.
    /// </summary>
    /// <param name="configuration">The live configuration.</param>
    /// <param name="provider">The provider the request arrived for.</param>
    /// <param name="subject">The SAML NameID to match.</param>
    /// <param name="sessionIndex">The SessionIndex to match, or blank to match every session for the subject.</param>
    /// <returns>The matching (sessionKey, state) pairs.</returns>
    internal static IReadOnlyList<KeyValuePair<string, LogoutSession>> FindByProviderSubject(
        PluginConfiguration configuration, string provider, string subject, string sessionIndex)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        // A blank subject must match NOTHING, never every blank-subject entry: this feeds a token-revocation
        // path, so a LogoutRequest carrying an empty NameID must not be able to sweep unrelated sessions. The
        // SLO caller also rejects an empty subject, but defending it here too keeps the store safe by itself.
        if (string.IsNullOrEmpty(subject))
        {
            return System.Array.Empty<KeyValuePair<string, LogoutSession>>();
        }

        return configuration.LogoutSessions
            .Where(pair =>
                string.Equals(pair.Value.Provider, provider, StringComparison.Ordinal)
                && string.Equals(pair.Value.Subject, subject, StringComparison.Ordinal)
                && (string.IsNullOrEmpty(sessionIndex)
                    || string.Equals(pair.Value.SessionIndex, sessionIndex, StringComparison.Ordinal)))
            .ToList();
    }

    /// <summary>
    /// Returns the sessions captured for a given Jellyfin user, newest first (#727, SLO-2). The OIDC
    /// RP-initiated logout uses this to pick the caller's most recent session for a provider, whose id_token
    /// is the id_token_hint. A blank/empty user id matches nothing, so it can never sweep unrelated sessions.
    /// </summary>
    /// <param name="configuration">The live configuration.</param>
    /// <param name="userId">The Jellyfin user id to match.</param>
    /// <returns>The user's captured sessions, ordered newest first.</returns>
    internal static IReadOnlyList<KeyValuePair<string, LogoutSession>> FindByUser(PluginConfiguration configuration, Guid userId)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (userId == Guid.Empty)
        {
            return System.Array.Empty<KeyValuePair<string, LogoutSession>>();
        }

        return configuration.LogoutSessions
            .Where(pair => pair.Value.UserId == userId)
            .OrderByDescending(pair => pair.Value.CapturedUtcTicks)
            .ToList();
    }

    private static void Prune(PluginConfiguration configuration, DateTime nowUtc)
    {
        var sessions = configuration.LogoutSessions;

        // Time-to-live sweep: drop anything older than MaxAge (a lower bound on CapturedUtcTicks).
        var oldestAllowed = nowUtc.Ticks - MaxAge.Ticks;
        var expired = sessions
            .Where(pair => pair.Value.CapturedUtcTicks < oldestAllowed)
            .Select(pair => pair.Key)
            .ToList();
        foreach (var key in expired)
        {
            sessions.Remove(key);
        }

        // Hard cap: if still over the limit, evict the oldest captures until within it, so the store is
        // bounded regardless of TTL. Ordered by capture time so the eviction is deterministic.
        if (sessions.Count > MaxEntries)
        {
            var overflow = sessions
                .OrderBy(pair => pair.Value.CapturedUtcTicks)
                .Take(sessions.Count - MaxEntries)
                .Select(pair => pair.Key)
                .ToList();
            foreach (var key in overflow)
            {
                sessions.Remove(key);
            }
        }
    }
}
