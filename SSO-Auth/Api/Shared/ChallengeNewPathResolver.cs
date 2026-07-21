// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Routing;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Shared;

/// <summary>
/// The one generic resolver both login-flow services share for the "new redirect path" spelling (#670): the
/// OpenID and SAML sites carried near-identical ~40-line copies — each with its own
/// <see cref="IntervalGate"/> persist-throttle — that differed only in which provider map the write
/// re-resolves against (<c>OidConfigs</c> vs <c>SamlConfigs</c>). Every field it touches
/// (<see cref="Config.ProviderConfigBase.NewPath"/>, <c>Enabled</c>) lives on the shared
/// <see cref="Config.ProviderConfigBase"/>, so one method generic over the provider-config type, taking the
/// map selector as a delegate, replaces both — with a SINGLE process-wide throttle gate rather than one per
/// flow. The race-window re-resolve, the throttle semantics and the best-effort swallow are preserved
/// verbatim from the pre-consolidation copies.
/// </summary>
internal static class ChallengeNewPathResolver
{
    // Throttles how often an actual NewPath change is persisted (#412 review follow-up). Both route
    // spellings stay permanently live side by side (ChallengePath and the URL builders never retire either one),
    // so a provider used concurrently by clients on both is EXPECTED to flip this value on alternating
    // logins — SamlAssertionValidator's ExpectedAcsUrls already treats a flip as routine, not a rare edge
    // case. Without a cap, that ordinary traffic shape would turn every such login into a synchronous
    // config persist under the process-wide config lock, serializing every OID/SAML login on the server
    // (not just this provider's) behind disk I/O. NewPath is only ever consulted by a LATER, separate
    // linking challenge — never this request's own redirect, which always uses its own freshly-derived
    // value regardless of whether a write lands — so bounding this to one persist attempt per interval,
    // process-wide, is harmless: it only delays how soon a flapping spelling's latest value reaches disk.
    // ONE gate is shared by both flows now (#670): a single process-wide throttle over the one persist path.
    // Not readonly: ResetForTests installs a fresh gate between tests, so one test's persisted change cannot
    // throttle a genuine change in the next one.
    private static IntervalGate _newPathPersistGate = new(TimeSpan.FromSeconds(5));

    /// <summary>
    /// Test-only reset of the shared NewPath persist-throttle gate (#412 review follow-up, #670): installs a
    /// fresh gate so a change persisted in one test can never throttle a genuine change in the next one. The
    /// flow services' own reset hooks (ResetOidStateForTests / ResetSamlRequestsForTests) call this, and
    /// SsoControllerHarness calls both for every test. Internal and reachable only through InternalsVisibleTo;
    /// never wired to an endpoint or DI, so it adds no runtime or security surface.
    /// </summary>
    internal static void ResetForTests() => _newPathPersistGate = new IntervalGate(TimeSpan.FromSeconds(5));

    // Resolves whether this challenge uses the "new", more descriptive redirect path, and records that as
    // server-managed runtime state on the provider config. A non-linking challenge derives the spelling
    // from the request path (a `.../start/...` route means the new path) and stores it, so a later linking
    // flow — which cannot know which redirect path the identity provider has registered — reuses the last
    // login's spelling. A linking challenge only reads the stored value. (See ExpectedAcsUrls for the same
    // reason this value is remembered across requests.)
    //
    // The record itself goes through MutateConfiguration rather than a bare field assignment (#412): the
    // `config` the caller passes in was read under ReadConfiguration's lock, which is released before this
    // runs, so writing straight into it raced a concurrent challenge for the same provider and never went
    // through the write path every other config mutation uses. The Mutate delegate re-resolves the
    // provider by name — against the map the caller selects (OidConfigs / SamlConfigs) — instead of trusting
    // the outer `config` reference, so one deleted/disabled in that race window is not written into. A plain
    // locked comparison with no write serves the case where the derived spelling already matches what is
    // stored; an actual change is throttled by _newPathPersistGate (see its comment) rather than persisted on
    // every mismatched challenge, and a persist failure is swallowed — this write is best-effort bookkeeping
    // for a later login, never a requirement for THIS one to succeed. Internal (not private) so
    // ProviderConfigStoreTests-style callers can exercise the race-window fallback branch directly and
    // deterministically, the way the flow services' test hooks already do for other login-flow internals.

    /// <summary>
    /// Resolves the NewPath spelling for a login challenge and, for a non-linking challenge whose derived
    /// spelling differs from the stored one, best-effort persists it through <c>MutateConfiguration</c> under
    /// the write lock (throttled, race-safe, failure-swallowed). The returned value always reflects this
    /// request's own path whether or not the write landed; a linking challenge only reads the stored value (#412).
    /// </summary>
    /// <typeparam name="T">The provider configuration type (OpenID or SAML), selected via <paramref name="selectConfigs"/>.</typeparam>
    /// <param name="provider">The provider name, used to re-resolve the live entry inside the mutation.</param>
    /// <param name="config">The provider configuration read outside the write lock; its stored NewPath is compared, never written directly.</param>
    /// <param name="isLinking">Whether this is a linking challenge (read-only) rather than a login challenge.</param>
    /// <param name="request">The current request, whose path the derived spelling comes from.</param>
    /// <param name="logger">The logger for a swallowed best-effort persist failure; may be null.</param>
    /// <param name="selectConfigs">Selects the provider map (OidConfigs or SamlConfigs) to re-resolve the live entry from.</param>
    /// <returns>The NewPath spelling this login/redirect should use.</returns>
    internal static bool ResolveChallengeNewPath<T>(
        string provider,
        T config,
        bool isLinking,
        HttpRequest request,
        ILogger logger,
        Func<PluginConfiguration, SerializableDictionary<string, T>> selectConfigs)
        where T : ProviderConfigBase
    {
        if (isLinking)
        {
            return config.NewPath;
        }

        var derived = ChallengePath.IsNewPath(request.Path.Value);
        if (derived == config.NewPath || !_newPathPersistGate.TryEnter(DateTime.Now))
        {
            return derived;
        }

        try
        {
            return SSOPlugin.Instance.MutateConfiguration(configuration =>
            {
                if (selectConfigs(configuration).TryGetValue(provider, out var liveConfig) && liveConfig is { Enabled: true })
                {
                    liveConfig.NewPath = derived;
                }

                // The current redirect always uses `derived` regardless of whether the write above landed —
                // it reflects this request's own path, exactly like a read-only resolution would have.
                return derived;
            });
        }
        catch (Exception ex)
        {
            // Best-effort: a config-persist failure here (full disk, permissions, a corrupt secret
            // envelope surfacing mid-ProtectAll) must not turn an otherwise-valid login into a 500 over a
            // value that only helps a LATER linking flow guess the right spelling. Broad on purpose —
            // every persist failure is handled identically — but logged so a persistently failing config
            // write stays observable rather than silently accepted forever (mirrors AvatarService's
            // best-effort avatar fetch).
            logger?.LogWarning(ex, "Could not record the NewPath redirect spelling for provider {Provider}; this login proceeds with its own derived value.", provider?.ReplaceLineEndings(string.Empty));
            return derived;
        }
    }
}
