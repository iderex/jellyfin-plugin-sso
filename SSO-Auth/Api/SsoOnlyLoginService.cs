using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The outcome of an SSO-only activation attempt: the guard <see cref="SsoOnlyGuardVerdict"/> and, only
/// when it was <see cref="SsoOnlyGuardVerdict.Allow"/>, how many accounts the enforcement sweep repointed
/// off the password provider. A non-Allow verdict changes nothing (the flag is not set and no account is
/// touched), so <see cref="RepointedCount"/> is zero on every refusal.
/// </summary>
/// <param name="Verdict">The guard verdict.</param>
/// <param name="RepointedCount">Accounts repointed to the SSO (non-password) provider on a successful activation.</param>
/// <param name="BreakGlassAdmin">The account's own canonical username on success (for the audit line); null on refusal.</param>
internal readonly record struct SsoOnlyEnableOutcome(SsoOnlyGuardVerdict Verdict, int RepointedCount, string BreakGlassAdmin);

/// <summary>
/// The login-path re-assertion outcome for a resolved account (#165, Findings A/B/H1): the
/// <c>AuthenticationProviderId</c> the mint must persist, and whether the account is the designated
/// break-glass admin while SSO-only mode is on. Both are derived from the RESOLVED account (its own
/// username), never the mutable IdP-supplied username, so the login path and the enable sweep can never
/// disagree on who the break-glass admin is.
/// </summary>
/// <param name="DefaultProvider">The provider id to persist as the account's default login provider (or the configured default when the mode is off).</param>
/// <param name="IsBreakGlassAdmin">True only when the account is the break-glass admin AND the mode is on, so the mint must leave its admin/enabled recovery state intact.</param>
internal readonly record struct SsoOnlyLoginDecision(string DefaultProvider, bool IsBreakGlassAdmin);

/// <summary>
/// The plugin-driven per-user enforcement of SSO-only login (#165). Jellyfin has no server-wide "disable
/// password login" switch, so the only lever is each account's <c>AuthenticationProviderId</c>
/// (SSO-ONLY-LOGIN-DESIGN.md §2). This service owns that lever: it runs the fail-closed last-admin guard
/// (<see cref="SsoOnlyLoginGuard"/>) before activation, then sweeps every non-exempt account off the
/// password provider — leaving the designated break-glass admin's password door untouched — and reverses
/// the sweep losslessly on disable (provider routing only; never a password hash, never a permission,
/// T-E2/T-E3). The controller keeps the HTTP boundary, the elevation guards, and the audit; this keeps the
/// account enumeration and every read/write of the mode flags under the <see cref="ProviderConfigStore"/>
/// lock.
/// </summary>
internal sealed class SsoOnlyLoginService
{
    private readonly IUserManager _userManager;
    private readonly ProviderConfigStore _configStore;
    private readonly ILogger _logger;

    internal SsoOnlyLoginService(IUserManager userManager, ProviderConfigStore configStore, ILogger logger)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _configStore = configStore ?? throw new ArgumentNullException(nameof(configStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Resolves an account by username into the <see cref="BreakGlassAdminState"/> the guard consumes. A
    /// missing account yields <c>Exists = false</c> (default), which the guard fails closed. "Usable
    /// password login" means the account currently routes to Jellyfin's built-in password provider AND has
    /// a non-empty stored password — an admin already switched to SSO (or to a third-party provider) cannot
    /// serve as the break-glass door, and a passwordless account cannot log in without SSO.
    /// </summary>
    /// <param name="username">The candidate break-glass admin username.</param>
    /// <returns>The resolved login state.</returns>
    internal BreakGlassAdminState DescribeBreakGlass(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return default;
        }

        var user = _userManager.GetUserByName(username);
        if (user is null)
        {
            return default;
        }

        var usablePasswordLogin = SsoAuthenticationProviders.IsDefaultPasswordProvider(user.AuthenticationProviderId)
            && !string.IsNullOrEmpty(user.Password);

        return new BreakGlassAdminState(
            Exists: true,
            IsAdministrator: user.HasPermission(PermissionKind.IsAdministrator),
            IsEnabled: !user.HasPermission(PermissionKind.IsDisabled),
            HasUsablePasswordLogin: usablePasswordLogin);
    }

    /// <summary>
    /// Re-asserts SSO-only enforcement for a resolved login on the LOGIN path (#165, Findings A/B/H1),
    /// mirroring the enable sweep's discipline so the two paths agree. The break-glass decision is judged on
    /// the RESOLVED account's own username (the sweep's <c>user.Username</c> basis), NOT the mutable
    /// IdP-supplied username, so a rename, a manual link, or a differing username claim can never treat the
    /// break-glass admin's own SSO login as non-exempt and strip its password door (Finding A). While the
    /// mode is on, a non-exempt account still on the password provider is TRACKED — persisted to
    /// <c>SsoOnlyRepointedUserIds</c> — BEFORE the mint repoints it, so the reversible off-switch and the boot
    /// reconciliation restore exactly the accounts the mode moved (Finding B); the break-glass admin and an
    /// account already on the SSO provider (plugin-created natively-SSO accounts included) are never tracked.
    /// The returned <see cref="SsoOnlyLoginDecision.IsBreakGlassAdmin"/> lets the mint keep the recovery
    /// account admin/enabled (Finding H1). When the mode is off, the configured default is returned unchanged
    /// and nothing is tracked (a read only, no config write).
    /// </summary>
    /// <param name="userId">The Jellyfin user id the login resolved to.</param>
    /// <param name="configuredDefaultProvider">The provider config's own <c>DefaultProvider</c> (already trimmed), used unchanged while the mode is off.</param>
    /// <returns>The provider id to persist and whether this is the break-glass admin under an active mode.</returns>
    internal SsoOnlyLoginDecision ResolveLoginEnforcement(Guid userId, string configuredDefaultProvider)
    {
        // Decide under one locked read for the common paths (mode off, break-glass, already-SSO or
        // already-tracked) so a login does NOT pay a config persist; only a first-time repoint of a
        // non-exempt account needs the tracking write below.
        var (decision, shouldTrack) = _configStore.Read(configuration =>
        {
            var resolved = _userManager.GetUserById(userId);
            if (resolved is null)
            {
                // Deleted between resolution and here; the mint fails closed on the null user, so enforce
                // nothing and track nothing.
                return (new SsoOnlyLoginDecision(configuredDefaultProvider, false), false);
            }

            var provider = SsoOnlyLoginGuard.ResolveLoginProvider(configuration, resolved.Username, configuredDefaultProvider);
            var modeOn = configuration is { DisablePasswordLogin: true };
            var isBreakGlass = modeOn && SsoOnlyLoginGuard.IsBreakGlass(configuration, resolved.Username);

            // Track a non-exempt account only when this login is actually moving it off the password provider:
            // never the break-glass admin, never an account already on the SSO provider (so a plugin-created
            // natively-SSO account is never handed a password door on restore), never a duplicate entry.
            var track = modeOn
                && !isBreakGlass
                && SsoAuthenticationProviders.IsDefaultPasswordProvider(resolved.AuthenticationProviderId)
                && !configuration.SsoOnlyRepointedUserIds.Contains(userId);

            return (new SsoOnlyLoginDecision(provider, isBreakGlass), track);
        });

        if (shouldTrack)
        {
            // Track FIRST — persisted before the mint repoints — exactly as SweepEnableAsync does: a crash
            // between tracking and the repoint leaves the account tracked-but-not-moved, which the idempotent,
            // IsSsoProvider-gated restore simply no-ops and clears. The reverse (moved-but-untracked, which the
            // tracked-set restore could never auto-recover) cannot happen. Re-checked under the lock so a
            // concurrent login for the same account cannot double-add.
            //
            // Documented residual (login-vs-Disable race): unlike the sweep, the actual repoint runs LATER, in
            // SessionMinter after the avatar fetch and revocation gates. If DisableAsync interleaves in that
            // gap it flips the flag, then RestoreRepointedAccountsAsync reads the tracked set, finds this
            // account still on the PASSWORD provider (the mint has not written yet) so IsSsoProvider is false,
            // skips it, and clears the whole set — after which the in-flight mint writes SsoProviderId, leaving
            // this account repointed-to-SSO, untracked, mode off. Accepted as a residual: it is a single
            // NON-break-glass account (the break-glass admin is never tracked, so recovery is never lost), it
            // is strictly better than the pre-fix state (which left EVERY login-path repoint untracked), and it
            // self-heals on the account's next mode-off SSO login whenever the provider's DefaultProvider
            // routes to the password provider (the mint then rewrites it). The narrow-window alternative —
            // keeping unrestored ids tracked instead of clearing — was rejected because it strands the
            // harmless tracked-but-not-moved id (a revoked-in-flight mint) in the set indefinitely.
            _configStore.Mutate(configuration =>
            {
                if (!configuration.SsoOnlyRepointedUserIds.Contains(userId))
                {
                    configuration.SsoOnlyRepointedUserIds.Add(userId);
                }
            });
        }

        return decision;
    }

    /// <summary>
    /// Attempts to turn SSO-only login on with the given break-glass admin. Fail-closed: the guard runs
    /// FIRST and, on any refusal, nothing is persisted and no account is touched. On success it persists
    /// <c>DisablePasswordLogin = true</c> and the (canonically-cased) break-glass username under the config
    /// lock, then repoints every non-exempt account off the password provider.
    /// </summary>
    /// <param name="breakGlassUsername">The account to designate as the always-password-capable break-glass admin.</param>
    /// <returns>The guard verdict and, on success, the number of accounts repointed.</returns>
    internal async Task<SsoOnlyEnableOutcome> TryEnableAsync(string breakGlassUsername)
    {
        var resolved = _userManager.GetUserByName(breakGlassUsername);
        var verdict = SsoOnlyLoginGuard.Evaluate(breakGlassUsername, DescribeBreakGlass(breakGlassUsername));
        if (verdict != SsoOnlyGuardVerdict.Allow)
        {
            return new SsoOnlyEnableOutcome(verdict, 0, null);
        }

        // Store the account's own canonical username (not the caller's casing) so the exempt check and the
        // audit line are unambiguous. resolved is non-null here — the guard proved the account exists.
        var canonicalUsername = resolved!.Username;
        _configStore.Mutate(configuration =>
        {
            configuration.DisablePasswordLogin = true;
            configuration.BreakGlassAdminUsername = canonicalUsername;
        });

        var repointed = await SweepEnableAsync(canonicalUsername).ConfigureAwait(false);
        return new SsoOnlyEnableOutcome(SsoOnlyGuardVerdict.Allow, repointed, canonicalUsername);
    }

    /// <summary>
    /// Re-designates the break-glass admin. The new target must itself satisfy the guard (an enabled
    /// administrator with a usable password), so the exemption can never point at a non-admin or a
    /// login-incapable account (T-E1). Fail-closed: an unqualified target changes nothing. Changing the
    /// designation while the mode is ON is not supported here — every other admin has already been repointed
    /// off the password provider, so no other account can satisfy the "usable password" guard; disable the
    /// mode first, re-designate, then re-enable.
    /// </summary>
    /// <param name="breakGlassUsername">The new break-glass admin username.</param>
    /// <returns>The guard verdict and the account's canonical username on success.</returns>
    internal SsoOnlyEnableOutcome TryDesignateBreakGlass(string breakGlassUsername)
    {
        var resolved = _userManager.GetUserByName(breakGlassUsername);
        var verdict = SsoOnlyLoginGuard.Evaluate(breakGlassUsername, DescribeBreakGlass(breakGlassUsername));
        if (verdict != SsoOnlyGuardVerdict.Allow)
        {
            return new SsoOnlyEnableOutcome(verdict, 0, null);
        }

        var canonicalUsername = resolved!.Username;
        _configStore.Mutate(configuration => configuration.BreakGlassAdminUsername = canonicalUsername);
        return new SsoOnlyEnableOutcome(SsoOnlyGuardVerdict.Allow, 0, canonicalUsername);
    }

    /// <summary>
    /// Turns SSO-only login off and restores native password routing for every account the mode repointed —
    /// the reversible, no-SSO off-switch (SSO-ONLY-LOGIN-DESIGN.md §3 option B). It restores
    /// <c>DefaultAuthenticationProvider</c> and NOTHING else: no stored password hash is reset or revealed
    /// (T-E2), so no account gains a known password from the toggle. Turning the mode off never depends on
    /// SSO.
    /// </summary>
    /// <returns>The number of accounts whose provider routing was restored.</returns>
    internal async Task<int> DisableAsync()
    {
        _configStore.Mutate(configuration => configuration.DisablePasswordLogin = false);
        return await RestoreRepointedAccountsAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Boot-time reconciliation of the user database to the flag (#165). If SSO-only is OFF but accounts the
    /// mode repointed are still routed to the SSO provider, restore them — this makes the documented
    /// total-lockout recovery ("edit config.xml, set <c>DisablePasswordLogin</c> to <c>false</c>, restart")
    /// genuinely work, because enforcement lives in the user database, not the flag. Idempotent and
    /// fail-safe: a normal boot (flag on, or the tracking set already empty) does nothing, and only accounts
    /// the mode itself recorded are touched, so the plugin's own SSO-created accounts (which permanently carry
    /// the SSO provider id) are never handed a password door. When the flag is ON this leaves enforcement in
    /// place.
    /// </summary>
    /// <returns>The number of accounts restored.</returns>
    internal async Task<int> ReconcileOnStartupAsync()
    {
        var (modeOn, trackedCount) = _configStore.Read(
            configuration => (configuration.DisablePasswordLogin, configuration.SsoOnlyRepointedUserIds.Count));
        if (modeOn || trackedCount == 0)
        {
            return 0;
        }

        return await RestoreRepointedAccountsAsync().ConfigureAwait(false);
    }

    // Repoints every non-exempt account currently on the password provider to the SSO (non-password)
    // provider, leaving the break-glass admin and every account already on another provider untouched, and
    // RECORDS each moved account's id so the off-switch and the boot reconciliation restore exactly this set
    // (never the plugin's own SSO-created accounts). Only the routing field is written (T-E3). Idempotent: an
    // account already on the SSO provider is skipped.
    //
    // Durability: each account is tracked (a persisted Mutate) BEFORE it is repointed, so a crash between the
    // two steps leaves the account tracked-but-not-moved — harmless, because the off-switch/boot reconcile is
    // idempotent and gated on IsSsoProvider, so it no-ops a still-password account and clears the id. The
    // failure the track-after ordering allowed — moved-but-untracked, which the tracked-set restore could
    // never auto-recover — cannot happen: the persisted tracked set is always a superset of the accounts
    // actually moved. The break-glass admin and accounts already off the password provider are never tracked,
    // so restore never hands a natively-SSO/plugin-created account a password door.
    private async Task<int> SweepEnableAsync(string breakGlassUsername)
    {
        var repointed = 0;
        foreach (var user in AllUsers())
        {
            if (IsBreakGlass(user.Username, breakGlassUsername))
            {
                continue;
            }

            if (!SsoAuthenticationProviders.IsDefaultPasswordProvider(user.AuthenticationProviderId))
            {
                continue;
            }

            var id = user.Id;
            _configStore.Mutate(configuration =>
            {
                if (!configuration.SsoOnlyRepointedUserIds.Contains(id))
                {
                    configuration.SsoOnlyRepointedUserIds.Add(id);
                }
            });

            user.AuthenticationProviderId = SsoAuthenticationProviders.SsoProviderId;
            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            repointed++;
        }

        return repointed;
    }

    // Enumerate every account across the whole supported Jellyfin range. IUserManager's all-users accessor
    // diverged inside that range: the 10.11.0 ABI floor exposes the `Users` property, while 10.11.11+ and 12.0
    // replaced it with a `GetUsers()` method — no member is common to all three at compile time. A source
    // reference to either one therefore breaks EITHER the floor build (proving the shipped artifact would
    // MissingMethod on an early-10.11 server, #142) or the shipping build. Binding whichever member the loaded
    // server actually exposes, at runtime, is the only way to keep the plugin loadable on every 10.11.x and on
    // 12.0. This is a cold path (mode enable only), so the per-call lookup cost is irrelevant.
    private IEnumerable<User> AllUsers()
    {
        var manager = (object)_userManager;
        var type = manager.GetType();

        if (type.GetMethod("GetUsers", Type.EmptyTypes)?.Invoke(manager, null) is IEnumerable<User> viaMethod)
        {
            return viaMethod;
        }

        if (type.GetProperty("Users")?.GetValue(manager) is IEnumerable<User> viaProperty)
        {
            return viaProperty;
        }

        return Array.Empty<User>();
    }

    // Restores the built-in password provider for ONLY the accounts the mode recorded as repointed (that are
    // still on the SSO provider), then clears the tracking set. Lossless: the routing field is the only thing
    // written; the stored password hash is left byte-for-byte intact (T-E2). Scoping to the tracked set is
    // what keeps the plugin's own SSO-created accounts (permanently on the SSO provider, never repointed by
    // the mode) from being wrongly handed a password door.
    private async Task<int> RestoreRepointedAccountsAsync()
    {
        var trackedIds = _configStore.Read(configuration => configuration.SsoOnlyRepointedUserIds.ToList());
        int restored = 0;
        foreach (var id in trackedIds)
        {
            var user = _userManager.GetUserById(id);
            if (user is not null && SsoAuthenticationProviders.IsSsoProvider(user.AuthenticationProviderId))
            {
                user.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
                await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
                restored++;
            }
        }

        _configStore.Mutate(configuration => configuration.SsoOnlyRepointedUserIds.Clear());
        return restored;
    }

    private static bool IsBreakGlass(string username, string breakGlassUsername)
        => string.Equals(username, breakGlassUsername, StringComparison.OrdinalIgnoreCase);
}
