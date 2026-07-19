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
    /// login-incapable account (T-E1). When the mode is already on, the change is followed by a fresh
    /// enforcement sweep so the previous break-glass admin (now non-exempt) is repointed and the new one is
    /// spared. Fail-closed: an unqualified target changes nothing.
    /// </summary>
    /// <param name="breakGlassUsername">The new break-glass admin username.</param>
    /// <returns>The guard verdict and, when the mode was on, the number of accounts repointed by the re-sweep.</returns>
    internal async Task<SsoOnlyEnableOutcome> TryDesignateBreakGlassAsync(string breakGlassUsername)
    {
        var resolved = _userManager.GetUserByName(breakGlassUsername);
        var verdict = SsoOnlyLoginGuard.Evaluate(breakGlassUsername, DescribeBreakGlass(breakGlassUsername));
        if (verdict != SsoOnlyGuardVerdict.Allow)
        {
            return new SsoOnlyEnableOutcome(verdict, 0, null);
        }

        var canonicalUsername = resolved!.Username;
        var modeOn = _configStore.Mutate(configuration =>
        {
            configuration.BreakGlassAdminUsername = canonicalUsername;
            return configuration.DisablePasswordLogin;
        });

        // When the mode is on, the exempt account changed, so re-assert the invariant: repoint the former
        // break-glass admin (now non-exempt) and spare the new one. A no-op sweep when the mode is off.
        var repointed = modeOn ? await SweepEnableAsync(canonicalUsername).ConfigureAwait(false) : 0;
        return new SsoOnlyEnableOutcome(SsoOnlyGuardVerdict.Allow, repointed, canonicalUsername);
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
        return await SweepDisableAsync().ConfigureAwait(false);
    }

    // Repoints every non-exempt account currently on the password provider to the SSO (non-password)
    // provider, leaving the break-glass admin and every account already on another provider untouched. Only
    // the routing field is written (T-E3). Idempotent: an account already on the SSO provider is skipped, so
    // re-running (e.g. a re-designation) costs no redundant writes.
    private async Task<int> SweepEnableAsync(string breakGlassUsername)
    {
        int repointed = 0;
        foreach (var user in _userManager.GetUsers() ?? Enumerable.Empty<User>())
        {
            if (IsBreakGlass(user.Username, breakGlassUsername))
            {
                continue;
            }

            if (SsoAuthenticationProviders.IsDefaultPasswordProvider(user.AuthenticationProviderId))
            {
                user.AuthenticationProviderId = SsoAuthenticationProviders.SsoProviderId;
                await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
                repointed++;
            }
        }

        return repointed;
    }

    // Restores the password provider for every account currently routed to the SSO (non-password) provider.
    // Lossless: the routing field is the only thing written; the stored password hash is left byte-for-byte
    // intact (T-E2). Accounts on the break-glass or a third-party provider are not on the SSO provider, so
    // they are not touched.
    private async Task<int> SweepDisableAsync()
    {
        int restored = 0;
        foreach (var user in _userManager.GetUsers() ?? Enumerable.Empty<User>())
        {
            if (SsoAuthenticationProviders.IsSsoProvider(user.AuthenticationProviderId))
            {
                user.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
                await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
                restored++;
            }
        }

        return restored;
    }

    private static bool IsBreakGlass(string username, string breakGlassUsername)
        => string.Equals(username, breakGlassUsername, StringComparison.OrdinalIgnoreCase);
}
