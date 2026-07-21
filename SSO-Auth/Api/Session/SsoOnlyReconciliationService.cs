// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>
/// Boot-time reconciliation of the user database to the SSO-only flag (#165). SSO-only enforcement is
/// stateful in each account's <c>AuthenticationProviderId</c>, not in the config flag, so the documented
/// total-lockout recovery — edit <c>config.xml</c>, set <c>DisablePasswordLogin</c> to <c>false</c>, restart
/// — only works if something reconciles the user DB to the flag on startup. That is this hosted service:
/// once, at host start, it restores the accounts the mode repointed when the flag is off. It runs in the
/// Jellyfin generic host (registered by <see cref="SsoOnlyServiceRegistrator"/>), where <c>IUserManager</c>
/// is available. Fail-safe: any error is logged and swallowed so a reconciliation problem can never block
/// the server from starting.
/// </summary>
internal sealed class SsoOnlyReconciliationService : IHostedService
{
    private readonly IUserManager _userManager;
    private readonly ILogger<SsoOnlyReconciliationService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SsoOnlyReconciliationService"/> class.
    /// </summary>
    /// <param name="userManager">The Jellyfin user manager, resolved from the host DI container.</param>
    /// <param name="logger">The logger.</param>
    public SsoOnlyReconciliationService(IUserManager userManager, ILogger<SsoOnlyReconciliationService> logger)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Runs the one-shot reconciliation at host start.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token (unused; the sweep is short and idempotent).</param>
    /// <returns>A completed task.</returns>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var plugin = SSOPlugin.Instance;
        if (plugin is null)
        {
            // The plugin is constructed during plugin load, before host services start, so this is normally
            // set. If it is not, there is no configuration to reconcile against — skip rather than throw.
            return;
        }

        try
        {
            var service = new SsoOnlyLoginService(_userManager, plugin.ConfigStore, _logger);
            var restored = await service.ReconcileOnStartupAsync().ConfigureAwait(false);
            if (restored > 0 && _logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "[SSO Audit] SSO-only login reconciliation on startup: the mode is off but {RestoredCount} account(s) were still SSO-only; native password routing has been restored.",
                    restored);
            }
        }
        catch (Exception ex)
        {
            // Fail-safe: reconciliation is best-effort recovery. A failure here (e.g. the user store not yet
            // ready) must never prevent the server from starting; the elevated Disable endpoint remains a
            // fallback once an admin session exists.
            _logger.LogError(ex, "SSO-only login startup reconciliation failed; skipping. Native password routing was not reconciled.");
        }
    }

    /// <summary>
    /// No-op on shutdown.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A completed task.</returns>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
