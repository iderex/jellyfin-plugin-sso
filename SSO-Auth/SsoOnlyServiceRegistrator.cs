using System.Threading;
using Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using Microsoft.Extensions.DependencyInjection;

namespace Jellyfin.Plugin.SSO_Auth;

/// <summary>
/// Registers the plugin's host-side services with Jellyfin's DI container (#165). Jellyfin discovers
/// <see cref="IPluginServiceRegistrator"/> implementations in plugin assemblies (via a parameterless
/// constructor) and calls <see cref="RegisterServices"/> while building the generic host. Two things are
/// registered: the boot-time SSO-only reconciliation (<see cref="SsoOnlyReconciliationService"/>), which
/// makes the documented <c>config.xml</c> total-lockout recovery genuinely restore password login; and the
/// SSRF-hardened outbound HTTP client the OpenID backchannel uses (#755).
/// </summary>
public sealed class SsoOnlyServiceRegistrator : IPluginServiceRegistrator
{
    /// <summary>
    /// Registers the plugin's services with the service collection.
    /// </summary>
    /// <param name="serviceCollection">The service collection.</param>
    /// <param name="applicationHost">The server application host.</param>
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddHostedService<SsoOnlyReconciliationService>();

        // Keeps the login-page "Sign in with …" buttons (#722) in sync with the configured providers by
        // splicing a managed block into the server's branding login disclaimer on every config change.
        serviceCollection.AddHostedService<LoginButtonManager>();

        // The plugin's SSRF-hardened outbound client (#755). The OpenID discovery / token / JWKS fetches
        // resolve this named client through SsoHttp.CreateClient, so a provider endpoint that resolves to a
        // private/loopback address is rejected at the transport layer — the same connect-time guard the
        // avatar fetch uses (SsoHttp.CreateHardenedHandler). A test's stub or loopback factory supplies its
        // own handler for this name, so an in-process test IdP stays reachable while production is fail-closed.
        serviceCollection.AddHttpClient(SsoHttp.OutboundClientName)
            .ConfigurePrimaryHttpMessageHandler(SsoHttp.CreateHardenedHandler)
            // The hardened handler manages its own connection freshness via PooledConnectionLifetime, so the
            // factory need not also rotate (and rebuild) the handler on its default 2-minute cadence — the
            // documented pattern when you own PooledConnectionLifetime. Keeps one long-lived hardened handler
            // (the ConnectCallback still fires on every connect) instead of churning a new one every 2 minutes.
            .SetHandlerLifetime(Timeout.InfiniteTimeSpan);
    }
}
