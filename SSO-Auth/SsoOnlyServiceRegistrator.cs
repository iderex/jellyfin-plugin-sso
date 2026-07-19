using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using Microsoft.Extensions.DependencyInjection;

namespace Jellyfin.Plugin.SSO_Auth;

/// <summary>
/// Registers the plugin's host-side services with Jellyfin's DI container (#165). Jellyfin discovers
/// <see cref="IPluginServiceRegistrator"/> implementations in plugin assemblies (via a parameterless
/// constructor) and calls <see cref="RegisterServices"/> while building the generic host. The one service
/// registered is the boot-time SSO-only reconciliation (<see cref="SsoOnlyReconciliationService"/>), which
/// makes the documented <c>config.xml</c> total-lockout recovery genuinely restore password login.
/// </summary>
public sealed class SsoOnlyServiceRegistrator : IPluginServiceRegistrator
{
    /// <summary>
    /// Registers the plugin's services with the service collection.
    /// </summary>
    /// <param name="serviceCollection">The service collection.</param>
    /// <param name="applicationHost">The server application host.</param>
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
        => serviceCollection.AddHostedService<SsoOnlyReconciliationService>();
}
