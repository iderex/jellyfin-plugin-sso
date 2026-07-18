using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using MediaBrowser.Common.Api;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Header value that selects the impersonated caller for a request against the fixture host.
/// </summary>
public static class TestRoles
{
    /// <summary>The header the test authentication scheme reads to decide who the caller is.</summary>
    public const string Header = "X-Test-Role";

    /// <summary>An authenticated, non-administrator caller (passes a plain <c>[Authorize]</c>, fails elevation).</summary>
    public const string User = "user";

    /// <summary>An authenticated administrator (passes both the default policy and the elevation policy).</summary>
    public const string Admin = "admin";
}

/// <summary>
/// Hosts the real <see cref="SSOController"/> in an in-process Kestrel server so the
/// <c>[Authorize(Policy = Policies.RequiresElevation)]</c> attributes on the production endpoints are
/// enforced by the genuine ASP.NET Core routing + authentication + authorization middleware — the same
/// pipeline that runs inside Jellyfin — rather than merely asserted present by reflection.
///
/// What is REAL here (not mocked away):
///   * the production controller type, loaded via <c>AddApplicationPart</c> over the shipped assembly;
///   * its <c>[Authorize]</c> / <c>[Authorize(RequiresElevation)]</c> attributes;
///   * ASP.NET Core's attribute routing, authentication challenge, and the authorization middleware that
///     reads those attributes and rejects a caller (401/403) BEFORE the action body (and its model binding)
///     ever runs.
///
/// What the FIXTURE supplies (the host's responsibility inside Jellyfin, not the plugin's):
///   * a test authentication scheme keyed off the <see cref="TestRoles.Header"/> header, and
///   * the <see cref="Policies.RequiresElevation"/> policy registered to require an authenticated caller
///     in the "Administrator" role — mirroring Jellyfin's own RequiresElevation handler
///     (<c>context.User.IsInRole(UserRoles.Administrator)</c>). The plugin's contract is only that it marks
///     these endpoints with the attribute and relies on the host to enforce it; this fixture stands in for
///     that host so the enforcement path is exercised end to end.
/// </summary>
public sealed class SsoAuthorizationServerFixture : IAsyncDisposable
{
    private readonly WebApplication _app;

    public SsoAuthorizationServerFixture()
    {
        // Set the process-wide SSOPlugin.Instance the controller reads at construction
        // (SSOPlugin.Instance.ConfigStore in the SSOController ctor). Mirrors SsoControllerHarness so an
        // authorized request reaches the action body cleanly instead of NRE-ing into a 500. The rejection
        // paths (401/403) never construct the controller, so they do not depend on this.
        var appPaths = Substitute.For<IApplicationPaths>();
        appPaths.PluginConfigurationsPath.Returns(Path.Combine(Path.GetTempPath(), "sso-authz-test-" + Guid.NewGuid()));
        appPaths.PluginsPath.Returns(Path.Combine(Path.GetTempPath(), "sso-authz-test-plugins-" + Guid.NewGuid()));
        var xml = Substitute.For<IXmlSerializer>();
        xml.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(new Jellyfin.Plugin.SSO_Auth.Config.PluginConfiguration());
        _ = new SSOPlugin(appPaths, xml, Substitute.For<ILogger<SSOPlugin>>());

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        // The nine constructor collaborators of SSOController, resolved from DI when the framework activates
        // the controller. They are substitutes: this fixture proves the AUTHORIZATION gate, not the action
        // bodies (those are covered by the in-process SsoControllerHarness tests).
        builder.Services.AddSingleton(Substitute.For<ISessionManager>());
        builder.Services.AddSingleton(Substitute.For<IUserManager>());
        builder.Services.AddSingleton(Substitute.For<IAuthorizationContext>());
        builder.Services.AddSingleton<ICryptoProvider>(new FakeCryptoProvider());
        builder.Services.AddSingleton(Substitute.For<IProviderManager>());
        builder.Services.AddSingleton(Substitute.For<IServerConfigurationManager>());
        builder.Services.AddHttpClient();

        builder.Services.AddAuthentication(TestAuthHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, null);

        // The default policy (used by a bare [Authorize]) requires an authenticated caller; the elevation
        // policy additionally requires the Administrator role, mirroring Jellyfin's RequiresElevation.
        builder.Services.AddAuthorizationBuilder()
            .AddPolicy(Policies.RequiresElevation, policy => policy.RequireAuthenticatedUser().RequireRole(AdministratorRole));

        builder.Services.AddControllers().AddApplicationPart(typeof(SSOController).Assembly);

        _app = builder.Build();
        _app.UseRouting();
        _app.UseAuthentication();
        _app.UseAuthorization();
        _app.MapControllers();
        _app.StartAsync().GetAwaiter().GetResult();

        var address = _app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.GetEnumerator();
        address.MoveNext();
        Client = new HttpClient { BaseAddress = new Uri(address.Current) };

        Endpoints = new EndpointCatalog(_app.Services);
    }

    /// <summary>Gets an <see cref="HttpClient"/> bound to the running host's loopback base address.</summary>
    public HttpClient Client { get; }

    /// <summary>Gets the authorization metadata discovered from the live endpoint table.</summary>
    public EndpointCatalog Endpoints { get; }

    /// <summary>The role name Jellyfin grants administrators; the elevation policy requires it.</summary>
    internal const string AdministratorRole = "Administrator";

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// A trivial authentication scheme: the <see cref="TestRoles.Header"/> header selects the caller.
    /// Absent header -> unauthenticated (any [Authorize] yields 401). "user" -> authenticated, no role.
    /// "admin" -> authenticated with the Administrator role.
    /// </summary>
    private sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public const string SchemeName = "Test";

        public TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(TestRoles.Header, out var role) || role.Count == 0)
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var claims = new List<Claim> { new(ClaimTypes.Name, "test-caller") };
            if (string.Equals(role.ToString(), TestRoles.Admin, StringComparison.Ordinal))
            {
                claims.Add(new Claim(ClaimTypes.Role, AdministratorRole));
            }

            var identity = new ClaimsIdentity(claims, SchemeName);
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}
