using System;
using System.IO;
using System.Net;
using System.Net.Http;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Builds an <see cref="SSOController"/> that runs in-process against mocked Jellyfin services and a
/// test <see cref="SSOPlugin"/> singleton, so the endpoint branches are unit-testable without a live
/// server. The plugin loads its configuration through the mocked <see cref="IXmlSerializer"/>, so a
/// caller can seed providers via the <c>configure</c> callback. Because it sets the static
/// <see cref="SSOPlugin.Instance"/>, tests that use it must run in the non-parallel
/// <c>SSOController</c> collection.
/// </summary>
internal sealed class SsoControllerHarness
{
    public SSOController Controller { get; }

    public IUserManager UserManager { get; }

    public ISessionManager SessionManager { get; }

    public PluginConfiguration Configuration { get; }

    public SsoControllerHarness(Action<PluginConfiguration>? configure = null, IPAddress? clientIp = null)
    {
        Configuration = new PluginConfiguration();
        configure?.Invoke(Configuration);

        var appPaths = Substitute.For<IApplicationPaths>();
        appPaths.PluginConfigurationsPath.Returns(Path.Combine(Path.GetTempPath(), "sso-test-" + Guid.NewGuid()));
        var xml = Substitute.For<IXmlSerializer>();
        xml.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(Configuration);
        // Constructing the plugin sets the static SSOPlugin.Instance the controller reads.
        _ = new SSOPlugin(appPaths, xml, Substitute.For<ILogger<SSOPlugin>>());

        UserManager = Substitute.For<IUserManager>();
        SessionManager = Substitute.For<ISessionManager>();

        Controller = new SSOController(
            Substitute.For<ILogger<SSOController>>(),
            Substitute.For<ILoggerFactory>(),
            SessionManager,
            UserManager,
            Substitute.For<IAuthorizationContext>(),
            Substitute.For<ICryptoProvider>(),
            Substitute.For<IProviderManager>(),
            Substitute.For<IHttpClientFactory>(),
            Substitute.For<IServerConfigurationManager>())
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
        };
        Controller.ControllerContext.HttpContext.Request.Scheme = "https";
        Controller.ControllerContext.HttpContext.Request.Host = new HostString("jf.example.com");
        // The rate limiter is a process-static keyed on the client IP; a test that exercises throttling
        // passes a dedicated address so its counter cannot collide with another test's.
        Controller.ControllerContext.HttpContext.Connection.RemoteIpAddress = clientIp ?? IPAddress.Loopback;
    }
}
