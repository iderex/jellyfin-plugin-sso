using System;
using System.IO;
using System.Net;
using System.Net.Http;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
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

    public IAuthorizationContext AuthContext { get; }

    public PluginConfiguration Configuration { get; }

    /// <summary>
    /// Gets the mocked XML serializer the plugin persists through. Exposed so a test can assert on
    /// <c>SerializeToFile</c> call counts — e.g. to prove a config write actually reached the store's
    /// persist step (#412), or that a no-op resolution did not pay for one.
    /// </summary>
    public IXmlSerializer Xml { get; }

    public SsoControllerHarness(
        Action<PluginConfiguration>? configure = null,
        IPAddress? clientIp = null,
        Func<HttpRequestMessage, HttpResponseMessage>? httpResponder = null)
    {
        // The OpenID flow keeps process-wide caches as statics on OidcLoginService; clear them so a prior
        // test that exercised the login flow cannot leak in-flight state into this one (#289). The
        // outstanding-SAML-request cache is the same kind of static and is cleared for the same reason (#415).
        OidcLoginService.ResetOidStateForTests();
        SamlLoginService.ResetSamlRequestsForTests();
        // The one-time SAML login-outcome store (#251) and the one-time replay cache are process-wide
        // statics too; clear them so a prior test's stored outcome or consumed assertion id cannot leak in.
        SamlLoginService.ResetSamlOutcomesForTests();
        SamlAssertionValidator.ResetReplaysForTests();

        Configuration = new PluginConfiguration();
        configure?.Invoke(Configuration);

        var appPaths = Substitute.For<IApplicationPaths>();
        appPaths.PluginConfigurationsPath.Returns(Path.Combine(Path.GetTempPath(), "sso-test-" + Guid.NewGuid()));
        // The plugin derives its at-rest secret key file from DataFolderPath (under PluginsPath) (#158);
        // point it at a fresh temp directory so a test that persists a real secret can create the key and
        // round-trip the encryption. The key is created lazily only when a non-empty secret is encrypted,
        // so tests that persist no secret never touch disk here.
        appPaths.PluginsPath.Returns(Path.Combine(Path.GetTempPath(), "sso-test-plugins-" + Guid.NewGuid()));
        Xml = Substitute.For<IXmlSerializer>();
        Xml.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(Configuration);
        // Constructing the plugin sets the static SSOPlugin.Instance the controller reads.
        _ = new SSOPlugin(appPaths, Xml, Substitute.For<ILogger<SSOPlugin>>());

        UserManager = Substitute.For<IUserManager>();
        SessionManager = Substitute.For<ISessionManager>();
        AuthContext = Substitute.For<IAuthorizationContext>();

        // With no responder the factory returns null (an unreachable network — the controller's discovery
        // fetch fails closed). With one, every CreateClient() hands back a client backed by the stub, so
        // OpenID discovery/JWKS can be served in-process.
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        if (httpResponder is not null)
        {
            httpClientFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new StubHttpMessageHandler(httpResponder)));
        }

        Controller = new SSOController(
            Substitute.For<ILogger<SSOController>>(),
            Substitute.For<ILoggerFactory>(),
            SessionManager,
            UserManager,
            AuthContext,
            new FakeCryptoProvider(),
            Substitute.For<IProviderManager>(),
            httpClientFactory,
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
