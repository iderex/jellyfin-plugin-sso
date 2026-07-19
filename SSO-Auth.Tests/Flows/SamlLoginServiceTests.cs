using System;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Direct unit tests of <see cref="SamlLoginService"/>, the SAML flow extracted off the controller
/// (#160, #318 step 13), the mirror of <see cref="OidcLoginServiceTests"/>. The end-to-end
/// challenge/callback/authenticate/link behaviour is still exercised through the thin controller endpoints
/// in <see cref="SSOControllerSamlPostTests"/>, <see cref="SSOControllerSamlAuthTests"/> and
/// <see cref="SSOControllerLinkTests"/> (each endpoint is now a one-line delegation, so a passing controller
/// test is a passing service test); these add coverage that targets the service in isolation — the
/// fail-closed guard branches that reject before any collaborator is touched, and the process-wide-state test
/// hook that moved with the flow. Uses the non-parallel <c>SSOController</c> collection because it sets the
/// static <see cref="SSOPlugin.Instance"/>.
/// </summary>
[Collection("SSOController")]
public class SamlLoginServiceTests
{
    [Fact]
    public void Challenge_DisabledProvider_RejectsAsUnknownProvider()
    {
        var (service, context) = Build(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = false });
        context.Request.Path = "/sso/SAML/start/adfs";

        // A disabled provider fails closed before any AuthnRequest is built, with the same uniform body the
        // unknown-provider case gets — so the two cannot be told apart (#318).
        var result = service.Challenge("adfs", isLinking: false, context.Request, context.Response);

        AssertUnknownProvider(result);
    }

    [Fact]
    public void Challenge_UnknownProvider_RejectsAsUnknownProvider()
    {
        var (service, context) = Build(_ => { });
        context.Request.Path = "/sso/SAML/start/nope";

        var result = service.Challenge("nope", isLinking: false, context.Request, context.Response);

        AssertUnknownProvider(result);
    }

    [Fact]
    public void Post_DisabledProvider_RejectsAsUnknownProvider()
    {
        var (service, context) = Build(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = false });

        var result = service.Callback("adfs", relayState: null, formSamlResponse: null, context.Request, context.Response);

        AssertUnknownProvider(result);
    }

    [Fact]
    public async Task AuthenticateAsync_DisabledProvider_RejectsAsUnknownProvider()
    {
        var (service, _) = Build(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = false });

        // Guard precedes the state consume, so a disabled provider is rejected without touching any
        // collaborator — the same uniform body an unknown provider gets.
        var result = await service.AuthenticateAsync("adfs", new AuthResponse { Data = "irrelevant" }, bindingCookie: null, () => "127.0.0.1");

        AssertUnknownProvider(result);
    }

    [Fact]
    public async Task AuthenticateAsync_MalformedResponse_RejectsAsInvalid()
    {
        var (service, _) = Build(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, DoNotValidateAudience = true });

        // A non-base64 / malformed response is not a live outcome token, so it misses the one-time redeem and
        // is rejected the same way an invalid one is — a clean 4xx in the uniform SAML body, never an
        // unhandled 500 (#199).
        var result = await service.AuthenticateAsync("adfs", new AuthResponse { Data = "not-a-saml-response" }, bindingCookie: null, () => "127.0.0.1");

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("SAML response validation failed", content.Content);
    }

    [Fact]
    public void Link_DisabledProvider_ReturnsBadRequest()
    {
        var (service, context) = Build(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = false });

        // A disabled provider must neither create a link nor consume the assertion (#343); the unknown and
        // disabled cases share one 400 response so neither can be probed apart.
        var result = service.Link("adfs", Guid.NewGuid(), new AuthResponse { Data = "irrelevant" }, context.Request);

        var content = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("No matching provider found", content.Value);
    }

    [Fact]
    public void SeedAndReset_AreProcessWideHooksThatMovedWithTheFlow()
    {
        // The seed and reset test hooks moved off the controller onto the flow service with the SAML statics
        // (#160). They are process-wide and must not throw when driven directly; the reset makes each test
        // start from a clean outstanding-request cache (the harness calls it for exactly this reason).
        SamlLoginService.SeedSamlRequestForTests("adfs", "req-1", "binding-1", DateTime.UtcNow.AddMinutes(15));
        SamlLoginService.ResetSamlRequestsForTests();
    }

    [Fact]
    public void ResolveChallengeNewPath_ProviderDisabledInTheRaceWindow_SkipsThePersist_ButStillReturnsThisRequestsDerivedSpelling()
    {
        // #412 review follow-up: exercises the Mutate delegate's own re-check inside the shared
        // ChallengeNewPathResolver (unified across both flows in #670), driven with the SAML map selector.
        // `config` mirrors the reference the real caller already captured under ReadConfiguration's lock
        // (FindSamlConfig) before its own Enabled check passed; something then disables the provider in the
        // LIVE store before this write attempt runs — a race the outer check cannot see. The current
        // challenge must still get its own freshly-derived spelling for its redirect, but the disabled
        // provider's stored NewPath must be left untouched rather than written into.
        var (_, context) = Build(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, NewPath = false });
        var config = SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"]);
        SSOPlugin.Instance.MutateConfiguration(c => c.SamlConfigs["adfs"].Enabled = false);
        context.Request.Path = "/sso/SAML/start/adfs";

        var result = ChallengeNewPathResolver.ResolveChallengeNewPath("adfs", config, isLinking: false, context.Request, Substitute.For<ILogger>(), c => c.SamlConfigs);

        Assert.True(result); // this request's own redirect still uses the freshly-derived spelling
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].NewPath)); // stored value untouched
    }

    private static void AssertUnknownProvider(ActionResult result)
    {
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("No matching provider found", content.Content);
    }

    // Builds a SamlLoginService over the same collaborator graph the controller constructs, against a
    // freshly-bootstrapped SSOPlugin.Instance seeded via the configure callback and a DefaultHttpContext for
    // the request/response the flow reads and writes. The harness resets the process-wide SAML state, so
    // each test starts clean.
    private static (SamlLoginService Service, DefaultHttpContext Context) Build(Action<PluginConfiguration> configure)
    {
        var harness = new SsoControllerHarness(configure);
        var logger = Substitute.For<ILogger>();

        var canonicalLinks = new CanonicalLinkService(harness.UserManager, new FakeCryptoProvider(), SSOPlugin.Instance.ConfigStore, logger);
        var avatarService = new AvatarService(harness.UserManager, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), logger, SsoHttp.UserAgent);
        var sessionMinter = new SessionMinter(harness.UserManager, avatarService, Substitute.For<ISessionManager>(), logger);
        var ssoOnly = new SsoOnlyLoginService(harness.UserManager, SSOPlugin.Instance.ConfigStore, logger);
        var loginCompletion = new LoginCompletionService(canonicalLinks, sessionMinter, ssoOnly, logger);
        var service = new SamlLoginService(loginCompletion, canonicalLinks, logger);

        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("jf.example.com");
        return (service, context);
    }
}
