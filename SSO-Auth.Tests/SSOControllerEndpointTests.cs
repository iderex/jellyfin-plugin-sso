using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the <see cref="SSOController"/> login endpoints via <see cref="SsoControllerHarness"/>.
/// These pin the unknown-provider rejection on every entry point — the callback/utility endpoints return
/// a 400, the challenge endpoints throw (surfaced as a 4xx by the pipeline) — so the provider lookup can
/// never fall through to the auth logic for a name that is not configured.
/// </summary>
[Collection("SSOController")]
public class SSOControllerEndpointTests
{
    [Fact]
    public async Task OidPost_UnknownProvider_ReturnsBadRequest()
    {
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.OidPost("does-not-exist", "some-state");

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task OidChallenge_UnknownProvider_RejectsWithUniform400()
    {
        // Unknown and disabled providers now share one in-process 400 (the answer no longer depends on
        // host middleware mapping a thrown ArgumentException), so neither can be probed apart (#318).
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.OidChallenge("does-not-exist");

        AssertUnknownProvider(result);
    }

    [Fact]
    public async Task OidAuth_UnknownProvider_RejectsWithUniform400()
    {
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.OidAuth("does-not-exist", new AuthResponse { Data = "x" });

        AssertUnknownProvider(result);
    }

    [Fact]
    public void SamlPost_UnknownProvider_RejectsWithUniform400()
    {
        var harness = new SsoControllerHarness();

        var result = harness.Controller.SamlPost("does-not-exist");

        AssertUnknownProvider(result);
    }

    [Fact]
    public void SamlChallenge_UnknownProvider_RejectsWithUniform400()
    {
        var harness = new SsoControllerHarness();

        var result = harness.Controller.SamlChallenge("does-not-exist");

        AssertUnknownProvider(result);
    }

    // The uniform unknown/disabled-provider rejection: a text/plain 400 with the one shared body, so a
    // caller cannot distinguish an unknown provider from a disabled one on any endpoint (no oracle).
    private static void AssertUnknownProvider(ActionResult result)
    {
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("No matching provider found", content.Content);
    }

    [Fact]
    public async Task OidPost_DisabledProvider_ReturnsBadRequest()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig { Enabled = false });

        var result = await harness.Controller.OidPost("keycloak", "some-state");

        // Assert the body, not just the type: a missing/invalid state also returns a 400, so pinning
        // the "no matching provider" message keeps this test on the disabled-provider fallthrough.
        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("No matching provider found", badRequest.Value);
    }

    [Fact]
    public async Task OidPost_EnabledProvider_MissingState_ReturnsBadRequest()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig { Enabled = true });

        var result = await harness.Controller.OidPost("keycloak", string.Empty);

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Missing state", badRequest.Value);
    }

    [Fact]
    public async Task OidPost_EnabledProvider_UnknownState_ReturnsBadRequest()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig { Enabled = true });

        var result = await harness.Controller.OidPost("keycloak", "not-a-real-state-token");

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Invalid or expired state", badRequest.Value);
    }

    [Fact]
    public void SamlChallenge_DisabledProvider_RejectsAsUnknownProvider()
    {
        // A configured-but-disabled provider shares the unknown provider's uniform 400, so the two
        // cannot be told apart (no enumeration oracle) — fail-closed either way.
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = false });

        AssertUnknownProvider(harness.Controller.SamlChallenge("adfs"));
    }

    [Fact]
    public void OidProviderNames_ReturnsSeededNames()
    {
        var harness = new SsoControllerHarness(c =>
        {
            c.OidConfigs["keycloak"] = new OidConfig();
            c.OidConfigs["authelia"] = new OidConfig();
        });

        var result = Assert.IsType<OkObjectResult>(harness.Controller.OidProviderNames());
        var names = Assert.IsType<List<string>>(result.Value);
        Assert.Equal(2, names.Count);
        Assert.Contains("keycloak", names);
        Assert.Contains("authelia", names);
    }

    [Fact]
    public void SamlProviderNames_ReturnsSeededNames()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig());

        var result = Assert.IsType<OkObjectResult>(harness.Controller.SamlProviderNames());
        var names = Assert.IsType<List<string>>(result.Value);
        Assert.Equal(new[] { "adfs" }, names);
    }

    [Fact]
    public void OidStates_NoFlowsInProgress_ReturnsEmpty()
    {
        var harness = new SsoControllerHarness();

        var result = Assert.IsType<OkObjectResult>(harness.Controller.OidStates());
        Assert.Empty(Assert.IsAssignableFrom<IEnumerable>(result.Value));
    }
}

// The controller tests share the static SSOPlugin.Instance, so they must not run in parallel.
[CollectionDefinition("SSOController", DisableParallelization = true)]
public class SSOControllerCollection
{
}
