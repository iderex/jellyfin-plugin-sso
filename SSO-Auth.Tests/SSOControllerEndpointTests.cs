using System;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
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
    public async Task OidChallenge_UnknownProvider_Throws()
    {
        var harness = new SsoControllerHarness();

        await Assert.ThrowsAsync<ArgumentException>(() => harness.Controller.OidChallenge("does-not-exist"));
    }

    [Fact]
    public async Task OidAuth_UnknownProvider_ReturnsBadRequest()
    {
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.OidAuth("does-not-exist", new AuthResponse { Data = "x" });

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public void SamlPost_UnknownProvider_ReturnsBadRequest()
    {
        var harness = new SsoControllerHarness();

        var result = harness.Controller.SamlPost("does-not-exist");

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public void SamlChallenge_UnknownProvider_Throws()
    {
        var harness = new SsoControllerHarness();

        Assert.Throws<ArgumentException>(() => harness.Controller.SamlChallenge("does-not-exist"));
    }
}

// The controller tests share the static SSOPlugin.Instance, so they must not run in parallel.
[CollectionDefinition("SSOController", DisableParallelization = true)]
public class SSOControllerCollection
{
}
