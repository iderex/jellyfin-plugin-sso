using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the provider-delete endpoints and the rate limiter via
/// <see cref="SsoControllerHarness"/>.
/// </summary>
[Collection("SSOController")]
public class SSOControllerAdminTests
{
    [Fact]
    public void OidDel_RemovesTheProvider()
    {
        // Enabled so the provider would appear in the enabled-only names list if it were not deleted
        // (#344), keeping the DoesNotContain assertion a real proof of removal.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig { Enabled = true });

        harness.Controller.OidDel("keycloak");

        var names = Assert.IsType<List<string>>(Assert.IsType<OkObjectResult>(harness.Controller.OidProviderNames()).Value);
        Assert.DoesNotContain("keycloak", names);
    }

    [Fact]
    public void OidDel_UnknownProvider_DoesNotThrow()
    {
        var harness = new SsoControllerHarness();

        var exception = Record.Exception(() => harness.Controller.OidDel("does-not-exist"));

        Assert.Null(exception);
    }

    [Fact]
    public void SamlDel_RemovesTheProvider_ReturnsOk()
    {
        // Enabled so it would appear in the enabled-only names list if not deleted (#344).
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true });

        Assert.IsType<OkResult>(harness.Controller.SamlDel("adfs"));

        var names = Assert.IsType<List<string>>(Assert.IsType<OkObjectResult>(harness.Controller.SamlProviderNames()).Value);
        Assert.DoesNotContain("adfs", names);
    }

    [Fact]
    public async Task RateLimit_SecondCallOverBudget_Returns429()
    {
        var harness = new SsoControllerHarness(
            c =>
            {
                c.EnableRateLimit = true;
                c.RateLimitMaxAttempts = 1;
                c.RateLimitWindowSeconds = 60;
            },
            // A public address (the limiter fails open for non-public sources — reverse-proxy defense),
            // dedicated to this test so the process-static counter is its alone.
            clientIp: IPAddress.Parse("8.8.8.8"));

        // The first call passes the limiter and spends the single-attempt budget (unknown provider -> 400).
        var first = await harness.Controller.OidCallback("does-not-exist", "s");
        Assert.IsType<BadRequestObjectResult>(first);

        // The second is over budget and throttled with a 429.
        var throttled = await harness.Controller.OidCallback("does-not-exist", "s");
        var content = Assert.IsType<ContentResult>(throttled);
        Assert.Equal(429, content.StatusCode);
    }
}
