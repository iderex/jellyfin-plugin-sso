// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Model.Branding;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="LoginButtonManager"/> — the hosted service that keeps the login-page branding
/// disclaimer in sync with the configured providers (#722), previously entirely untested (#928 U4).
/// Pinned: the startup sync writes the managed block, the write-guard skips the branding save when the
/// merge changes nothing, a configuration-change event re-syncs, StopAsync unsubscribes (a later event
/// writes nothing), and a branding-store failure is swallowed (a branding problem must never block
/// startup or a config save).
/// </summary>
public class LoginButtonManagerTests
{
    private static (LoginButtonManager Manager, IServerConfigurationManager Branding, BrandingOptions Options, SsoControllerHarness Harness) Build(
        Action<PluginConfiguration>? configure = null, string? existingDisclaimer = null)
    {
        // The harness constructs SSOPlugin and sets the static Instance the manager reads.
        var harness = new SsoControllerHarness(configure);
        var options = new BrandingOptions { LoginDisclaimer = existingDisclaimer };
        var branding = Substitute.For<IServerConfigurationManager>();
        branding.GetConfiguration("branding").Returns(options);
        return (new LoginButtonManager(branding, NullLogger<LoginButtonManager>.Instance), branding, options, harness);
    }

    private static void EnableButtons(PluginConfiguration c)
    {
        c.ManageLoginPageButtons = true;
        c.OidConfigs["corp"] = new OidConfig { Enabled = true };
    }

    [Fact]
    public async Task StartAsync_WithAManagedProvider_WritesTheButtonBlockIntoTheDisclaimer()
    {
        var (manager, branding, options, _) = Build(EnableButtons);

        await manager.StartAsync(CancellationToken.None);

        Assert.NotNull(options.LoginDisclaimer);
        Assert.Contains("corp", options.LoginDisclaimer, StringComparison.Ordinal);
        Assert.Contains("/sso/OID/start/corp", options.LoginDisclaimer, StringComparison.Ordinal);
        branding.Received(1).SaveConfiguration("branding", options);

        await manager.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task StartAsync_WhenTheMergeChangesNothing_PerformsNoBrandingSave()
    {
        // The write-guard: management off and no managed region present leaves the disclaimer byte-identical,
        // so the startup sync must not pay for (or version-churn) a branding save.
        var (manager, branding, _, _) = Build(configure: null, existingDisclaimer: "house rules");

        await manager.StartAsync(CancellationToken.None);

        branding.DidNotReceive().SaveConfiguration(Arg.Any<string>(), Arg.Any<object>());

        await manager.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task ConfigurationChanged_ReSyncsFromTheSavedConfiguration()
    {
        var (manager, branding, options, _) = Build();
        await manager.StartAsync(CancellationToken.None);
        branding.ClearReceivedCalls();

        // A save that turns button management on must splice the block in via the event hook.
        var updated = new PluginConfiguration();
        EnableButtons(updated);
        SSOPlugin.Instance.UpdateConfiguration(updated);

        Assert.NotNull(options.LoginDisclaimer);
        Assert.Contains("/sso/OID/start/corp", options.LoginDisclaimer, StringComparison.Ordinal);
        branding.Received(1).SaveConfiguration("branding", options);

        await manager.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task StopAsync_Unsubscribes_ALaterConfigurationChangeWritesNothing()
    {
        var (manager, branding, _, _) = Build();
        await manager.StartAsync(CancellationToken.None);
        await manager.StopAsync(CancellationToken.None);
        branding.ClearReceivedCalls();

        var updated = new PluginConfiguration();
        EnableButtons(updated);
        SSOPlugin.Instance.UpdateConfiguration(updated);

        branding.DidNotReceive().SaveConfiguration(Arg.Any<string>(), Arg.Any<object>());
    }

    [Fact]
    public async Task BrandingStoreFailure_IsSwallowed_StartupAndConfigSaveSurvive()
    {
        // Fail-safe contract: a branding-store fault must never propagate — it would otherwise block host
        // startup (StartAsync) or a plugin config save (the event hook runs inside the save path).
        var harness = new SsoControllerHarness(EnableButtons);
        var branding = Substitute.For<IServerConfigurationManager>();
        branding.GetConfiguration("branding").Returns(_ => throw new InvalidOperationException("branding store down"));
        var manager = new LoginButtonManager(branding, NullLogger<LoginButtonManager>.Instance);

        await manager.StartAsync(CancellationToken.None);

        var updated = new PluginConfiguration();
        EnableButtons(updated);
        SSOPlugin.Instance.UpdateConfiguration(updated);

        await manager.StopAsync(CancellationToken.None);
        _ = harness;
    }
}
