using System;
using System.Reflection;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the SSO-only login endpoints (#165) via <see cref="SsoControllerHarness"/>: the
/// RequiresElevation gate on every mutating endpoint (criterion 6), the fail-closed activation refusal, the
/// happy-path enable, and the reversible disable. The pure guard, the enforcement sweep, and the audit
/// format are pinned in their own suites; these pin the controller wiring and HTTP shape.
/// </summary>
[Collection("SSOController")]
public class SSOControllerSsoOnlyTests
{
    private static readonly Guid RootId = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000001");
    private static readonly Guid AliceId = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002");

    [Theory]
    [InlineData(nameof(SSOController.EnableSsoOnly))]
    [InlineData(nameof(SSOController.DisableSsoOnly))]
    [InlineData(nameof(SSOController.DesignateBreakGlassAdmin))]
    [InlineData(nameof(SSOController.SsoOnlyStatus))]
    public void SsoOnlyEndpoints_RequireElevation(string methodName)
    {
        // Toggling the mode and changing the break-glass designation are elevated operations (criterion 6):
        // the [Authorize(RequiresElevation)] filter refuses a non-elevated caller before the body runs.
        var authorize = typeof(SSOController).GetMethod(methodName)!.GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(authorize);
        Assert.Equal(Policies.RequiresElevation, authorize!.Policy);
    }

    [Fact]
    public async Task EnableSsoOnly_WithBreakGlassPasswordAdmin_ReturnsOk_AndPersistsMode()
    {
        var harness = new SsoControllerHarness();
        var root = SeedPasswordAdmin(harness, "root", RootId);
        harness.UserManager.GetUsers().Returns(new[] { root });

        var result = await harness.Controller.EnableSsoOnly("root");

        Assert.IsType<OkResult>(result);
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.DisablePasswordLogin));
        Assert.Equal("root", SSOPlugin.Instance.ReadConfiguration(c => c.BreakGlassAdminUsername));
    }

    [Fact]
    public async Task EnableSsoOnly_WithNoQualifyingAdmin_ReturnsBadRequest_AndChangesNothing()
    {
        var harness = new SsoControllerHarness();
        // Only a non-admin exists — enabling would strand every administrator, so it is refused fail-closed.
        var alice = SeedPasswordUser(harness, "alice", AliceId);
        harness.UserManager.GetUsers().Returns(new[] { alice });

        var result = await harness.Controller.EnableSsoOnly("alice");

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(SsoOnlyLoginGuard.PublicRefusalMessage, bad.Value);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.DisablePasswordLogin));
    }

    [Fact]
    public async Task DisableSsoOnly_AfterEnable_ReturnsOk_AndClearsMode()
    {
        var harness = new SsoControllerHarness();
        var root = SeedPasswordAdmin(harness, "root", RootId);
        var alice = SeedPasswordUser(harness, "alice", AliceId);
        harness.UserManager.GetUsers().Returns(new[] { root, alice });

        Assert.IsType<OkResult>(await harness.Controller.EnableSsoOnly("root"));
        var result = await harness.Controller.DisableSsoOnly();

        Assert.IsType<OkResult>(result);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.DisablePasswordLogin));
        // Alice was repointed on enable and restored on disable; the break-glass admin never moved.
        Assert.Equal(SsoAuthenticationProviders.DefaultPasswordProviderId, alice.AuthenticationProviderId);
        Assert.Equal(SsoAuthenticationProviders.DefaultPasswordProviderId, root.AuthenticationProviderId);
    }

    [Fact]
    public async Task DesignateBreakGlassAdmin_NonAdminTarget_ReturnsBadRequest()
    {
        var harness = new SsoControllerHarness();
        var alice = SeedPasswordUser(harness, "alice", AliceId);
        harness.UserManager.GetUsers().Returns(new[] { alice });

        var result = await harness.Controller.DesignateBreakGlassAdmin("alice");

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.True(string.IsNullOrEmpty(SSOPlugin.Instance.ReadConfiguration(c => c.BreakGlassAdminUsername)));
    }

    [Fact]
    public async Task ImportConfig_AssertingSsoOnly_WithNoSafeAdmin_ReturnsBadRequest()
    {
        // The guard fires on the import persistence path too (T-T2): a document turning SSO-only on with no
        // provable safe admin is rejected, and nothing is persisted.
        var harness = new SsoControllerHarness();
        var document = new ConfigExportDocument
        {
            FormatVersion = ConfigExport.FormatVersion,
            Configuration = new PluginConfiguration { DisablePasswordLogin = true, BreakGlassAdminUsername = "ghost" },
        };

        var result = harness.Controller.ImportConfig(document);

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.DisablePasswordLogin));
    }

    private static User SeedPasswordAdmin(SsoControllerHarness harness, string name, Guid id)
    {
        var user = SeedPasswordUser(harness, name, id);
        user.SetPermission(PermissionKind.IsAdministrator, true);
        return user;
    }

    private static User SeedPasswordUser(SsoControllerHarness harness, string name, Guid id)
    {
        var user = new User(name, "SSO-Auth", "Default") { Id = id, Password = "hash-" + name };
        user.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        harness.UserManager.GetUserByName(name).Returns(user);
        harness.UserManager.GetUserById(id).Returns(user);
        return user;
    }
}
