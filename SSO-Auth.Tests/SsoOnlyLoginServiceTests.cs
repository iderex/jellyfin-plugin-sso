using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Behavioural suite for <see cref="SsoOnlyLoginService"/> (#165): the fail-closed activation guard, the
/// per-user provider-id enforcement sweep, and the lossless reversible off-switch. Uses a mocked
/// <c>IUserManager</c> and a real <see cref="ProviderConfigStore"/> over an in-memory configuration, so
/// each fail-closed branch and every "only the routing field changes" invariant is pinned as the design's
/// conformance tests require (SSO-ONLY-LOGIN-DESIGN.md §6/§7).
/// </summary>
public class SsoOnlyLoginServiceTests
{
    private static readonly Guid RootId = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid AliceId = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000002");
    private static readonly Guid SsoUserId = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000003");

    private static User PasswordAdmin(string name, Guid id)
    {
        var user = new User(name, "SSO-Auth", "Default") { Id = id, Password = "hash-" + name };
        user.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        user.SetPermission(PermissionKind.IsAdministrator, true);
        return user;
    }

    private static User PasswordUser(string name, Guid id)
    {
        var user = new User(name, "SSO-Auth", "Default") { Id = id, Password = "hash-" + name };
        user.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        return user;
    }

    private static User SsoOnlyUser(string name, Guid id)
    {
        // The shape CanonicalLinkService gives every account it creates: routed to the plugin's SSO provider
        // (no password door) with a random password. Born SSO-only, so the mode leaves it as-is.
        var user = new User(name, "SSO-Auth", "Default") { Id = id, Password = "random-64-bytes" };
        user.AuthenticationProviderId = SsoAuthenticationProviders.SsoProviderId;
        return user;
    }

    private static (SsoOnlyLoginService Service, PluginConfiguration Config, IUserManager Users) Build(
        IReadOnlyList<User> allUsers,
        Action<PluginConfiguration>? seed = null)
    {
        var cfg = new PluginConfiguration();
        seed?.Invoke(cfg);
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var users = Substitute.For<IUserManager>();
        users.GetUsers().Returns(allUsers);
        foreach (var user in allUsers)
        {
            users.GetUserByName(user.Username).Returns(user);
        }

        return (new SsoOnlyLoginService(users, store, new CapturingLogger()), cfg, users);
    }

    // --- Enable_allowed_when_a_break_glass_password_admin_exists ---

    [Fact]
    public async Task Enable_WithBreakGlassPasswordAdmin_Succeeds_AndPersistsFlag()
    {
        var root = PasswordAdmin("root", RootId);
        var (service, config, _) = Build(new[] { root });

        var outcome = await service.TryEnableAsync("root");

        Assert.Equal(SsoOnlyGuardVerdict.Allow, outcome.Verdict);
        Assert.True(config.DisablePasswordLogin);
        Assert.Equal("root", config.BreakGlassAdminUsername);
    }

    // --- Break_glass_admin_provider_id_never_repointed ---

    [Fact]
    public async Task Enable_BreakGlassAdminProviderId_NeverRepointed()
    {
        var root = PasswordAdmin("root", RootId);
        var alice = PasswordUser("alice", AliceId);
        var (service, _, users) = Build(new[] { root, alice });

        await service.TryEnableAsync("root");

        // The exempt admin keeps its password door untouched; every other password account is repointed.
        Assert.Equal(SsoAuthenticationProviders.DefaultPasswordProviderId, root.AuthenticationProviderId);
        Assert.Equal(SsoAuthenticationProviders.SsoProviderId, alice.AuthenticationProviderId);
        await users.DidNotReceive().UpdateUserAsync(root);
        await users.Received(1).UpdateUserAsync(alice);
    }

    // --- No_nonexempt_account_keeps_password_provider_while_mode_on ---

    [Fact]
    public async Task Enable_NoNonExemptAccountKeepsPasswordProvider()
    {
        var root = PasswordAdmin("root", RootId);
        var alice = PasswordUser("alice", AliceId);
        var born = SsoOnlyUser("carol", SsoUserId); // a natively-SSO (created) account, already password-less
        var all = new[] { root, alice, born };
        var (service, config, _) = Build(all);

        await service.TryEnableAsync("root");

        // The invariant across the whole userbase: no non-exempt account is left on the password provider
        // (T-S1). The break-glass admin is the sole deliberate residual door; the created account was never
        // on the password provider to begin with.
        foreach (var user in all)
        {
            if (SsoOnlyLoginGuard.IsBreakGlass(config, user.Username))
            {
                Assert.Equal(SsoAuthenticationProviders.DefaultPasswordProviderId, user.AuthenticationProviderId);
            }
            else
            {
                Assert.False(SsoAuthenticationProviders.IsDefaultPasswordProvider(user.AuthenticationProviderId));
            }
        }
    }

    // --- Disable_restores_default_provider_without_touching_password_hash ---

    [Fact]
    public async Task Disable_RestoresDefaultProvider_WithoutTouchingPasswordHash()
    {
        var root = PasswordAdmin("root", RootId);
        var alice = PasswordUser("alice", AliceId);
        var (service, config, _) = Build(new[] { root, alice });
        var aliceHashBefore = alice.Password;

        await service.TryEnableAsync("root");
        Assert.Equal(SsoAuthenticationProviders.SsoProviderId, alice.AuthenticationProviderId); // repointed

        var restored = await service.DisableAsync();

        Assert.False(config.DisablePasswordLogin);
        // The off-switch restores native password routing WITHOUT resetting the stored hash (T-E2/criterion 4).
        Assert.Equal(SsoAuthenticationProviders.DefaultPasswordProviderId, alice.AuthenticationProviderId);
        Assert.Equal(aliceHashBefore, alice.Password);
        Assert.Equal(1, restored);
    }

    // --- Enforcement_routine_touches_only_authentication_provider_id ---

    [Fact]
    public async Task Enable_EnforcementRoutine_TouchesOnlyAuthenticationProviderId()
    {
        var root = PasswordAdmin("root", RootId);
        var alice = PasswordUser("alice", AliceId);
        alice.SetPermission(PermissionKind.EnableAllFolders, true);
        var (service, _, _) = Build(new[] { root, alice });
        var passwordBefore = alice.Password;

        await service.TryEnableAsync("root");

        // Only the provider-routing field may change (T-E3): the password hash, the administrator flag, and
        // an unrelated permission are all left exactly as they were.
        Assert.Equal(SsoAuthenticationProviders.SsoProviderId, alice.AuthenticationProviderId);
        Assert.Equal(passwordBefore, alice.Password);
        Assert.False(alice.HasPermission(PermissionKind.IsAdministrator));
        Assert.True(alice.HasPermission(PermissionKind.EnableAllFolders));
    }

    // --- Enable_refused_when_no_admin_would_retain_a_login_path ---

    [Fact]
    public async Task Enable_NoBreakGlassDesignated_Refused_AndChangesNothing()
    {
        var alice = PasswordUser("alice", AliceId);
        var (service, config, users) = Build(new[] { alice });

        var outcome = await service.TryEnableAsync(string.Empty);

        Assert.Equal(SsoOnlyGuardVerdict.NoBreakGlassDesignated, outcome.Verdict);
        Assert.False(config.DisablePasswordLogin);
        Assert.Equal(SsoAuthenticationProviders.DefaultPasswordProviderId, alice.AuthenticationProviderId);
        await users.DidNotReceive().UpdateUserAsync(Arg.Any<User>());
    }

    // --- Guard_does_not_count_sso_link_on_disabled_or_deleted_provider ---

    [Fact]
    public async Task Enable_SoleAdminHasOnlySsoLink_Refused_GuardNeverCountsAnSsoLink()
    {
        // The only administrator is already routed to the SSO provider — its login depends entirely on the
        // IdP. Even with a live SSO canonical link (here on a DISABLED provider), the survivor guard never
        // counts it: only a password door qualifies (SSO-ONLY-LOGIN-DESIGN.md §3, T-D3/§7). So activation is
        // refused and nothing is persisted — exactly the lockout the guard exists to prevent.
        var admin = new User("root", "SSO-Auth", "Default") { Id = RootId, Password = "random" };
        admin.AuthenticationProviderId = SsoAuthenticationProviders.SsoProviderId;
        admin.SetPermission(PermissionKind.IsAdministrator, true);
        var (service, config, users) = Build(
            new[] { admin },
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = false,
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-root"] = RootId },
            });

        var outcome = await service.TryEnableAsync("root");

        Assert.Equal(SsoOnlyGuardVerdict.BreakGlassNoPasswordLogin, outcome.Verdict);
        Assert.False(config.DisablePasswordLogin);
        await users.DidNotReceive().UpdateUserAsync(Arg.Any<User>());
    }

    // --- Break_glass_designation_rejects_non_admin_target ---

    [Fact]
    public async Task DesignateBreakGlass_NonAdminTarget_Refused_AndDoesNotDesignate()
    {
        var root = PasswordAdmin("root", RootId);
        var alice = PasswordUser("alice", AliceId); // a non-admin
        var (service, config, _) = Build(new[] { root, alice });

        var outcome = await service.TryDesignateBreakGlassAsync("alice");

        // The exemption can never point at a non-administrator (T-E1) — it cannot grant admin.
        Assert.Equal(SsoOnlyGuardVerdict.BreakGlassNotAdministrator, outcome.Verdict);
        Assert.True(string.IsNullOrEmpty(config.BreakGlassAdminUsername));
    }

    [Fact]
    public async Task DesignateBreakGlass_EnabledPasswordAdmin_Succeeds()
    {
        var root = PasswordAdmin("root", RootId);
        var (service, config, _) = Build(new[] { root });

        var outcome = await service.TryDesignateBreakGlassAsync("root");

        Assert.Equal(SsoOnlyGuardVerdict.Allow, outcome.Verdict);
        Assert.Equal("root", config.BreakGlassAdminUsername);
        Assert.False(config.DisablePasswordLogin); // designation alone does not enable the mode
    }
}
