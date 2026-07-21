using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Direct tests of <see cref="CanonicalLinkService"/> — the account-linking workflow extracted from the
/// controller (#318). The service is constructible without a plugin instance (its config lives behind a
/// <see cref="ProviderConfigStore"/> built over an in-memory <see cref="PluginConfiguration"/>), so these
/// pin the resolve/adopt/create/reject decision, the legacy-key migration (#155), and the revoke loop as
/// unit tests — including the account-takeover reject path (#95), which no controller test exercised today.
/// </summary>
public class CanonicalLinkServiceTests
{
    private static readonly Guid Existing = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Other = Guid.Parse("22222222-2222-2222-2222-222222222222");


    private static User AdminUserNamed(string name, Guid id)
    {
        var user = TestUsers.Named(name, id);
        user.SetPermission(PermissionKind.IsAdministrator, true);
        return user;
    }

    private static (CanonicalLinkService Service, PluginConfiguration Config, IUserManager Users, CapturingLogger Log) Build(Action<PluginConfiguration>? seed = null)
    {
        var cfg = new PluginConfiguration();
        seed?.Invoke(cfg);
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var users = Substitute.For<IUserManager>();
        var log = new CapturingLogger();

        // Inject a FRESH legacy-link-warning gate per service so the process-wide static gate (#362) never
        // leaks its cursor across cases: a fresh gate starts at MinValue, so the single warning each of the
        // legacy-link tests provokes always enters. The dedicated throttle test below drives its own gate +
        // fake clock to pin the once-per-interval bound.
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, log, new IntervalGate(TimeSpan.FromMinutes(1)));
        return (service, cfg, users, log);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LiveSubjectLink_ReusesItWithoutCreating()
    {
        var (service, _, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Existing, resolved);
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task ResolveOrCreateAsync_NoLinkNoAccount_CreatesAndLinksOnTheSubjectKey()
    {
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var created = TestUsers.Named("alice", Other);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Other).Returns(created);

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Other, resolved);
        await users.Received(1).CreateUserAsync("alice");
        Assert.Equal(Other, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ProvisionDisabled_NewAccount_CreatesItDisabledAndPersists()
    {
        // #737: with the policy on, a brand-new account is created disabled and PERSISTED here (the deferred
        // path short-circuits before the minter, so it must persist the inert account itself), it is audited
        // once at the provisioning event, and it is then reported as awaiting approval so the completion path
        // refuses the login.
        var (service, cfg, users, log) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var created = TestUsers.Named("alice", Other);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Other).Returns(created);

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisionDisabled: true);

        Assert.Equal(Other, resolved);
        Assert.True(created.HasPermission(PermissionKind.IsDisabled)); // created inert
        await users.Received(1).UpdateUserAsync(created); // and persisted (the normal path leaves this to the minter)
        Assert.True(service.IsAccountAwaitingApproval(Other)); // so the login is refused downstream
        Assert.Equal(Other, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]); // still linked, so a re-login resolves it
        Assert.Single(log.Entries, e => e.Message.Contains("provisioned pending approval", StringComparison.OrdinalIgnoreCase)); // audited once
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ProvisionDisabled_PersistFails_RollsBackTheAccountAndFailsClosed()
    {
        // #737 fail-closed: if persisting the disabled flag throws, the just-created account must not survive
        // ENABLED and link-less (a later login could adopt it and mint a session). It is deleted, the login
        // fails closed (the failure propagates), and no canonical link is written.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var created = TestUsers.Named("alice", Other);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Other).Returns(created);
        users.When(u => u.UpdateUserAsync(created)).Do(_ => throw new InvalidOperationException("db down"));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisionDisabled: true));

        await users.Received(1).DeleteUserAsync(Other); // rolled back — no enabled orphan survives
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1")); // and never linked
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LiveLinkToDisabledAccount_ResolvesWithoutReAuditingProvisioning()
    {
        // The provisioning audit fires only at the create event, never on a later login of the now-pending
        // account: resolving a live link to an already-disabled user emits no "provisioned pending" line.
        var (service, _, users, log) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });
        var pending = TestUsers.Named("alice", Existing);
        pending.SetPermission(PermissionKind.IsDisabled, true);
        users.GetUserById(Existing).Returns(pending);

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisionDisabled: true);

        Assert.Equal(Existing, resolved);
        Assert.True(service.IsAccountAwaitingApproval(Existing)); // still refused downstream
        Assert.DoesNotContain(log.Entries, e => e.Message.Contains("provisioned pending approval", StringComparison.OrdinalIgnoreCase));
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task ResolveOrCreateAsync_NewAccount_PolicyOff_IsCreatedEnabledAndNotPersistedHere()
    {
        // Default (policy off): the new account is NOT disabled and is NOT persisted by the linking layer —
        // the session minter persists it, exactly as before #737. No behavior change for existing deployments.
        var (service, _, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var created = TestUsers.Named("alice", Other);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Other).Returns(created);

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Other, resolved);
        Assert.False(created.HasPermission(PermissionKind.IsDisabled));
        await users.DidNotReceive().UpdateUserAsync(Arg.Any<User>());
        Assert.False(service.IsAccountAwaitingApproval(Other));
    }

    [Fact]
    public void IsAccountAwaitingApproval_DisabledUser_True_EnabledUser_False_MissingUser_False()
    {
        var (service, _, users, _) = Build();
        var disabled = TestUsers.Named("alice", Existing);
        disabled.SetPermission(PermissionKind.IsDisabled, true);
        users.GetUserById(Existing).Returns(disabled);
        users.GetUserById(Other).Returns(TestUsers.Named("bob", Other)); // enabled
        users.GetUserById(Arg.Is<Guid>(g => g != Existing && g != Other)).Returns((User?)null); // missing

        Assert.True(service.IsAccountAwaitingApproval(Existing));
        Assert.False(service.IsAccountAwaitingApproval(Other));
        Assert.False(service.IsAccountAwaitingApproval(Guid.NewGuid())); // a vanished user is left to the minter's null guard
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ExistingAccountAndAdoptionAllowed_AdoptsAndLinks()
    {
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true);

        Assert.Equal(Existing, resolved);
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
        Assert.Equal(Existing, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ExistingAccountButAdoptionDisabled_RefusesWithoutCreatingOrLinking()
    {
        // The account-takeover guard (#95): a login whose name matches a pre-existing unlinked account,
        // with adoption off, must be refused — not silently take the account over. No controller test
        // reached this path before the extraction; this pins it directly.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1"));
    }

    [Theory]
    [InlineData("", "alice")]
    [InlineData("   ", "alice")]
    [InlineData("sub-1", "")]
    [InlineData("sub-1", "  ")]
    public async Task ResolveOrCreateAsync_UnresolvedIdentity_FailsClosedWithoutCreating(string canonicalKey, string username)
    {
        // Fail-closed belt (#95/#155): a blank identity key or username must never create, adopt, or
        // look up an account, even if a caller forgets its own guard.
        var (service, _, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", canonicalKey, username, allowExistingAccountLink: true));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LegacyNameKeyedOidLink_WithAdoptionAllowed_MigratesToTheSubjectKey()
    {
        // #155: an OpenID login with only a legacy username-keyed link adopts and re-keys it to the
        // stable subject, so a later provider-side rename cannot detach it. The legacy key is the
        // mutable username, so this name-based hand-off requires AllowExistingAccountLink (#354).
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true);

        Assert.Equal(Existing, resolved);
        var links = cfg.OidConfigs["kc"].CanonicalLinks;
        Assert.Equal(Existing, links["sub-1"]);
        Assert.False(links.ContainsKey("alice")); // the legacy key is gone
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LegacyLinkButAdoptionDisabled_RefusesAndMigratesNothing()
    {
        // The account-takeover characterization (#354, CWE-287): preferred_username is chosen at the
        // identity provider, so a login with a foreign sub and a victim's name as preferred_username
        // must NOT be handed the account the legacy name-keyed entry points at while adoption is off.
        // The entry stays untouched: no migration, no link under the attacker's sub.
        var (service, cfg, users, log) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "attacker-sub", "alice", allowExistingAccountLink: false));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
        var links = cfg.OidConfigs["kc"].CanonicalLinks;
        Assert.Equal(Existing, links["alice"]); // the legacy entry is untouched
        Assert.False(links.ContainsKey("attacker-sub"));

        // The operator breadcrumb, emitted at the terminal refusal (not pre-gate): it marks this 403
        // as a migratable pending-legacy-link case, distinct from an ordinary name collision. Exactly
        // one warning fires for the reject path (no pre-gate double-log).
        var warnings = log.Entries.FindAll(e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning);
        Assert.Single(warnings);
        Assert.Contains("legacy username-keyed link", warnings[0].Message, StringComparison.Ordinal);
        Assert.Contains("refused", warnings[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LegacyLinkAdoptionDisabledAndNameFree_CreatesNewInsteadOfFollowingIt()
    {
        // With adoption off and no live account under the login's name (e.g. the linked user was
        // renamed), the ignored legacy entry must not resolve either: the login provisions a fresh
        // account and the foreign entry survives for its real owner to migrate later (#354).
        var (service, cfg, users, log) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("renamed-alice", Existing));
        users.GetUserByName("alice").Returns((User?)null);
        var created = TestUsers.Named("alice", Other);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Other).Returns(created);

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "attacker-sub", "alice", allowExistingAccountLink: false);

        Assert.Equal(Other, resolved);
        await users.Received(1).CreateUserAsync("alice");
        var links = cfg.OidConfigs["kc"].CanonicalLinks;
        Assert.Equal(Existing, links["alice"]); // the legacy entry is untouched
        Assert.Equal(Other, links["attacker-sub"]); // the fresh account is linked under the login's own sub

        // CR#1 on #358: this is a SUCCESSFUL login that silently orphans the original account, so it
        // must emit its own accurate warning (not mislabeled "refused"). Exactly one warning, naming
        // the orphaning.
        var warnings = log.Entries.FindAll(e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning);
        Assert.Single(warnings);
        Assert.Contains("orphaned", warnings[0].Message, StringComparison.Ordinal);
        Assert.DoesNotContain("refused", warnings[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_PendingLegacyLinkWarning_IsThrottledToOncePerInterval()
    {
        // #362 (CWE-400, log-volume): the terminal pending-legacy-link warning must be bounded to one line
        // per interval so a hot login loop for a not-yet-migrated user cannot flood the log. The reject
        // branch is idempotent (it throws and writes nothing), so repeating the same login re-enters the
        // warning site every time — exactly the loop the gate must throttle. A fresh gate + a fake clock the
        // test advances pins the once-per-interval bound deterministically, and the refusal must still throw
        // on every attempt regardless of whether the line is emitted.
        var cfg = new PluginConfiguration();
        cfg.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        };
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var users = Substitute.For<IUserManager>();
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));
        var log = new CapturingLogger();

        var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var service = new CanonicalLinkService(
            users,
            new FakeCryptoProvider(),
            store,
            log,
            new IntervalGate(TimeSpan.FromMinutes(1)),
            () => now);

        async Task AttemptRefusedLogin() =>
            await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
                service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "attacker-sub", "alice", allowExistingAccountLink: false));

        int LegacyWarnings() => log.Entries
            .FindAll(e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning
                && e.Message.Contains("legacy username-keyed link", StringComparison.Ordinal))
            .Count;

        // Three refused logins inside one interval: the first enters the gate, the next two are throttled.
        await AttemptRefusedLogin();
        now = now.AddSeconds(10);
        await AttemptRefusedLogin();
        now = now.AddSeconds(49); // t0 + 59s, still within the 1-minute interval
        await AttemptRefusedLogin();
        Assert.Equal(1, LegacyWarnings());

        // Past the interval, one more login re-opens the gate: a second line, so the signal still surfaces
        // periodically for triage rather than being suppressed forever.
        now = now.AddSeconds(2); // t0 + 61s
        await AttemptRefusedLogin();
        Assert.Equal(2, LegacyWarnings());
    }

    [Fact]
    public async Task ResolveOrCreateAsync_FlagOnRenamedLegacyOwner_DoesNotHandOverTheRenamedAccount()
    {
        // The #361 fix (residual surfaced on #358): with the flag on, a legacy name-keyed link whose
        // target was renamed away from the presented name must NOT be followed — otherwise a login with a
        // foreign sub and the pre-rename name is handed the renamed account and re-keys it (a stale-name
        // superset of same-name adoption, CWE-287). No live account bears "oldname", so the login instead
        // provisions a FRESH account under its own sub; the renamed victim's account and the legacy entry
        // are left untouched, and the orphan warning fires.
        var (service, cfg, users, log) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["oldname"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("newname", Existing));
        users.GetUserByName("oldname").Returns((User?)null); // renamed: no live account bears the key
        var created = TestUsers.Named("oldname", Other);
        users.CreateUserAsync("oldname").Returns(created);
        users.GetUserById(Other).Returns(created);

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "attacker-sub", "oldname", allowExistingAccountLink: true);

        Assert.Equal(Other, resolved); // a fresh account, NOT the renamed victim (Existing)
        await users.Received(1).CreateUserAsync("oldname");
        var links = cfg.OidConfigs["kc"].CanonicalLinks;
        Assert.Equal(Existing, links["oldname"]); // the legacy entry is untouched, not re-keyed
        Assert.Equal(Other, links["attacker-sub"]); // the fresh account is linked under the login's own sub

        // The orphan warning fires (the legacy link is now stale), not mislabeled a "refused" login.
        var warnings = log.Entries.FindAll(e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning);
        Assert.Single(warnings);
        Assert.Contains("orphaned", warnings[0].Message, StringComparison.Ordinal);
        Assert.DoesNotContain("refused", warnings[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_FlagOnRenamedLegacyOwner_NameNowHeldByAnother_AdoptsTheCurrentHolderNotTheVictim()
    {
        // The #361 fix, the case where a DIFFERENT account has since taken the pre-rename name: the legacy
        // link still points at the renamed victim (Existing), but the account currently named "oldname" is
        // a third party (Other). The stale legacy key must not be followed; the login falls through to
        // ordinary same-name adoption of the CURRENT holder (Other), never the renamed victim (Existing).
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["oldname"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("newname", Existing)); // the victim, renamed away
        users.GetUserByName("oldname").Returns(TestUsers.Named("oldname", Other)); // a different account now holds the name
        users.GetUserById(Other).Returns(TestUsers.Named("oldname", Other));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "attacker-sub", "oldname", allowExistingAccountLink: true);

        Assert.Equal(Other, resolved); // adopts the current name-holder, NOT the renamed victim (Existing)
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
        var links = cfg.OidConfigs["kc"].CanonicalLinks;
        Assert.Equal(Existing, links["oldname"]); // the victim's legacy entry is untouched
        Assert.Equal(Other, links["attacker-sub"]); // the adopted (current-holder) account is linked under the sub
    }

    [Fact]
    public async Task ResolveOrCreateAsync_SubFallbackShape_NeverEngagesTheLegacyArm()
    {
        // The opaque-sub / sub-fallback provider shape (e.g. Google without preferred_username):
        // the username IS the sub, so canonicalKey == username, the inequality guard keeps the
        // legacy arm structurally dormant, and the link resolves subject-keyed with no migration —
        // independent of AllowExistingAccountLink, proving no name trust is involved.
        var (service, cfg, users, log) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["opaque-sub-123"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "opaque-sub-123", "opaque-sub-123", allowExistingAccountLink: false);

        Assert.Equal(Existing, resolved);
        Assert.Equal(Existing, cfg.OidConfigs["kc"].CanonicalLinks["opaque-sub-123"]); // untouched, not re-keyed
        Assert.DoesNotContain(log.Entries, e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ProviderDeletedMidLogin_FailsClosedWithoutCreating()
    {
        // TOCTOU (#373 review): the controller resolves the provider, then this runs. If an admin
        // deletes the provider in that window, the links map is absent — the login must fail CLOSED
        // (refuse), never fall through to the adoption gate whose create/adopt arms would mint a
        // session for a provider that no longer exists.
        var (service, _, users, _) = Build(); // no provider configured
        users.GetUserByName("alice").Returns((User?)null); // name is free -> the create arm would fire

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "deleted-provider", "sub-1", "alice", allowExistingAccountLink: true));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ProviderDeletedBetweenReadAndMigrate_FailsClosed()
    {
        // The legacy-migration path runs a second transaction (the re-key) after the read that resolved
        // the candidate. If the provider is deleted in that window, migration must fail CLOSED too, not
        // no-op and let the already-resolved legacy user through UseExistingLink for a gone provider
        // (#373). Simulated deterministically: drop the provider right before the migrate transaction.
        var cfg = new PluginConfiguration();
        cfg.OidConfigs["kc"] = new OidConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing } };
        var users = Substitute.For<IUserManager>();
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));

        // The first store access is the candidate-resolving Read; the second is the migrate Mutate.
        // Removing the provider on the second access reproduces an admin delete racing the login.
        var access = 0;
        var store = new ProviderConfigStore(
            () =>
            {
                if (++access == 2)
                {
                    cfg.OidConfigs.Remove("kc");
                }

                return cfg;
            },
            _ => { },
            new CapturingLogger());
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());

        var ex = await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true));

        // Pin the MIGRATE guard specifically, not just any fail-closed throw: the three login-path guards
        // carry distinct messages, so if the provider were dropped during the wrong transaction the test
        // would silently cover a different guard. This asserts the migrate transaction is the one that
        // refused.
        Assert.Contains("refusing to migrate the account link", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LiveSubjectLink_PersistsNothing()
    {
        // #363 guard: an ordinary login that resolves an existing subject-keyed link must stay a pure
        // read. Folding the legacy migration into the resolution must NOT turn every login into a config
        // persist — the common (no-migration) path writes nothing, so the fold cannot regress the hot
        // path into an always-mutate.
        var cfg = new PluginConfiguration();
        cfg.OidConfigs["kc"] = new OidConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing } };
        var users = Substitute.For<IUserManager>();
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        var persists = 0;
        var store = new ProviderConfigStore(() => cfg, _ => persists++, new CapturingLogger());
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Existing, resolved);
        Assert.Equal(0, persists); // no write on the hot path
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LegacyMigration_PersistsExactlyOnce()
    {
        // #363: the legacy re-key is folded into a SINGLE config transaction, so a migrating login
        // persists exactly once — not the two write-capable lock acquisitions the pre-fold read-then-
        // migrate pattern implied. The link ends up subject-keyed and the login binds to the migrated user.
        var cfg = new PluginConfiguration();
        cfg.OidConfigs["kc"] = new OidConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing } };
        var users = Substitute.For<IUserManager>();
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));
        var persists = 0;
        var store = new ProviderConfigStore(() => cfg, _ => persists++, new CapturingLogger());
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true);

        Assert.Equal(Existing, resolved);
        Assert.Equal(1, persists); // one mutation for the migration, not two
        var links = cfg.OidConfigs["kc"].CanonicalLinks;
        Assert.Equal(Existing, links["sub-1"]);
        Assert.False(links.ContainsKey("alice"));
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ConcurrentLoginMigratedBeforeReKey_BindsToTheWinnerWithoutOverwriting()
    {
        // #363, the window the fold closes: the candidate-resolving read sees only the legacy key, but a
        // concurrent login for the SAME identity commits its migration (subject key now live, legacy key
        // gone) before this login's re-key transaction runs. The re-key transaction re-resolves the
        // candidates authoritatively and binds to the winner's live subject link WITHOUT overwriting it —
        // one winner, no double-write, and no stale pre-migration snapshot driving the outcome.
        var cfg = new PluginConfiguration();
        cfg.OidConfigs["kc"] = new OidConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing } };
        var users = Substitute.For<IUserManager>();
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));

        // Access 1 is the candidate-resolving Read; access 2 is the migrate Mutate. Interposing the
        // concurrent winner's committed migration right before the second access reproduces the race
        // deterministically — exactly the interpose the two former separate lock acquisitions allowed.
        var access = 0;
        var store = new ProviderConfigStore(
            () =>
            {
                if (++access == 2)
                {
                    var live = cfg.OidConfigs["kc"].CanonicalLinks;
                    live.Remove("alice");
                    live["sub-1"] = Existing; // the concurrent winner already re-keyed to the subject
                }

                return cfg;
            },
            _ => { },
            new CapturingLogger());
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true);

        Assert.Equal(Existing, resolved); // bound to the winner's live subject link
        var final = cfg.OidConfigs["kc"].CanonicalLinks;
        Assert.Equal(Existing, final["sub-1"]); // not overwritten
        Assert.False(final.ContainsKey("alice")); // the winner's re-key stands
    }

    // --- Admin surface: TryCreateLink / TryRemoveLink / LinksByUser (#372, finishing #241) ---

    [Fact]
    public void TryCreateLink_KnownProvider_WritesTheLinkAndReturnsCreated()
    {
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = service.TryCreateLink(ProviderMode.Oid, "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkWriteResult.Created, result);
        Assert.Equal(Existing, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void TryCreateLink_EmptyKey_ReturnsEmptyKey_WithoutWriting(string providerUserId)
    {
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = service.TryCreateLink(ProviderMode.Oid, "kc", providerUserId, Existing);

        Assert.Equal(CanonicalLinkWriteResult.EmptyKey, result);
        Assert.Empty(cfg.OidConfigs["kc"].CanonicalLinks);
    }

    [Fact]
    public void TryCreateLink_UnknownProvider_ReturnsUnknownProvider()
    {
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = service.TryCreateLink(ProviderMode.Oid, "does-not-exist", "sub-1", Existing);

        Assert.Equal(CanonicalLinkWriteResult.UnknownProvider, result);
    }

    [Fact]
    public void TryCreateLink_EmptyKeyAndUnknownProvider_ReturnsEmptyKey_NotUnknownProvider()
    {
        // The two refusals map to DIFFERENT response bodies, so the order is observable: an unresolved
        // identity is reported as EmptyKey even when the provider is also unknown (the empty-key guard
        // runs first). Locks the check ordering the controller's distinct 400 bodies depend on.
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = service.TryCreateLink(ProviderMode.Oid, "does-not-exist", "   ", Existing);

        Assert.Equal(CanonicalLinkWriteResult.EmptyKey, result);
    }

    [Fact]
    public void TryCreateLink_ExistingKey_RebindsItToTheNewUser()
    {
        // Deliberate admin capability (pinned so the last-writer-wins semantics are not changed by
        // accident): re-linking an already-linked provider identity to a different Jellyfin user
        // silently overwrites the prior binding — an admin correcting a mis-link, not a defect.
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });

        var result = service.TryCreateLink(ProviderMode.Oid, "kc", "sub-1", Other);

        Assert.Equal(CanonicalLinkWriteResult.Created, result);
        Assert.Equal(Other, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]); // rebound to the new user
    }

    [Fact]
    public async Task ResolveOrCreateAsync_NullConfigProvider_FailsClosedWithoutCreating()
    {
        // The login-path companion to the admin null-config guards: a provider stored as a null config
        // object (reachable via #350) must REJECT the login (fail closed), never fall through to the
        // adoption gate whose create/adopt arms would mint a session for an unusable provider.
        var (service, _, users, _) = Build(c => c.OidConfigs["broken"] = null!);
        users.GetUserByName("alice").Returns((User?)null); // name is free -> the create arm would fire if it fell through

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "broken", "sub-1", "alice", allowExistingAccountLink: true));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public void TryRemoveLink_NullConfigProvider_FailsClosedAsUnknownProvider()
    {
        // A provider stored with a null config object (reachable via #350's null-body add) must be read
        // as absent, not dereferenced into a 500 — same fail-closed treatment as a missing provider.
        var (service, _, _, _) = Build(c => c.OidConfigs["broken"] = null!);

        var result = service.TryRemoveLink(ProviderMode.Oid, "broken", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.UnknownProvider, result.Result);
    }

    [Fact]
    public void LinksByUser_SkipsNullConfigProviders_WithoutThrowing()
    {
        // The read-side companion to the guard above: a null-valued provider entry is skipped, so listing
        // a user's links cannot NRE into a 500 on the #350 state.
        var (service, _, _, _) = Build(c =>
        {
            c.OidConfigs["kc"] = new OidConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing } };
            c.OidConfigs["broken"] = null!;
        });

        var oid = service.LinksByUser(ProviderMode.Oid, Existing);

        Assert.Equal(new[] { "sub-1" }, oid["kc"]);
        Assert.DoesNotContain("broken", oid.Keys); // the null-config provider is skipped, not thrown on
    }

    [Fact]
    public void DisabledProvider_LinksStayListedAndRemovable()
    {
        // The linking page no longer offers a disabled provider for new links (#344), but a link the
        // user already holds to one must stay visible and removable — disable-then-clean-up is the
        // intended workflow. This pins the server contract the page now relies on: LinksByUser returns
        // the disabled provider's links, and TryRemoveLink removes them (requireEnabled:false), so the
        // enabled-only GetNames filter never strands a stale link.
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = false,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });

        var listed = service.LinksByUser(ProviderMode.Oid, Existing);
        Assert.Equal(new[] { "sub-1" }, listed["kc"]);

        var result = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Existing);
        Assert.Equal(CanonicalLinkRemoveResult.Removed, result.Result);
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void TryRemoveLink_OwnLink_RemovesItAndReturnsRemoved()
    {
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });

        var result = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, result.Result);
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void TryRemoveLink_SamlOwnLink_RemovesItAndReturnsRemoved()
    {
        // The SAML branch of the admin surface (mode "saml") was covered only indirectly; pin it
        // directly, since TryGetLinks dispatches saml vs oid to different config dictionaries.
        var (service, cfg, _, _) = Build(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });

        var result = service.TryRemoveLink(ProviderMode.Saml, "adfs", "alice", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, result.Result);
        Assert.False(cfg.SamlConfigs["adfs"].CanonicalLinks.ContainsKey("alice"));
    }

    [Fact]
    public void TryRemoveLink_RemovingTheUsersLastLink_ReportsNoRemainingLink()
    {
        // #468: removing the user's only canonical link leaves them unable to SSO at all, so the removal
        // reports UserRetainsAnyLink=false — the signal the controller uses to revoke live tokens.
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });

        var result = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, result.Result);
        Assert.False(result.UserRetainsAnyLink);
    }

    [Fact]
    public void TryRemoveLink_UserKeepsALinkOnAnotherProvider_ReportsRemainingLink()
    {
        // #468: the user still holds a link on a DIFFERENT provider (even a different protocol), so they can
        // still SSO in — the removal reports UserRetainsAnyLink=true, and the controller must NOT revoke
        // (avoiding a self-inflicted mass-logout of a healthy multi-link user).
        var (service, _, _, _) = Build(c =>
        {
            c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
            };
            c.SamlConfigs["adfs"] = new SamlConfig
            {
                Enabled = true,
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
            };
        });

        var result = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, result.Result);
        Assert.True(result.UserRetainsAnyLink);
    }

    [Fact]
    public void TryRemoveLink_UserKeepsASecondLinkOnTheSameProvider_ReportsRemainingLink()
    {
        // #468: two identities on the same provider point at the same user; removing one leaves the other,
        // so the user keeps SSO access and the removal reports UserRetainsAnyLink=true.
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing, ["sub-2"] = Existing },
        });

        var result = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, result.Result);
        Assert.True(result.UserRetainsAnyLink);
    }

    [Fact]
    public void TryRemoveLink_AnotherUsersRemainingLink_DoesNotCountAsThisUsersRemainder()
    {
        // #468: the remainder is scoped to the UNLINKED user's id — a different user's surviving link on the
        // same provider must not be read as this user retaining SSO access, or the controller would skip a
        // required revoke (an under-revoke leaving the severed identity's tokens alive).
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing, ["sub-other"] = Other },
        });

        var result = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, result.Result);
        Assert.False(result.UserRetainsAnyLink);
    }

    [Fact]
    public void TryRemoveLink_UnknownCanonicalName_ReturnsNotFound()
    {
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = service.TryRemoveLink(ProviderMode.Oid, "kc", "does-not-exist", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.NotFound, result.Result);
    }

    [Fact]
    public void TryRemoveLink_LinkedToDifferentUser_ReturnsMismatch_WithoutRemoving()
    {
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });

        var result = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Other);

        Assert.Equal(CanonicalLinkRemoveResult.Mismatch, result.Result);
        Assert.Equal(Existing, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]); // untouched
    }

    [Fact]
    public void TryRemoveLink_UnknownProvider_ReturnsUnknownProvider()
    {
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = service.TryRemoveLink(ProviderMode.Oid, "does-not-exist", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.UnknownProvider, result.Result);
    }

    [Fact]
    public void LinksByUser_ReturnsOnlyTheUsersKeys_PerProvider_AsADetachedSnapshot()
    {
        var (service, cfg, _, _) = Build(c =>
        {
            c.OidConfigs["kc"] = new OidConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing, ["sub-2"] = Other } };
            c.OidConfigs["authelia"] = new OidConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-3"] = Existing } };
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing } };
        });

        var oid = service.LinksByUser(ProviderMode.Oid, Existing);

        Assert.Equal(new[] { "sub-1" }, oid["kc"]); // the other user's sub-2 is excluded
        Assert.Equal(new[] { "sub-3" }, oid["authelia"]);
        Assert.DoesNotContain("adfs", oid.Keys); // SAML provider is not in the OID projection

        // The projection is materialized (ToList, #157/F-10), not a deferred query over the live map:
        // a subsequent write to the source must not appear in the already-returned result, or a JSON
        // serialization could enumerate the live dictionary and tear against a concurrent login.
        cfg.OidConfigs["kc"].CanonicalLinks["sub-9"] = Existing;
        Assert.Equal(new[] { "sub-1" }, oid["kc"]);
    }

    [Fact]
    public void LinksByUser_Saml_ReturnsTheUsersKeys_AndExcludesOidProviders()
    {
        // The SAML projection (mode "saml") reads the SAML config dictionary, and must not fold in OID
        // providers — the mirror of the OID test above, pinning the saml branch directly.
        var (service, _, _, _) = Build(c =>
        {
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing, ["bob"] = Other } };
            c.OidConfigs["kc"] = new OidConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing } };
        });

        var saml = service.LinksByUser(ProviderMode.Saml, Existing);

        Assert.Equal(new[] { "alice" }, saml["adfs"]); // the other user's "bob" is excluded
        Assert.DoesNotContain("kc", saml.Keys); // OID provider is not in the SAML projection
    }

    [Fact]
    public void RemoveUserEverywhere_RemovesTheUsersLinksAcrossAllProviders_AndCountsThem()
    {
        var (service, cfg, _, _) = Build(c =>
        {
            c.OidConfigs["kc"] = new OidConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing, ["sub-2"] = Other } };
            c.SamlConfigs["adfs"] = new SamlConfig { Enabled = true, CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing } };
        });

        var removed = service.RemoveUserEverywhere(Existing);

        Assert.Equal(2, removed); // one OID link + one SAML link
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1"));
        Assert.True(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-2")); // the other user's link survives
        Assert.False(cfg.SamlConfigs["adfs"].CanonicalLinks.ContainsKey("alice"));
    }

    // --- IsIdentityStillLinked (#232): the in-flight revocation gate re-checked just before the mint ---

    [Fact]
    public void IsIdentityStillLinked_LiveEnabledLink_ReturnsTrue()
    {
        var (service, _, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        Assert.True(service.IsIdentityStillLinked(ProviderMode.Oid, "kc", "sub-1", Existing));
    }

    [Fact]
    public void IsIdentityStillLinked_SamlLiveEnabledLink_ReturnsTrue()
    {
        // Both protocols share the gate; SAML keys on the NameID.
        var (service, _, users, _) = Build(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        Assert.True(service.IsIdentityStillLinked(ProviderMode.Saml, "adfs", "alice", Existing));
    }

    [Fact]
    public void IsIdentityStillLinked_AfterRevocation_ReturnsFalse()
    {
        // The #232 scenario: the link was resolved, then RemoveUserEverywhere (Unregister) removed it, so
        // the mint-time re-check now fails closed even though the user still exists.
        var (service, _, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        service.RemoveUserEverywhere(Existing);

        Assert.False(service.IsIdentityStillLinked(ProviderMode.Oid, "kc", "sub-1", Existing));
    }

    [Fact]
    public void IsIdentityStillLinked_ProviderDisabledMidFlight_ReturnsFalse()
    {
        // #380: a provider disabled between resolution and the mint fails the re-check, so the login
        // cannot mint with the provider's pre-disable settings.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        cfg.OidConfigs["kc"].Enabled = false;

        Assert.False(service.IsIdentityStillLinked(ProviderMode.Oid, "kc", "sub-1", Existing));
    }

    [Fact]
    public void IsIdentityStillLinked_UnknownProvider_ReturnsFalse()
    {
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        Assert.False(service.IsIdentityStillLinked(ProviderMode.Oid, "does-not-exist", "sub-1", Existing));
    }

    [Fact]
    public void IsIdentityStillLinked_UnknownKey_ReturnsFalse()
    {
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });

        Assert.False(service.IsIdentityStillLinked(ProviderMode.Oid, "kc", "sub-unknown", Existing));
    }

    [Fact]
    public void IsIdentityStillLinked_LinkedToADifferentUser_ReturnsFalse()
    {
        // Fail closed if the link now points at another user (e.g. the identity was re-linked): the
        // resolved user must still be the one the link names.
        var (service, _, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Other },
        });
        users.GetUserById(Other).Returns(TestUsers.Named("bob", Other));

        Assert.False(service.IsIdentityStillLinked(ProviderMode.Oid, "kc", "sub-1", Existing));
    }

    [Fact]
    public void IsIdentityStillLinked_DanglingLinkTargetDeleted_ReturnsFalse()
    {
        // A link whose target user was deleted is dead, not an identity — GetUserById returns null.
        var (service, _, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });
        users.GetUserById(Existing).Returns((User?)null);

        Assert.False(service.IsIdentityStillLinked(ProviderMode.Oid, "kc", "sub-1", Existing));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsIdentityStillLinked_EmptyOrWhitespaceKey_ReturnsFalse(string? canonicalKey)
    {
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        Assert.False(service.IsIdentityStillLinked(ProviderMode.Oid, "kc", canonicalKey, Existing));
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ProviderDisabled_RefusesLikeADeletedOne()
    {
        // #380: a provider disabled between the controller's Enabled gate and the service's read must be
        // rejected exactly like a deleted one — even a live subject link must not resolve, because the
        // mint would run with the provider's pre-disable settings.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = false,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
        Assert.Equal(Existing, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]); // link untouched
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ProviderDisabledBetweenResolveAndLinkWrite_RefusesWithoutLinking()
    {
        // #380, the race the issue names: the provider passes the resolve-read enabled, then is disabled
        // before the link-write transaction of the adopt arm. The write-side guard must reject rather
        // than persist a link (and mint) with the pre-disable settings. The flip runs inside the
        // GetUserByName stub, which the flow consults exactly between the two transactions.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        users.GetUserByName("alice").Returns(_ =>
        {
            cfg.OidConfigs["kc"].Enabled = false;
            return TestUsers.Named("alice", Existing);
        });

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true));

        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1")); // no link written
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ProviderDisabledBeforeLegacyMigration_RefusesInsteadOfMinting()
    {
        // #380 on the #155 legacy path: the candidate-resolving read passes enabled, then the provider
        // is disabled before the migration transaction. Without the guard the caller would still return
        // UseExistingLink and mint with pre-disable settings; with it the migration rejects and the
        // legacy key stays un-migrated. The flip runs inside the GetUserById stub, which the read
        // consults after its own guard has already passed. The name is still held by the legacy target
        // (GetUserByName -> Existing), so the #361 follow-gate lets the migrate be attempted — the point
        // this test exercises — rather than short-circuiting to a fresh account.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(_ =>
        {
            cfg.OidConfigs["kc"].Enabled = false;
            return TestUsers.Named("alice", Existing);
        });
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true));

        Assert.True(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("alice")); // not re-keyed
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void TryCreateLink_ProviderDisabled_ReturnsUnknownProviderWithoutWriting()
    {
        // Link creation is a GRANT of future login capability, so it takes the same disabled-is-absent
        // treatment as the login-path guards (#380): a provider disabled between the controller's Enabled
        // gate and this transaction must not gain a dormant link that would mint on re-enable.
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = false });

        var result = service.TryCreateLink(ProviderMode.Oid, "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkWriteResult.UnknownProvider, result);
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void TryRemoveLink_ProviderDisabled_StillRemoves()
    {
        // The admin paths deliberately keep working on a disabled provider (#380): disable-then-clean-up
        // is the normal workflow, so only absence maps to UnknownProvider there.
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = false,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });

        var result = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, result.Result);
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public async Task ResolveOrCreateAsync_AdoptionAllowed_AdminTarget_RefusedWithoutLinking()
    {
        // #218: an administrator account is the highest-value takeover target, so a name-based adoption
        // of one is always refused regardless of the verified-email gate — even with adoption enabled and
        // a fully verified login. The operator links an admin account explicitly via the admin endpoints.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        users.GetUserByName("admin").Returns(AdminUserNamed("admin", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "attacker-sub", "admin", allowExistingAccountLink: true, new AdoptionGate(RequireVerifiedEmail: true, EmailVerified: true)));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("attacker-sub"));
    }

    [Fact]
    public async Task ResolveOrCreateAsync_SamlAdoptionAllowed_AdminTarget_RefusedWithoutLinking()
    {
        // #218: the admin-adoption refusal is protocol-agnostic. SAML carries no email_verified claim
        // (AdoptionGate.None), but adopting an admin account by NameID is still refused.
        var (service, cfg, users, _) = Build(c => c.SamlConfigs["idp"] = new SamlConfig { Enabled = true });
        users.GetUserByName("admin").Returns(AdminUserNamed("admin", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Saml, "idp", "admin", "admin", allowExistingAccountLink: true, AdoptionGate.None));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
        Assert.False(cfg.SamlConfigs["idp"].CanonicalLinks.ContainsKey("admin"));
    }

    [Fact]
    public async Task ResolveOrCreateAsync_RequireVerifiedEmail_ClaimTrue_AdoptsNonAdmin()
    {
        // #218: with the verified-email gate on, a non-admin login carrying email_verified == true clears
        // it and adopts, keying the link on the stable subject as usual.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true, new AdoptionGate(RequireVerifiedEmail: true, EmailVerified: true));

        Assert.Equal(Existing, resolved);
        Assert.Equal(Existing, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]);
    }

    [Theory]
    [InlineData(false)] // email_verified == false
    [InlineData(null)]  // claim absent
    public async Task ResolveOrCreateAsync_RequireVerifiedEmail_ClaimFalseOrAbsent_RefusesWithoutLinking(bool? emailVerified)
    {
        // #218: with the gate on, an absent or false email_verified claim fails closed — no link, no
        // account, and the takeover-blocking 403 (AccountLinkForbiddenException) is thrown.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true, new AdoptionGate(RequireVerifiedEmail: true, EmailVerified: emailVerified)));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LegacyLinkToAdminAccount_RefusesInsteadOfMigrating()
    {
        // #218: the admin-adoption refusal also covers the #155 legacy re-key path — an attacker
        // presenting a NEW subject with an admin's preferred_username must not migrate the admin's legacy
        // username-keyed link onto their subject. Fail closed: no re-key, 403, legacy key untouched.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["admin"] = Existing },
        });
        users.GetUserById(Existing).Returns(AdminUserNamed("admin", Existing));
        users.GetUserByName("admin").Returns(AdminUserNamed("admin", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "attacker-sub", "admin", allowExistingAccountLink: true));

        var links = cfg.OidConfigs["kc"].CanonicalLinks;
        Assert.True(links.ContainsKey("admin"));       // legacy key not re-keyed
        Assert.False(links.ContainsKey("attacker-sub")); // attacker's subject not linked
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    // --- OpenID canonical-link issuer binding (#186) ---

    private const string OldIssuer = "https://old-idp.example";
    private const string NewIssuer = "https://new-idp.example";

    [Fact]
    public async Task ResolveOrCreateAsync_SubjectLinkStampedWithADifferentIssuer_RefusesFailClosed()
    {
        // The non-inert proof (#186, acceptance criterion 1): a subject-keyed link minted under one issuer
        // must NOT resolve when the login presents a different one (the provider was repointed at another
        // IdP behind the same discovery URL). The check FIRES at runtime and refuses — the prior review
        // rejected an inert take, so this is the load-bearing test. No takeover: the old account is not
        // handed to the new-IdP identity, and the stale link/issuer are left untouched for the admin.
        var (service, cfg, users, log) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["1"] = Existing },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["1"] = OldIssuer },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "1", "mallory", allowExistingAccountLink: false, issuer: NewIssuer));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
        Assert.Equal(Existing, cfg.OidConfigs["kc"].CanonicalLinks["1"]); // stale link untouched
        Assert.Equal(OldIssuer, cfg.OidConfigs["kc"].CanonicalLinkIssuers["1"]); // stored issuer untouched

        var warnings = log.Entries.FindAll(e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning);
        Assert.Single(warnings);
        Assert.Contains("issuer", warnings[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_SubjectLinkStampedWithTheSameIssuer_ReusesItWithoutWriting()
    {
        // The hot path stays pure (#186): a login whose issuer matches the stored one reuses the link and
        // writes nothing — the issuer binding adds no per-login persist once a link is stamped.
        var cfg = new PluginConfiguration();
        cfg.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-1"] = OldIssuer },
        };
        var users = Substitute.For<IUserManager>();
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        var persists = 0;
        var store = new ProviderConfigStore(() => cfg, _ => persists++, new CapturingLogger());
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, issuer: OldIssuer);

        Assert.Equal(Existing, resolved);
        Assert.Equal(0, persists); // matched binding = pure read, no write
    }

    [Fact]
    public async Task ResolveOrCreateAsync_UnstampedSubjectLink_TrustOnFirstUse_StampsAndProceeds()
    {
        // Transparent migration (#186, acceptance criterion 3): an existing link with NO stored issuer
        // (minted before this store) keeps working while the provider is unchanged AND gets stamped with the
        // current issuer on its first login — no lockout on upgrade, and the binding is in force from then on.
        var cfg = new PluginConfiguration();
        cfg.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        };
        var users = Substitute.For<IUserManager>();
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        var persists = 0;
        var store = new ProviderConfigStore(() => cfg, _ => persists++, new CapturingLogger());
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, issuer: OldIssuer);

        Assert.Equal(Existing, resolved);
        Assert.Equal(OldIssuer, cfg.OidConfigs["kc"].CanonicalLinkIssuers["sub-1"]); // stamped on first use
        Assert.Equal(1, persists); // exactly one write for the stamp
    }

    [Fact]
    public async Task ResolveOrCreateAsync_UnstampedSubjectLink_ThenRepointedIssuer_IsRefused()
    {
        // The end-to-end story: after trust-on-first-use stamps a link, a later login from a DIFFERENT issuer
        // is refused. Proves the stamp is what arms the binding (the same-URL-repoint case the belt cannot see).
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        // First login stamps the current issuer.
        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, issuer: OldIssuer);
        Assert.Equal(OldIssuer, cfg.OidConfigs["kc"].CanonicalLinkIssuers["sub-1"]);

        // A later login from a swapped IdP (same URL) is now refused.
        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, issuer: NewIssuer));
    }

    [Fact]
    public async Task ResolveOrCreateAsync_StampedSubjectLink_LoginWithNoIssuer_IsRefused()
    {
        // Bypass closed (#186): a token that omits `iss` (issuer resolves to null) must NOT slip past a
        // stamped binding — a null current issuer against a stored one is a mismatch, so the login is refused
        // rather than mapping onto the stamped account.
        var (service, _, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-1"] = OldIssuer },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, issuer: null));
    }

    [Fact]
    public async Task ResolveOrCreateAsync_CreateNewAccount_StampsTheLoginIssuer()
    {
        // A newly created account's link is issuer-bound at creation (#186), so it is protected from the
        // first login onward, not only after a later trust-on-first-use pass.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var created = TestUsers.Named("alice", Other);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Other).Returns(created);

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, issuer: NewIssuer);

        Assert.Equal(Other, resolved);
        Assert.Equal(NewIssuer, cfg.OidConfigs["kc"].CanonicalLinkIssuers["sub-1"]);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_AdoptExistingAccount_StampsTheLoginIssuer()
    {
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true, issuer: NewIssuer);

        Assert.Equal(Existing, resolved);
        Assert.Equal(NewIssuer, cfg.OidConfigs["kc"].CanonicalLinkIssuers["sub-1"]);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LegacyMigration_StampsIssuerOnTheSubjectKey()
    {
        // The re-keyed link (#155 legacy migration) is a fresh subject-keyed link written under this login,
        // so it is stamped with the login's issuer (#186) — the migrated link is issuer-bound like any other.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true, issuer: NewIssuer);

        Assert.Equal(Existing, resolved);
        var issuers = cfg.OidConfigs["kc"].CanonicalLinkIssuers;
        Assert.Equal(NewIssuer, issuers["sub-1"]);
        Assert.False(issuers.ContainsKey("alice")); // no issuer under the retired legacy key
    }

    [Fact]
    public async Task ResolveOrCreateAsync_NullIssuerOnUnstampedLink_LeavesItUnstamped_AndProceeds()
    {
        // A login that carries no issuer (SAML, or a non-conformant token) never stamps a blank value — the
        // link stays un-stamped rather than binding to nothing, and the login proceeds unchanged (#186).
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, issuer: null);

        Assert.Equal(Existing, resolved);
        Assert.Empty(cfg.OidConfigs["kc"].CanonicalLinkIssuers);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_Saml_IgnoresIssuerBinding()
    {
        // SAML is out of scope (#186): a SAML login resolves normally regardless of any issuer argument, and
        // SamlConfig carries no issuer map at all — the binding is OpenID only.
        var (service, cfg, users, _) = Build(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Saml, "adfs", "alice", "alice", allowExistingAccountLink: false, issuer: NewIssuer);

        Assert.Equal(Existing, resolved);
        Assert.Equal(Existing, cfg.SamlConfigs["adfs"].CanonicalLinks["alice"]);
    }

    [Fact]
    public void TryCreateLink_Oid_StampsTheIssuer()
    {
        // A manual OpenID link (the admin/self link redeem) is issuer-bound too (#186), so it is not left an
        // un-stamped TOFU candidate a repoint could exploit before its first login.
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var result = service.TryCreateLink(ProviderMode.Oid, "kc", "sub-1", Existing, issuer: NewIssuer);

        Assert.Equal(CanonicalLinkWriteResult.Created, result);
        Assert.Equal(NewIssuer, cfg.OidConfigs["kc"].CanonicalLinkIssuers["sub-1"]);
    }

    [Fact]
    public void TryRemoveLink_Oid_DropsTheIssuerEntry()
    {
        // Removing a link drops its issuer entry (#186), so a removed-then-recreated sub does not inherit a
        // stale binding and the issuer map does not accumulate orphans.
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-1"] = OldIssuer },
        });

        var result = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, result.Result);
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinkIssuers.ContainsKey("sub-1"));
    }

    [Fact]
    public void RemoveUserEverywhere_PrunesOrphanedIssuerEntries()
    {
        // Revoking a user's links also prunes any now-orphaned issuer entries (#186), so the map stays clean.
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing, ["sub-2"] = Other },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-1"] = OldIssuer, ["sub-2"] = NewIssuer },
        });

        service.RemoveUserEverywhere(Existing);

        var issuers = cfg.OidConfigs["kc"].CanonicalLinkIssuers;
        Assert.False(issuers.ContainsKey("sub-1")); // the revoked user's issuer entry is gone
        Assert.Equal(NewIssuer, issuers["sub-2"]); // the other user's binding survives
    }

    [Fact]
    public async Task ResolveOrCreateAsync_RequireVerifiedEmailOff_NonAdmin_AdoptsRegardlessOfClaim()
    {
        // #218: the default posture (gate off) is unchanged — a non-admin adoption proceeds with no
        // email_verified claim, so a conformant deployment already using AllowExistingAccountLink is not
        // silently locked out on upgrade.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Existing));
        users.GetUserById(Existing).Returns(TestUsers.Named("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true, new AdoptionGate(RequireVerifiedEmail: false, EmailVerified: null));

        Assert.Equal(Existing, resolved);
        Assert.Equal(Existing, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]);
    }
}
