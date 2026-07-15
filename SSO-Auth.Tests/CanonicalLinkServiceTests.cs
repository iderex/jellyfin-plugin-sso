using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
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

    private static User UserNamed(string name, Guid id) => new User(name, "SSO-Auth", "Default") { Id = id };

    private static (CanonicalLinkService Service, PluginConfiguration Config, IUserManager Users, CapturingLogger Log) Build(Action<PluginConfiguration>? seed = null)
    {
        var cfg = new PluginConfiguration();
        seed?.Invoke(cfg);
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var users = Substitute.For<IUserManager>();
        var log = new CapturingLogger();
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, log);
        return (service, cfg, users, log);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LiveSubjectLink_ReusesItWithoutCreating()
    {
        var (service, _, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });
        users.GetUserById(Existing).Returns(UserNamed("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync("oid", "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Existing, resolved);
        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task ResolveOrCreateAsync_NoLinkNoAccount_CreatesAndLinksOnTheSubjectKey()
    {
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig());
        var created = UserNamed("alice", Other);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Other).Returns(created);

        var resolved = await service.ResolveOrCreateAsync("oid", "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Other, resolved);
        await users.Received(1).CreateUserAsync("alice");
        Assert.Equal(Other, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_ExistingAccountAndAdoptionAllowed_AdoptsAndLinks()
    {
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig());
        users.GetUserByName("alice").Returns(UserNamed("alice", Existing));
        users.GetUserById(Existing).Returns(UserNamed("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync("oid", "kc", "sub-1", "alice", allowExistingAccountLink: true);

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
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig());
        users.GetUserByName("alice").Returns(UserNamed("alice", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync("oid", "kc", "sub-1", "alice", allowExistingAccountLink: false));

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
        var (service, _, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig());

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync("oid", "kc", canonicalKey, username, allowExistingAccountLink: true));

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
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(UserNamed("alice", Existing));
        users.GetUserByName("alice").Returns(UserNamed("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync("oid", "kc", "sub-1", "alice", allowExistingAccountLink: true);

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
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(UserNamed("alice", Existing));
        users.GetUserByName("alice").Returns(UserNamed("alice", Existing));

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync("oid", "kc", "attacker-sub", "alice", allowExistingAccountLink: false));

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
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(UserNamed("renamed-alice", Existing));
        users.GetUserByName("alice").Returns((User?)null);
        var created = UserNamed("alice", Other);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Other).Returns(created);

        var resolved = await service.ResolveOrCreateAsync("oid", "kc", "attacker-sub", "alice", allowExistingAccountLink: false);

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
    public async Task ResolveOrCreateAsync_FlagOnRenamedLegacyOwner_HandsOutTheRecordedAccount()
    {
        // Characterization of the flag-ON residual (#361, surfaced on #358): the legacy arm resolves
        // the RECORDED name key even when no live account bears that name anymore (the owner was
        // renamed), a strict superset of same-name adoption — so during an enable-the-flag migration
        // window, a login presenting a foreign sub and the pre-rename name is handed the account and
        // re-keys it. This pins the current behavior empirically; the #361 fix will flip it.
        var (service, cfg, users, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["oldname"] = Existing },
        });
        users.GetUserById(Existing).Returns(UserNamed("newname", Existing));
        users.GetUserByName("oldname").Returns((User?)null); // renamed: no live account bears the key

        var resolved = await service.ResolveOrCreateAsync("oid", "kc", "attacker-sub", "oldname", allowExistingAccountLink: true);

        Assert.Equal(Existing, resolved);
        var links = cfg.OidConfigs["kc"].CanonicalLinks;
        Assert.Equal(Existing, links["attacker-sub"]); // re-keyed to the presented sub
        Assert.False(links.ContainsKey("oldname"));
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
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["opaque-sub-123"] = Existing },
        });
        users.GetUserById(Existing).Returns(UserNamed("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync("oid", "kc", "opaque-sub-123", "opaque-sub-123", allowExistingAccountLink: false);

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
            service.ResolveOrCreateAsync("oid", "deleted-provider", "sub-1", "alice", allowExistingAccountLink: true));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    // --- Admin surface: TryCreateLink / TryRemoveLink / LinksByUser (#372, finishing #241) ---

    [Fact]
    public void TryCreateLink_KnownProvider_WritesTheLinkAndReturnsCreated()
    {
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig());

        var result = service.TryCreateLink("oid", "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkWriteResult.Created, result);
        Assert.Equal(Existing, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void TryCreateLink_EmptyKey_ReturnsEmptyKey_WithoutWriting(string providerUserId)
    {
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig());

        var result = service.TryCreateLink("oid", "kc", providerUserId, Existing);

        Assert.Equal(CanonicalLinkWriteResult.EmptyKey, result);
        Assert.Empty(cfg.OidConfigs["kc"].CanonicalLinks);
    }

    [Fact]
    public void TryCreateLink_UnknownProvider_ReturnsUnknownProvider()
    {
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig());

        var result = service.TryCreateLink("oid", "does-not-exist", "sub-1", Existing);

        Assert.Equal(CanonicalLinkWriteResult.UnknownProvider, result);
    }

    [Fact]
    public void TryCreateLink_EmptyKeyAndUnknownProvider_ReturnsEmptyKey_NotUnknownProvider()
    {
        // The two refusals map to DIFFERENT response bodies, so the order is observable: an unresolved
        // identity is reported as EmptyKey even when the provider is also unknown (the empty-key guard
        // runs first). Locks the check ordering the controller's distinct 400 bodies depend on.
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig());

        var result = service.TryCreateLink("oid", "does-not-exist", "   ", Existing);

        Assert.Equal(CanonicalLinkWriteResult.EmptyKey, result);
    }

    [Fact]
    public void TryRemoveLink_OwnLink_RemovesItAndReturnsRemoved()
    {
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });

        var result = service.TryRemoveLink("oid", "kc", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, result);
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1"));
    }

    [Fact]
    public void TryRemoveLink_UnknownCanonicalName_ReturnsNotFound()
    {
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig());

        var result = service.TryRemoveLink("oid", "kc", "does-not-exist", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.NotFound, result);
    }

    [Fact]
    public void TryRemoveLink_LinkedToDifferentUser_ReturnsMismatch_WithoutRemoving()
    {
        var (service, cfg, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing },
        });

        var result = service.TryRemoveLink("oid", "kc", "sub-1", Other);

        Assert.Equal(CanonicalLinkRemoveResult.Mismatch, result);
        Assert.Equal(Existing, cfg.OidConfigs["kc"].CanonicalLinks["sub-1"]); // untouched
    }

    [Fact]
    public void TryRemoveLink_UnknownProvider_ReturnsUnknownProvider()
    {
        var (service, _, _, _) = Build(c => c.OidConfigs["kc"] = new OidConfig());

        var result = service.TryRemoveLink("oid", "does-not-exist", "sub-1", Existing);

        Assert.Equal(CanonicalLinkRemoveResult.UnknownProvider, result);
    }

    [Fact]
    public void LinksByUser_ReturnsOnlyTheUsersKeys_PerProvider_AsADetachedSnapshot()
    {
        var (service, cfg, _, _) = Build(c =>
        {
            c.OidConfigs["kc"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing, ["sub-2"] = Other } };
            c.OidConfigs["authelia"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-3"] = Existing } };
            c.SamlConfigs["adfs"] = new SamlConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing } };
        });

        var oid = service.LinksByUser("oid", Existing);

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
    public void RemoveUserEverywhere_RemovesTheUsersLinksAcrossAllProviders_AndCountsThem()
    {
        var (service, cfg, _, _) = Build(c =>
        {
            c.OidConfigs["kc"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Existing, ["sub-2"] = Other } };
            c.SamlConfigs["adfs"] = new SamlConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing } };
        });

        var removed = service.RemoveUserEverywhere(Existing);

        Assert.Equal(2, removed); // one OID link + one SAML link
        Assert.False(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-1"));
        Assert.True(cfg.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-2")); // the other user's link survives
        Assert.False(cfg.SamlConfigs["adfs"].CanonicalLinks.ContainsKey("alice"));
    }
}
