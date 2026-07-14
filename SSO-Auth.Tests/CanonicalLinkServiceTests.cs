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

    private static (CanonicalLinkService Service, PluginConfiguration Config, IUserManager Users) Build(Action<PluginConfiguration>? seed = null)
    {
        var cfg = new PluginConfiguration();
        seed?.Invoke(cfg);
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var users = Substitute.For<IUserManager>();
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());
        return (service, cfg, users);
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LiveSubjectLink_ReusesItWithoutCreating()
    {
        var (service, _, users) = Build(c => c.OidConfigs["kc"] = new OidConfig
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
        var (service, cfg, users) = Build(c => c.OidConfigs["kc"] = new OidConfig());
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
        var (service, cfg, users) = Build(c => c.OidConfigs["kc"] = new OidConfig());
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
        var (service, cfg, users) = Build(c => c.OidConfigs["kc"] = new OidConfig());
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
        var (service, _, users) = Build(c => c.OidConfigs["kc"] = new OidConfig());

        await Assert.ThrowsAsync<AccountLinkForbiddenException>(() =>
            service.ResolveOrCreateAsync("oid", "kc", canonicalKey, username, allowExistingAccountLink: true));

        await users.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task ResolveOrCreateAsync_LegacyNameKeyedOidLink_MigratesToTheSubjectKey()
    {
        // #155: an OpenID login with only a legacy username-keyed link adopts and re-keys it to the
        // stable subject, so a later provider-side rename cannot detach it.
        var (service, cfg, users) = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = Existing },
        });
        users.GetUserById(Existing).Returns(UserNamed("alice", Existing));
        users.GetUserByName("alice").Returns(UserNamed("alice", Existing));

        var resolved = await service.ResolveOrCreateAsync("oid", "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Existing, resolved);
        var links = cfg.OidConfigs["kc"].CanonicalLinks;
        Assert.Equal(Existing, links["sub-1"]);
        Assert.False(links.ContainsKey("alice")); // the legacy key is gone
    }

    [Fact]
    public void RemoveUserEverywhere_RemovesTheUsersLinksAcrossAllProviders_AndCountsThem()
    {
        var (service, cfg, _) = Build(c =>
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
