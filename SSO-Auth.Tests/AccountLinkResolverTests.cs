using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="AccountLinkResolver"/> — the fail-closed decision that binds an SSO identity
/// to a Jellyfin account. The security-critical case is that a pre-existing, unlinked account is
/// NOT adopted unless the administrator opted in, preventing account takeover by name collision.
/// </summary>
public class AccountLinkResolverTests
{
    private static readonly Guid Linked = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Existing = Guid.Parse("22222222-2222-2222-2222-222222222222");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExistingLink_IsAlwaysUsed_RegardlessOfOptIn(bool allow)
    {
        var decision = AccountLinkResolver.Resolve(Linked, Existing, allow);
        Assert.Equal(AccountLinkAction.UseExistingLink, decision.Action);
        Assert.Equal(Linked, decision.UserId);
    }

    [Fact]
    public void NoLinkButNameTaken_WithoutOptIn_IsRejected()
    {
        var decision = AccountLinkResolver.Resolve(null, Existing, allowExistingAccountLink: false);
        Assert.Equal(AccountLinkAction.RejectNameTaken, decision.Action);
        Assert.Equal(Guid.Empty, decision.UserId);
    }

    [Fact]
    public void NoLinkButNameTaken_WithOptIn_AdoptsExistingAccount()
    {
        var decision = AccountLinkResolver.Resolve(null, Existing, allowExistingAccountLink: true);
        Assert.Equal(AccountLinkAction.AdoptExistingAccount, decision.Action);
        Assert.Equal(Existing, decision.UserId);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NoLinkAndNameFree_CreatesNewAccount_RegardlessOfOptIn(bool allow)
    {
        var decision = AccountLinkResolver.Resolve(null, null, allow);
        Assert.Equal(AccountLinkAction.CreateNewAccount, decision.Action);
        Assert.Equal(Guid.Empty, decision.UserId);
    }
}
