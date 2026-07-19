using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
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

    // --- ResolveCanonicalLink: subject-keyed lookup with one-time legacy-name migration (#155),
    // gated behind AllowExistingAccountLink because the legacy key is the mutable username (#354) ---

    private static readonly Guid Subject = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid Legacy = Guid.Parse("44444444-4444-4444-4444-444444444444");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ResolveCanonicalLink_SubjectKeyed_IsUsed_WithoutMigration(bool allow)
    {
        var (linkedUserId, migrate) = AccountLinkResolver.ResolveCanonicalLink(Subject, legacyNameKeyedUserId: null, legacyNameStillHeldByTarget: false, allowExistingAccountLink: allow);
        Assert.Equal(Subject, linkedUserId);
        Assert.False(migrate);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ResolveCanonicalLink_SubjectKeyed_WinsOverLegacy_NoMigration(bool allow)
    {
        // Once a subject-keyed link exists, the legacy name-keyed one is never consulted or migrated —
        // even when the name is still held by its target (legacyNameStillHeldByTarget: true).
        var (linkedUserId, migrate) = AccountLinkResolver.ResolveCanonicalLink(Subject, Legacy, legacyNameStillHeldByTarget: true, allowExistingAccountLink: allow);
        Assert.Equal(Subject, linkedUserId);
        Assert.False(migrate);
    }

    [Fact]
    public void ResolveCanonicalLink_OnlyLegacy_WithOptIn_IsAdopted_AndMigrated()
    {
        // No subject-keyed link yet, but a legacy name-keyed one resolves, the provider permits
        // name-based matching, AND the target still bears the name: adopt it and signal the one-time
        // re-key to the subject.
        var (linkedUserId, migrate) = AccountLinkResolver.ResolveCanonicalLink(subjectKeyedUserId: null, Legacy, legacyNameStillHeldByTarget: true, allowExistingAccountLink: true);
        Assert.Equal(Legacy, linkedUserId);
        Assert.True(migrate);
    }

    [Fact]
    public void ResolveCanonicalLink_OnlyLegacy_WithOptIn_ButNameRenamedAway_IsIgnored()
    {
        // The #361 fix: the flag is on and a legacy name-keyed link resolves, but the account it points
        // at no longer bears the presented name (it was renamed away). Following it would hand the login
        // an account selected by a stale, provider-controlled name (CWE-287), so it must NOT be followed
        // or migrated; the login falls through to the adoption gate over the CURRENT name-holder instead.
        var (linkedUserId, migrate) = AccountLinkResolver.ResolveCanonicalLink(subjectKeyedUserId: null, Legacy, legacyNameStillHeldByTarget: false, allowExistingAccountLink: true);
        Assert.Null(linkedUserId);
        Assert.False(migrate);
    }

    [Fact]
    public void ResolveCanonicalLink_OnlyLegacy_WithoutOptIn_IsIgnored()
    {
        // The security-critical case (#354): the legacy key is the mutable preferred_username, so with
        // AllowExistingAccountLink off a login must NOT be handed the account that key points at, and
        // nothing may be migrated — even while the name is still held by its target. The login falls
        // through to Resolve(), whose adoption gate fails closed.
        var (linkedUserId, migrate) = AccountLinkResolver.ResolveCanonicalLink(subjectKeyedUserId: null, Legacy, legacyNameStillHeldByTarget: true, allowExistingAccountLink: false);
        Assert.Null(linkedUserId);
        Assert.False(migrate);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ResolveCanonicalLink_NeitherLink_ResolvesNothing(bool allow)
    {
        var (linkedUserId, migrate) = AccountLinkResolver.ResolveCanonicalLink(null, null, legacyNameStillHeldByTarget: false, allowExistingAccountLink: allow);
        Assert.Null(linkedUserId);
        Assert.False(migrate);
    }

    // --- ResolveLinkWrite: atomic check-then-link outcome (#133) ---

    [Fact]
    public void ResolveLinkWrite_NoExistingLink_WritesCandidate()
    {
        var (effective, wrote) = AccountLinkResolver.ResolveLinkWrite(existingLiveLinkUserId: null, Subject);
        Assert.Equal(Subject, effective);
        Assert.True(wrote);
    }

    [Fact]
    public void ResolveLinkWrite_ExistingLiveLink_UsesWinner_WithoutWriting()
    {
        // A concurrent first-login already linked this identity: use its account, do NOT overwrite it
        // and do NOT report a write (so the caller does not re-emit the adoption audit).
        var (effective, wrote) = AccountLinkResolver.ResolveLinkWrite(existingLiveLinkUserId: Existing, Subject);
        Assert.Equal(Existing, effective);
        Assert.False(wrote);
    }
}
