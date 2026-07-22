// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlLoginPolicy"/> — the login allow-list gate that must hold at both the
/// assertion-consumer page and the session-minting endpoint (enforcing it only at the page is
/// fail-open). Fail-closed: an assertion whose roles are not on a non-empty allow-list is denied.
/// </summary>
public class SamlLoginPolicyTests
{
    [Fact]
    public void NoAllowList_IsAllowed()
    {
        Assert.True(SamlLoginPolicy.IsLoginAllowed(new[] { "anything" }, null));
        Assert.True(SamlLoginPolicy.IsLoginAllowed(new[] { "anything" }, new string[0]));
    }

    [Fact]
    public void MatchingRole_IsAllowed()
    {
        Assert.True(SamlLoginPolicy.IsLoginAllowed(new[] { "users", "jellyfin" }, new[] { "jellyfin" }));
    }

    [Fact]
    public void NoMatchingRole_IsDenied()
    {
        Assert.False(SamlLoginPolicy.IsLoginAllowed(new[] { "users", "other" }, new[] { "jellyfin" }));
    }

    [Fact]
    public void EmptyOrNoAssertionRoles_WithAllowList_IsDenied()
    {
        Assert.False(SamlLoginPolicy.IsLoginAllowed(new string[0], new[] { "jellyfin" }));
        Assert.False(SamlLoginPolicy.IsLoginAllowed(null, new[] { "jellyfin" }));
    }

    [Fact]
    public void ComparisonIsCaseSensitiveAndNullSafe()
    {
        Assert.False(SamlLoginPolicy.IsLoginAllowed(new[] { "Jellyfin" }, new[] { "jellyfin" }));
        Assert.False(SamlLoginPolicy.IsLoginAllowed(new[] { "jellyfin" }, new string?[] { null }));
    }

    [Fact]
    public void NullOrEmptyRolesNeverAuthorize()
    {
        // A null/empty on both sides must not satisfy the allow-list.
        Assert.False(SamlLoginPolicy.IsLoginAllowed(new string?[] { null }, new string?[] { null }));
        Assert.False(SamlLoginPolicy.IsLoginAllowed(new[] { "" }, new[] { "" }));
    }

    /// <summary>
    /// The whitespace variant of the blank class (#952, follow-up to #935): a whitespace-only
    /// configured entry (hand-edited or imported config XML) must not be satisfiable by a
    /// whitespace-only assertion role — XML text nodes preserve whitespace and the assertion
    /// roles are compared raw, so the pair is producible. Aligns SAML login validity with the
    /// OIDC allow-list, which skips whitespace-only entries since #935.
    /// </summary>
    /// <param name="configured">The blank configured entry variant.</param>
    /// <param name="asserted">The blank assertion-role variant.</param>
    [Theory]
    [InlineData("   ", "   ")]
    [InlineData("\t", "\t")]
    [InlineData(" ", " ")]
    public void WhitespaceOnlyRolesNeverAuthorize(string configured, string asserted)
    {
        Assert.False(SamlLoginPolicy.IsLoginAllowed(new[] { asserted }, new[] { configured }));
    }

    [Fact]
    public void WhitespaceOnlyAllowList_StillCountsAsConfigured_AndDeniesRealRoles()
    {
        // A list holding only a blank entry is a misconfiguration, and it fails CLOSED: it does not
        // fall into the RBAC-off early return (Length > 0), so a real asserted role is denied.
        Assert.False(SamlLoginPolicy.IsLoginAllowed(new[] { "jellyfin" }, new[] { "   " }));
    }

    [Fact]
    public void WhitespaceEntryBesideRealEntry_RealMatchingIsUnaffected()
    {
        // The blank entry is skipped per-entry, not per-list, and no trimming is introduced for
        // non-blank values: an entry carrying inner/outer whitespace still requires the exact
        // ordinal role.
        Assert.True(SamlLoginPolicy.IsLoginAllowed(new[] { "jellyfin" }, new[] { "   ", "jellyfin" }));
        Assert.True(SamlLoginPolicy.IsLoginAllowed(new[] { " jellyfin " }, new[] { " jellyfin " }));
        Assert.False(SamlLoginPolicy.IsLoginAllowed(new[] { "jellyfin" }, new[] { " jellyfin " }));
    }
}
