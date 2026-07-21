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
}
