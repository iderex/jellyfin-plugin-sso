using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins <see cref="OidcLoginService.BuildScopeString"/> — the shared OpenID scope-string builder used by
/// both the challenge and the callback client. Guards #368: a provider stored without scopes leaves
/// <see cref="OidConfig.OidScopes"/> null, which previously threw an unhandled 500 on the anonymous
/// challenge (<c>OidScopes.Prepend</c> on null) and null-padded the callback scope string
/// (<c>new string[2]</c> → trailing separators). The builder normalizes null to empty so both sides
/// emit the same clean, base-prefixed string.
/// </summary>
public class SSOControllerScopeStringTests
{
    [Fact]
    public void NullScopes_YieldBaseScopesOnly_NoThrow()
    {
        var config = new OidConfig { OidScopes = null };

        Assert.Equal("openid profile", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void EmptyScopes_YieldBaseScopesOnly()
    {
        var config = new OidConfig { OidScopes = Array.Empty<string>() };

        Assert.Equal("openid profile", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void ConfiguredScopes_ArePrefixedWithBaseScopes()
    {
        var config = new OidConfig { OidScopes = new[] { "email", "groups" } };

        Assert.Equal("openid profile email groups", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void NullElement_IsDropped_NoTrailingSeparator()
    {
        var config = new OidConfig { OidScopes = new[] { "email", null } };

        Assert.Equal("openid profile email", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void EmptyElement_IsDropped_NoDoubledSeparator()
    {
        var config = new OidConfig { OidScopes = new[] { "", "groups" } };

        Assert.Equal("openid profile groups", OidcLoginService.BuildScopeString(config));
    }

    [Fact]
    public void AllBlankElements_YieldBaseScopesOnly()
    {
        var config = new OidConfig { OidScopes = new[] { "", " ", null } };

        Assert.Equal("openid profile", OidcLoginService.BuildScopeString(config));
    }
}
