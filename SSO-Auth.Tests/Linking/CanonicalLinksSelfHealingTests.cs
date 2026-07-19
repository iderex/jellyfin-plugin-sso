using System;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for the self-healing <c>CanonicalLinks</c> getter (#239): a direct
/// <c>CanonicalLinks[key] = id</c> must persist into the stored map, not a throwaway. Before the fix
/// the getter returned a fresh empty map while the backing field was null, so the write was silently
/// lost — login-critical account-link state.
/// </summary>
public class CanonicalLinksSelfHealingTests
{
    private static readonly Guid User = Guid.Parse("22222222-2222-2222-2222-222222222222");

    [Fact]
    public void OidConfig_DirectWrite_Persists()
    {
        var config = new OidConfig();

        config.CanonicalLinks["sub-1"] = User;

        Assert.True(config.CanonicalLinks.ContainsKey("sub-1"));
        Assert.Equal(User, config.CanonicalLinks["sub-1"]);
    }

    [Fact]
    public void SamlConfig_DirectWrite_Persists()
    {
        var config = new SamlConfig();

        config.CanonicalLinks["nameid-1"] = User;

        Assert.True(config.CanonicalLinks.ContainsKey("nameid-1"));
        Assert.Equal(User, config.CanonicalLinks["nameid-1"]);
    }

    [Fact]
    public void CanonicalLinks_ReturnsTheSameInstanceAcrossReads()
    {
        var config = new OidConfig();

        // Two reads return the one stored map, not a fresh throwaway each time.
        Assert.Same(config.CanonicalLinks, config.CanonicalLinks);
    }
}
