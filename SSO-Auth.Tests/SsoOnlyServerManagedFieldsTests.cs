using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins that the SSO-only login state is server-managed on the config-page save path (#165, criterion 3):
/// <see cref="ServerManagedFields.Preserve(PluginConfiguration, PluginConfiguration)"/> re-injects the live
/// <c>DisablePasswordLogin</c> and <c>BreakGlassAdminUsername</c>, so a plugin-config PUT can neither flip
/// the mode nor repoint the break-glass admin — the only door for those is the elevated, guarded SSO-Only
/// endpoints. This is stronger than re-validating an incoming toggle: an unsafe (or accidental) value can
/// never be introduced via the config-page save at all.
/// </summary>
public class SsoOnlyServerManagedFieldsTests
{
    [Fact]
    public void Preserve_ConfigPageSaveCannotDisableTheMode()
    {
        var live = new PluginConfiguration { DisablePasswordLogin = true, BreakGlassAdminUsername = "root" };
        // A config-page save that omits (defaults) the fields must not silently turn the mode off.
        var incoming = new PluginConfiguration { DisablePasswordLogin = false, BreakGlassAdminUsername = null };

        ServerManagedFields.Preserve(incoming, live);

        Assert.True(incoming.DisablePasswordLogin);
        Assert.Equal("root", incoming.BreakGlassAdminUsername);
    }

    [Fact]
    public void Preserve_ConfigPageSaveCannotEnableTheModeOrRepointTheBreakGlassAdmin()
    {
        var live = new PluginConfiguration { DisablePasswordLogin = false, BreakGlassAdminUsername = null };
        // A hand-crafted PUT trying to enable SSO-only or hijack the exemption is frozen back to the live off state.
        var incoming = new PluginConfiguration { DisablePasswordLogin = true, BreakGlassAdminUsername = "attacker" };

        ServerManagedFields.Preserve(incoming, live);

        Assert.False(incoming.DisablePasswordLogin);
        Assert.Null(incoming.BreakGlassAdminUsername);
    }
}
