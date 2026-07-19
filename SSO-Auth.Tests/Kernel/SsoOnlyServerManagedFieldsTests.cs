using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins that the SSO-only login state is server-managed on the config-page save path (#165, criterion 3):
/// <see cref="ServerManagedFields.Preserve(PluginConfiguration, PluginConfiguration)"/> re-injects the live
/// <c>DisablePasswordLogin</c>, <c>BreakGlassAdminUsername</c> and <c>SsoOnlyRepointedUserIds</c>, so a
/// plugin-config PUT can neither flip the mode, repoint the break-glass admin, nor read/forge/clear the
/// repointed-account tracking set — the only door for those is the elevated, guarded SSO-Only endpoints.
/// This is stronger than re-validating an incoming toggle: an unsafe (or accidental) value can never be
/// introduced via the config-page save at all.
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

    [Fact]
    public void Preserve_ConfigPageSaveCannotClearTheRepointedUserIds()
    {
        var tracked = Guid.NewGuid();
        var live = new PluginConfiguration { SsoOnlyRepointedUserIds = new List<Guid> { tracked } };
        // A config-page save that omits (defaults to empty) the tracking set must not drop it — losing the
        // recorded ids would strand repointed accounts the off-switch/boot reconcile can no longer restore.
        var incoming = new PluginConfiguration { SsoOnlyRepointedUserIds = new List<Guid>() };

        ServerManagedFields.Preserve(incoming, live);

        Assert.Equal(new[] { tracked }, incoming.SsoOnlyRepointedUserIds);
    }

    [Fact]
    public void Preserve_ConfigPageSaveCannotForgeTheRepointedUserIds()
    {
        var real = Guid.NewGuid();
        var live = new PluginConfiguration { SsoOnlyRepointedUserIds = new List<Guid> { real } };
        // A hand-crafted PUT injecting an attacker-chosen id (to later hand that account a password door on
        // restore) is frozen back to the server-side set.
        var incoming = new PluginConfiguration { SsoOnlyRepointedUserIds = new List<Guid> { Guid.NewGuid() } };

        ServerManagedFields.Preserve(incoming, live);

        Assert.Equal(new[] { real }, incoming.SsoOnlyRepointedUserIds);
    }
}
