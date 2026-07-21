// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins the SSO-only guard on the config-import persistence path (#165, criterion 3 / T-T2): a document
/// asserting <c>DisablePasswordLogin</c> must prove a surviving admin login path or the whole import is
/// rejected fail-closed before anything is merged. The SSO-only globals themselves are instance-local and
/// are never applied by an import (like the rate-limit settings) — import VALIDATES the assertion but does
/// not flip the target's mode; the operator enables it through the elevated SSO-Only endpoints.
/// </summary>
public class SsoOnlyConfigImportTests
{
    private static ConfigExportDocument DocumentAsserting(bool disablePasswordLogin, string? breakGlass)
        => new()
        {
            FormatVersion = ConfigExport.FormatVersion,
            Configuration = new PluginConfiguration
            {
                DisablePasswordLogin = disablePasswordLogin,
                BreakGlassAdminUsername = breakGlass,
            },
        };

    private static BreakGlassAdminState QualifiedAdmin(string name)
        => new(Exists: true, IsAdministrator: true, IsEnabled: true, HasUsablePasswordLogin: true);

    [Fact]
    public void Import_AssertingSsoOnly_WithNoSafeAdmin_IsRejected_AndAppliesNothing()
    {
        // The central lockout-via-import branch: a document turns SSO-only on but no break-glass admin can be
        // proven (the resolver reports no qualifying account), so the whole import throws before merging.
        var target = new PluginConfiguration();
        var document = DocumentAsserting(disablePasswordLogin: true, breakGlass: "ghost");

        var ex = Assert.Throws<ArgumentException>(() => ConfigImport.Apply(target, document, _ => default));

        Assert.StartsWith(SsoOnlyLoginGuard.PublicRefusalMessage, ex.Message, StringComparison.Ordinal);
        Assert.False(target.DisablePasswordLogin);
        Assert.True(string.IsNullOrEmpty(target.BreakGlassAdminUsername));
    }

    [Fact]
    public void Import_AssertingSsoOnly_WithNullResolver_FailsClosed()
    {
        // Belt: no resolver at all cannot be read as "safe" — an unresolved account fails the guard closed.
        var target = new PluginConfiguration();
        var document = DocumentAsserting(disablePasswordLogin: true, breakGlass: "root");

        Assert.Throws<ArgumentException>(() => ConfigImport.Apply(target, document));
        Assert.False(target.DisablePasswordLogin);
    }

    [Fact]
    public void Import_AssertingSsoOnly_WithSafeAdmin_DoesNotThrow_ButStillDoesNotFlipTheMode()
    {
        // Even with a provable safe admin, import validates but does not APPLY the operational mode (it has
        // no IUserManager to run the per-user enforcement sweep) — the target's own state is unchanged.
        var target = new PluginConfiguration();
        var document = DocumentAsserting(disablePasswordLogin: true, breakGlass: "root");

        Assert.Null(Record.Exception(() => ConfigImport.Apply(target, document, QualifiedAdmin)));
        Assert.False(target.DisablePasswordLogin);
    }

    [Fact]
    public void Import_NotAssertingSsoOnly_ImportsNormally()
    {
        // A document that does not turn SSO-only on never trips the guard, regardless of the resolver.
        var target = new PluginConfiguration();
        var document = DocumentAsserting(disablePasswordLogin: false, breakGlass: null);

        Assert.Null(Record.Exception(() => ConfigImport.Apply(target, document, _ => default)));
        Assert.False(target.DisablePasswordLogin);
    }
}
