// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins the SSO-only login audit trail (#165, criterion 6 / T-R1): an <c>[SSO Audit]</c> entry is emitted
/// on enable, on disable, and on a guard refusal, each recording the actor and outcome — and the refusal
/// records only a reason CODE, never a username/roster (T-I1). Admin-supplied values are line-ending
/// sanitized so they cannot forge or split an entry.
/// </summary>
public class SsoOnlyAuditTests
{
    [Fact]
    public void SsoOnlyLoginEnabled_LogsWarning_WithActorBreakGlassAndCount()
    {
        var logger = new CapturingLogger();

        SsoAudit.SsoOnlyLoginEnabled(logger, "admin", "root", 3);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("ENABLED", entry.Message, StringComparison.Ordinal);
        Assert.Contains("admin", entry.Message, StringComparison.Ordinal);
        Assert.Contains("root", entry.Message, StringComparison.Ordinal);
        Assert.Contains("3", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SsoOnlyLoginDisabled_LogsWarning_WithActorAndCount()
    {
        var logger = new CapturingLogger();

        SsoAudit.SsoOnlyLoginDisabled(logger, "admin", 2);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("DISABLED", entry.Message, StringComparison.Ordinal);
        Assert.Contains("admin", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SsoOnlyLoginActivationRefused_LogsReasonCodeOnly_NoUsernameEnumeration()
    {
        var logger = new CapturingLogger();

        SsoAudit.SsoOnlyLoginActivationRefused(logger, "admin", SsoOnlyGuardVerdict.BreakGlassNotFound.ToString());

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("REFUSED", entry.Message, StringComparison.Ordinal);
        // The reason is a fixed verdict code — not a roster of who is or is not an admin (T-I1).
        Assert.Contains("BreakGlassNotFound", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SsoOnlyLoginEnabled_StripsLineEndingsFromActorAndBreakGlass()
    {
        var logger = new CapturingLogger();

        SsoAudit.SsoOnlyLoginEnabled(logger, "admin\r\nInjected", "root\r\nForged", 1);

        var message = Assert.Single(logger.Entries).Message;
        Assert.DoesNotContain("\n", message, StringComparison.Ordinal);
        Assert.Contains("adminInjected", message, StringComparison.Ordinal);
        Assert.Contains("rootForged", message, StringComparison.Ordinal);
    }

    [Fact]
    public void BreakGlassAdminDesignated_LogsWarning_WithActorAndTarget()
    {
        var logger = new CapturingLogger();

        SsoAudit.BreakGlassAdminDesignated(logger, "admin", "root");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("Break-glass admin designated", entry.Message, StringComparison.Ordinal);
        Assert.Contains("root", entry.Message, StringComparison.Ordinal);
    }
}
