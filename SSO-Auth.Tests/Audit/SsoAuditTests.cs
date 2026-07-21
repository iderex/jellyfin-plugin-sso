// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SsoAudit"/> — the structured security audit-log entries. Focused on the
/// insecure-options warning (#140): it must fire at Warning level, name the provider and the enabled
/// options, and strip line endings from the (route/admin-supplied) provider name so it cannot forge
/// or split a log entry.
/// </summary>
public class SsoAuditTests
{
    [Fact]
    public void InsecureOptionsEnabled_LogsWarning_NamingProviderAndOptions()
    {
        var logger = new CapturingLogger();

        SsoAudit.InsecureOptionsEnabled(logger, "OpenID", "corp", new[] { "DisableHttps", "DoNotValidateEndpoints" });

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("corp", entry.Message, StringComparison.Ordinal);
        Assert.Contains("DisableHttps", entry.Message, StringComparison.Ordinal);
        Assert.Contains("DoNotValidateEndpoints", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void InsecureOptionsEnabled_StripsLineEndingsFromProviderName()
    {
        var logger = new CapturingLogger();

        // A provider name carrying a newline must not split the entry — the sanitizer collapses it.
        SsoAudit.InsecureOptionsEnabled(logger, "OpenID", "corp\r\nInjected", new[] { "DisableHttps" });

        var message = Assert.Single(logger.Entries).Message;
        Assert.DoesNotContain("\n", message, StringComparison.Ordinal);
        Assert.Contains("corpInjected", message, StringComparison.Ordinal);
    }
}
