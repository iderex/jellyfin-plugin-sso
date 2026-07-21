// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="LogoutContext"/> — the id_token it carries is a bearer secret, so its synthesized
/// string form must redact it (#727), so a stray interpolation or logged context can never spill the token.
/// </summary>
public class LogoutContextTests
{
    [Fact]
    public void ToString_RedactsTheIdToken_ButKeepsTheSessionIndex()
    {
        var text = new LogoutContext("sid-1", "super.secret.id.token").ToString();

        Assert.DoesNotContain("super.secret.id.token", text, System.StringComparison.Ordinal);
        Assert.Contains("<redacted>", text, System.StringComparison.Ordinal);
        Assert.Contains("sid-1", text, System.StringComparison.Ordinal);
    }

    [Fact]
    public void ToString_NullIdToken_ShowsNull_NotRedacted()
        => Assert.Contains("IdToken = null", new LogoutContext("sid-1", null).ToString(), System.StringComparison.Ordinal);
}
