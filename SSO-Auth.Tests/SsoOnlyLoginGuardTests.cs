using System;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Negative-path suite for the pure SSO-only activation guard (#165) — the fail-closed last-admin interlock
/// that refuses to enable <c>DisablePasswordLogin</c> unless a working non-SSO admin login path is provable
/// (SSO-ONLY-LOGIN-DESIGN.md §3, criterion 3). Each refusal branch is pinned so loosening the guard to
/// accept flips a test red, and the public refusal message is asserted to be actionable but non-enumerating
/// (T-I1). The guard is pure, so these call it directly with a resolved <see cref="BreakGlassAdminState"/>.
/// </summary>
public class SsoOnlyLoginGuardTests
{
    private static BreakGlassAdminState QualifiedAdmin => new(Exists: true, IsAdministrator: true, IsEnabled: true, HasUsablePasswordLogin: true);

    [Fact]
    public void Evaluate_QualifiedBreakGlassAdmin_Allows()
    {
        // The positive path: an existing, enabled administrator with a usable password is the guaranteed
        // survivor, so activation is safe.
        Assert.Equal(SsoOnlyGuardVerdict.Allow, SsoOnlyLoginGuard.Evaluate("admin", QualifiedAdmin));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Evaluate_NoBreakGlassDesignated_Refuses(string? username)
    {
        // No designation at all: there is nothing standing between the org and a locked server.
        Assert.Equal(SsoOnlyGuardVerdict.NoBreakGlassDesignated, SsoOnlyLoginGuard.Evaluate(username!, QualifiedAdmin));
    }

    [Fact]
    public void Evaluate_BreakGlassAccountMissing_Refuses()
    {
        // The designated username resolves to no account — fail closed.
        Assert.Equal(SsoOnlyGuardVerdict.BreakGlassNotFound, SsoOnlyLoginGuard.Evaluate("ghost", default));
    }

    [Fact]
    public void Evaluate_BreakGlassNotAdministrator_Refuses()
    {
        // The exemption may only spare an EXISTING administrator (T-E1) — a non-admin target cannot become
        // the break-glass door, and the exemption never grants admin.
        var nonAdmin = QualifiedAdmin with { IsAdministrator = false };

        Assert.Equal(SsoOnlyGuardVerdict.BreakGlassNotAdministrator, SsoOnlyLoginGuard.Evaluate("bob", nonAdmin));
    }

    [Fact]
    public void Evaluate_BreakGlassDisabled_Refuses()
    {
        // A disabled admin cannot log in, so it cannot be the survivor.
        var disabled = QualifiedAdmin with { IsEnabled = false };

        Assert.Equal(SsoOnlyGuardVerdict.BreakGlassDisabled, SsoOnlyLoginGuard.Evaluate("admin", disabled));
    }

    [Fact]
    public void Evaluate_BreakGlassWithoutUsablePasswordLogin_Refuses()
    {
        // The survivor guard NEVER counts an admin whose only path is SSO (SSO-ONLY-LOGIN-DESIGN.md §3,
        // T-D3): an admin already routed away from the password provider (or without a password) has no
        // password door, so it fails the guard even though it is an enabled administrator.
        var noPassword = QualifiedAdmin with { HasUsablePasswordLogin = false };

        Assert.Equal(SsoOnlyGuardVerdict.BreakGlassNoPasswordLogin, SsoOnlyLoginGuard.Evaluate("admin", noPassword));
    }

    [Fact]
    public void AssertCanActivate_Refusal_ThrowsNonEnumeratingMessage()
    {
        // Fail-closed like ProviderConfigValidator: an unsafe activation throws an ArgumentException whose
        // message states the reason and the fix but never leaks a username/roster (T-I1).
        const string username = "supersecret-admin-name";

        var ex = Assert.Throws<ArgumentException>(() => SsoOnlyLoginGuard.AssertCanActivate(username, default));

        // ArgumentException appends "(Parameter '...')" (the param NAME, never the username value), so the
        // public reason is the message prefix and the username itself never appears.
        Assert.StartsWith(SsoOnlyLoginGuard.PublicRefusalMessage, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(username, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AssertCanActivate_QualifiedAdmin_DoesNotThrow()
    {
        Assert.Null(Record.Exception(() => SsoOnlyLoginGuard.AssertCanActivate("admin", QualifiedAdmin)));
    }

    [Fact]
    public void IsEnforcedNonExempt_ModeOn_NonExemptUser_IsEnforced()
    {
        var config = new PluginConfiguration { DisablePasswordLogin = true, BreakGlassAdminUsername = "root" };

        Assert.True(SsoOnlyLoginGuard.IsEnforcedNonExempt(config, "alice"));
    }

    [Theory]
    [InlineData("root")]
    [InlineData("ROOT")] // account names are case-insensitive in Jellyfin
    public void IsEnforcedNonExempt_ModeOn_BreakGlassAdmin_IsExempt(string username)
    {
        var config = new PluginConfiguration { DisablePasswordLogin = true, BreakGlassAdminUsername = "root" };

        Assert.False(SsoOnlyLoginGuard.IsEnforcedNonExempt(config, username));
        Assert.True(SsoOnlyLoginGuard.IsBreakGlass(config, username));
    }

    [Fact]
    public void IsEnforcedNonExempt_ModeOff_NeverEnforced()
    {
        var config = new PluginConfiguration { DisablePasswordLogin = false, BreakGlassAdminUsername = "root" };

        Assert.False(SsoOnlyLoginGuard.IsEnforcedNonExempt(config, "alice"));
    }
}
