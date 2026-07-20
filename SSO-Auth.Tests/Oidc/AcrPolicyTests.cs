using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="AcrPolicy"/> — the step-up / forced-MFA acr allow-list check (#757). Fail-closed:
/// only a non-blank returned acr that exactly (ordinally) matches one of the space-separated configured
/// values satisfies the policy; everything else — absent acr, empty allow-list, a non-listed value — is
/// refused.
/// </summary>
public class AcrPolicyTests
{
    [Theory]
    [InlineData("mfa", "mfa", true)] // exact single match
    [InlineData("gold", "silver gold", true)] // one of several, order-independent
    [InlineData("  mfa  ", "phr mfa", true)] // returned acr is trimmed
    [InlineData("mfa", "silver gold", false)] // not in the allow-list
    [InlineData("MFA", "mfa", false)] // ordinal / case-sensitive (acr values are case-sensitive)
    [InlineData("mfa", "", false)] // empty allow-list satisfies nothing
    [InlineData("mfa", null, false)] // null allow-list satisfies nothing
    [InlineData("", "mfa", false)] // absent returned acr fails closed
    [InlineData(null, "mfa", false)] // absent returned acr fails closed
    [InlineData("  ", "mfa", false)] // blank returned acr fails closed
    public void IsSatisfied_EnforcesTheAllowListFailClosed(string? returnedAcr, string? configuredAcrValues, bool expected)
        => Assert.Equal(expected, AcrPolicy.IsSatisfied(returnedAcr, configuredAcrValues));
}
