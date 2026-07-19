using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Unit tests for the single <see cref="ProviderMode"/> ↔ token mapping parsed once at the controller
/// boundary (#369): the route's <c>{mode}</c> string is turned into the typed enum exactly here, an unknown
/// token is rejected fail-closed (never defaulting to a protocol), and the two accepted protocols round-trip
/// through the lowercase link-namespace token used in operator logs. The theories key on token strings (not
/// the internal enum) so the public test methods stay accessible; the enum is asserted inside the body.
/// </summary>
public class ProviderModeTests
{
    [Theory]
    [InlineData("oid")]
    [InlineData("saml")]
    [InlineData("OID")]  // case-insensitive, so both former divergent dispatches agree
    [InlineData("SAML")]
    [InlineData("Oid")]
    [InlineData("Saml")]
    public void TryParse_KnownToken_ParsesAndRoundTripsThroughTheLowercaseToken(string token)
    {
        Assert.True(ProviderModeParser.TryParse(token, out var mode));
        // The parse is case-insensitive but the rendered token is always the canonical lowercase form.
        Assert.Equal(token.ToLowerInvariant(), mode.ToToken());
    }

    [Fact]
    public void TryParse_DistinguishesTheTwoProtocols()
    {
        Assert.True(ProviderModeParser.TryParse("oid", out var oid));
        Assert.True(ProviderModeParser.TryParse("saml", out var saml));
        Assert.Equal(ProviderMode.Oid, oid);
        Assert.Equal(ProviderMode.Saml, saml);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("ldap")]
    [InlineData("oidc")]     // near-miss: only the exact tokens are accepted
    [InlineData("sam l")]
    public void TryParse_UnknownToken_FailsClosedWithoutDefaultingToAProtocol(string? token)
    {
        Assert.False(ProviderModeParser.TryParse(token, out var mode));
        // The out value is the default and must not be mistaken for a resolved protocol: callers gate on the
        // bool, never the out on a false return.
        Assert.Equal(default, mode);
    }
}
