using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="ProviderNameValidator"/> — the shared predicate behind the provider-name
/// registration gate (#336, #360). Covers every rejected character individually (RFC 3986 gen-delims,
/// sub-delims, and the percent escape), the C0/C1 control characters (#360), the concrete round-trip
/// breakers from the issue, and the deliberately accepted shapes: unreserved characters, spaces,
/// non-ASCII (all pinned as surviving the raw URL round-trip in SsoUrlBuilderTests), and blank.
/// </summary>
public class ProviderNameValidatorTests
{
    [Theory]
    [InlineData(':')]
    [InlineData('/')]
    [InlineData('?')]
    [InlineData('#')]
    [InlineData('[')]
    [InlineData(']')]
    [InlineData('@')]
    [InlineData('!')]
    [InlineData('$')]
    [InlineData('&')]
    [InlineData('\'')]
    [InlineData('(')]
    [InlineData(')')]
    [InlineData('*')]
    [InlineData('+')]
    [InlineData(',')]
    [InlineData(';')]
    [InlineData('=')]
    [InlineData('%')]
    [InlineData('\\')] // browsers normalize backslash to slash in URLs (WHATWG), recreating the unmatchable-path dead end
    public void IsInvalid_EveryUriReservedCharacterAndThePercentEscape_IsRejected(char reserved)
    {
        Assert.True(ProviderNameValidator.IsInvalid($"idp{reserved}1"));
    }

    [Theory]
    [InlineData('\u0000')] // C0 NUL (bottom of the C0 range)
    [InlineData('\t')] // C0 horizontal tab
    [InlineData('\n')] // C0 newline, also the ProviderScopedKey separator hazard flagged in #360
    [InlineData('\r')] // C0 carriage return
    [InlineData('\u001F')] // C0 unit separator (top of the C0 range)
    [InlineData('\u007F')] // DEL
    [InlineData('\u0085')] // C1 next line (NEL)
    [InlineData('\u009F')] // C1 application program command (top of the C1 range)
    public void IsInvalid_C0AndC1ControlCharacters_AreRejected(char control)
    {
        Assert.True(ProviderNameValidator.IsInvalid($"idp{control}1"));
    }

    [Theory]
    [InlineData("prov%1")] // invalid percent sequence: route decoding rejects the callback outright
    [InlineData("a%2Fb")] // valid percent sequence: routing decodes it to "a/b" and the config lookup misses
    [InlineData("my/realm")] // '/' builds a callback URL no route can match, so the IdP redirect dead-ends
    public void IsInvalid_TheRoundTripBreakersFromTheIssue_AreRejected(string name)
    {
        Assert.True(ProviderNameValidator.IsInvalid(name));
    }

    [Theory]
    [InlineData("keycloak")]
    [InlineData("Google-SSO")]
    [InlineData("idp_01.example~x")] // every non-alphanumeric RFC 3986 unreserved character
    [InlineData("my provider")] // spaces survive the round-trip today (pinned in SsoUrlBuilderTests)
    [InlineData("käse")] // non-ASCII survives too
    [InlineData("")] // blank is out of this rule's scope: no route can produce an empty provider segment
    [InlineData(null)]
    public void IsInvalid_UnreservedSpacesNonAsciiAndBlank_AreAccepted(string? name)
    {
        Assert.False(ProviderNameValidator.IsInvalid(name));
    }
}
