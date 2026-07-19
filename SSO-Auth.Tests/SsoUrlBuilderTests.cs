using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests pinning the exact bytes SsoUrlBuilder produces. These strings are validated
/// byte-for-byte on the other side (the IdP's redirect_uri registration; the SAML Recipient echo,
/// compared Ordinal by SamlRecipientValidator), so the pins here are the primary evidence that the
/// #318 extraction changed nothing — the end-to-end suites assert only URL prefixes and parameter
/// presence, not full bytes.
/// </summary>
public class SsoUrlBuilderTests
{
    private const string Base = "https://jf.example.com";

    [Fact]
    public void OidRedirectUri_ClassicRoute_UsesTheLegacySpelling()
    {
        Assert.Equal("https://jf.example.com/sso/OID/r/kc", SsoUrlBuilder.OidRedirectUri(Base, newPath: false, "kc"));
    }

    [Fact]
    public void OidRedirectUri_NewPathRoute_UsesTheRedirectSpelling()
    {
        Assert.Equal("https://jf.example.com/sso/OID/redirect/kc", SsoUrlBuilder.OidRedirectUri(Base, newPath: true, "kc"));
    }

    [Fact]
    public void OidRedirectUri_BaseWithPathBase_KeepsItAheadOfTheSsoSegment()
    {
        // CanonicalBaseUrl.Resolve hands over a trailing-slash-free base including the server's path
        // base; the builder's "/sso/..." concatenation relies on exactly that contract.
        Assert.Equal(
            "https://jf.example.com/jellyfin/sso/OID/r/kc",
            SsoUrlBuilder.OidRedirectUri("https://jf.example.com/jellyfin", newPath: false, "kc"));
    }

    [Theory]
    [InlineData("/sso/OID/redirect/kc", "https://jf.example.com/sso/OID/redirect/kc")]
    [InlineData("/sso/OID/r/kc", "https://jf.example.com/sso/OID/r/kc")]
    public void OidCallbackRedirectUri_EchoesTheCallbackPathSpelling(string callbackPath, string expected)
    {
        Assert.Equal(expected, SsoUrlBuilder.OidCallbackRedirectUri(Base, callbackPath, "kc"));
    }

    [Fact]
    public void OidCallbackRedirectUri_ProviderNamedRedirectOnTheClassicRoute_StaysLegacy()
    {
        // The spelling is decided by the exact segment after OID, not by substring matching, so a
        // provider literally named "redirect" cannot flip it (#98, pinned end-to-end here on top of
        // OidcCallbackPathTests).
        Assert.Equal(
            "https://jf.example.com/sso/OID/r/redirect",
            SsoUrlBuilder.OidCallbackRedirectUri(Base, "/sso/OID/r/redirect", "redirect"));
    }

    [Fact]
    public void OidCallbackRedirectUri_NullPath_DefaultsToTheLegacySpelling()
    {
        Assert.Equal("https://jf.example.com/sso/OID/r/kc", SsoUrlBuilder.OidCallbackRedirectUri(Base, null, "kc"));
    }

    [Theory]
    [InlineData(false, "https://jf.example.com/sso/SAML/p/idp")]
    [InlineData(true, "https://jf.example.com/sso/SAML/post/idp")]
    public void SamlAcsUrl_SpellingFollowsTheRouteVariant(bool newPath, string expected)
    {
        Assert.Equal(expected, SsoUrlBuilder.SamlAcsUrl(Base, newPath, "idp"));
    }

    [Fact]
    public void SamlExpectedAcsUrls_ReturnsBothSpellings_NewPathFirst()
    {
        // Exact array and order: the Recipient binding iterates this set, and the challenge-time ACS
        // is definitionally one of its members, so the validator cannot drift from the challenge.
        Assert.Equal(
            new[] { "https://jf.example.com/sso/SAML/post/idp", "https://jf.example.com/sso/SAML/p/idp" },
            SsoUrlBuilder.SamlExpectedAcsUrls(Base, "idp"));
    }

    [Theory]
    [InlineData("my provider", "https://jf.example.com/sso/OID/r/my provider")]
    [InlineData("käse", "https://jf.example.com/sso/OID/r/käse")]
    public void OidRedirectUri_ProviderIsAppendedRaw_NeverReEncoded(string provider, string expected)
    {
        // Characterizes the contract, not an endorsement: the server never encodes the provider —
        // re-encoding would change the bytes IdPs already have registered and break every working
        // deployment. Rejecting problematic names at registration is #336.
        Assert.Equal(expected, SsoUrlBuilder.OidRedirectUri(Base, newPath: false, provider));
    }

    [Theory]
    [InlineData(true, "redirect")]
    [InlineData(false, "r")]
    public void ChallengeAndCallbackLegs_ProduceTheSameRedirectUri(bool newPath, string segment)
    {
        // RFC 6749 section 4.1.3: the token request must repeat the authorization request's
        // redirect_uri byte-for-byte. The challenge leg derives the spelling from newPath, the
        // callback leg re-derives it from its own path — this pins that the two constructions agree.
        Assert.Equal(
            SsoUrlBuilder.OidRedirectUri(Base, newPath, "kc"),
            SsoUrlBuilder.OidCallbackRedirectUri(Base, $"/sso/OID/{segment}/kc", "kc"));
    }
}
