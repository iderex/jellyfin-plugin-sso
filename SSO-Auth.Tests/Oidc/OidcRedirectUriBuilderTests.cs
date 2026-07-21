// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests pinning the exact bytes <see cref="OidcRedirectUriBuilder"/> produces. The
/// redirect_uri is validated byte-for-byte on the other side (the IdP's registration; RFC 6749 section
/// 4.1.3 equality), so the pins here are the primary evidence that refactors change nothing — the
/// end-to-end suites assert only URL prefixes and parameter presence, not full bytes.
/// </summary>
public class OidcRedirectUriBuilderTests
{
    private const string Base = "https://jf.example.com";

    [Fact]
    public void ChallengeRedirectUri_ClassicRoute_UsesTheLegacySpelling()
    {
        Assert.Equal("https://jf.example.com/sso/OID/r/kc", OidcRedirectUriBuilder.ChallengeRedirectUri(Base, newPath: false, "kc"));
    }

    [Fact]
    public void ChallengeRedirectUri_NewPathRoute_UsesTheRedirectSpelling()
    {
        Assert.Equal("https://jf.example.com/sso/OID/redirect/kc", OidcRedirectUriBuilder.ChallengeRedirectUri(Base, newPath: true, "kc"));
    }

    [Fact]
    public void ChallengeRedirectUri_BaseWithPathBase_KeepsItAheadOfTheSsoSegment()
    {
        // CanonicalBaseUrl.Resolve hands over a trailing-slash-free base including the server's path
        // base; the builder's "/sso/..." concatenation relies on exactly that contract.
        Assert.Equal(
            "https://jf.example.com/jellyfin/sso/OID/r/kc",
            OidcRedirectUriBuilder.ChallengeRedirectUri("https://jf.example.com/jellyfin", newPath: false, "kc"));
    }

    [Theory]
    [InlineData("/sso/OID/redirect/kc", "https://jf.example.com/sso/OID/redirect/kc")]
    [InlineData("/sso/OID/r/kc", "https://jf.example.com/sso/OID/r/kc")]
    public void CallbackRedirectUri_EchoesTheCallbackPathSpelling(string callbackPath, string expected)
    {
        Assert.Equal(expected, OidcRedirectUriBuilder.CallbackRedirectUri(Base, callbackPath, "kc"));
    }

    [Fact]
    public void CallbackRedirectUri_ProviderNamedRedirectOnTheClassicRoute_StaysLegacy()
    {
        // The spelling is decided by the exact segment after OID, not by substring matching, so a
        // provider literally named "redirect" cannot flip it (#98, pinned end-to-end here on top of
        // OidcCallbackPathTests).
        Assert.Equal(
            "https://jf.example.com/sso/OID/r/redirect",
            OidcRedirectUriBuilder.CallbackRedirectUri(Base, "/sso/OID/r/redirect", "redirect"));
    }

    [Fact]
    public void CallbackRedirectUri_NullPath_DefaultsToTheLegacySpelling()
    {
        Assert.Equal("https://jf.example.com/sso/OID/r/kc", OidcRedirectUriBuilder.CallbackRedirectUri(Base, null, "kc"));
    }

    [Theory]
    [InlineData("my provider", "https://jf.example.com/sso/OID/r/my provider")]
    [InlineData("käse", "https://jf.example.com/sso/OID/r/käse")]
    public void ChallengeRedirectUri_ProviderIsAppendedRaw_NeverReEncoded(string provider, string expected)
    {
        // Characterizes the contract, not an endorsement: the server never encodes the provider —
        // re-encoding would change the bytes IdPs already have registered and break every working
        // deployment. Rejecting problematic names at registration is #336.
        Assert.Equal(expected, OidcRedirectUriBuilder.ChallengeRedirectUri(Base, newPath: false, provider));
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
            OidcRedirectUriBuilder.ChallengeRedirectUri(Base, newPath, "kc"),
            OidcRedirectUriBuilder.CallbackRedirectUri(Base, $"/sso/OID/{segment}/kc", "kc"));
    }
}
