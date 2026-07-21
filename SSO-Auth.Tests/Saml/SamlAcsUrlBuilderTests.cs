// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests pinning the exact bytes <see cref="SamlAcsUrlBuilder"/> produces. The SAML
/// Recipient echo is compared Ordinal by SamlRecipientValidator — byte-for-byte — so the pins here are
/// the primary evidence that refactors change nothing. Since the #790 split the SAML half no longer
/// shares its concatenation with the OIDC builder, so it carries its own raw-provider and path-base pins.
/// </summary>
public class SamlAcsUrlBuilderTests
{
    private const string Base = "https://jf.example.com";

    [Theory]
    [InlineData(false, "https://jf.example.com/sso/SAML/p/idp")]
    [InlineData(true, "https://jf.example.com/sso/SAML/post/idp")]
    public void AcsUrl_SpellingFollowsTheRouteVariant(bool newPath, string expected)
    {
        Assert.Equal(expected, SamlAcsUrlBuilder.AcsUrl(Base, newPath, "idp"));
    }

    [Fact]
    public void AcsUrl_BaseWithPathBase_KeepsItAheadOfTheSsoSegment()
    {
        // CanonicalBaseUrl.Resolve hands over a trailing-slash-free base including the server's path
        // base; the builder's "/sso/..." concatenation relies on exactly that contract.
        Assert.Equal(
            "https://jf.example.com/jellyfin/sso/SAML/p/idp",
            SamlAcsUrlBuilder.AcsUrl("https://jf.example.com/jellyfin", newPath: false, "idp"));
    }

    [Theory]
    [InlineData("my idp", "https://jf.example.com/sso/SAML/p/my idp")]
    [InlineData("käse", "https://jf.example.com/sso/SAML/p/käse")]
    public void AcsUrl_ProviderIsAppendedRaw_NeverReEncoded(string provider, string expected)
    {
        // Characterizes the contract, not an endorsement: the server never encodes the provider —
        // re-encoding would change the bytes IdPs already have registered and break every working
        // deployment. Rejecting problematic names at registration is #336.
        Assert.Equal(expected, SamlAcsUrlBuilder.AcsUrl(Base, newPath: false, provider));
    }

    [Fact]
    public void ExpectedAcsUrls_ReturnsBothSpellings_NewPathFirst()
    {
        // Exact array and order: the Recipient binding iterates this set, and the challenge-time ACS
        // is definitionally one of its members, so the validator cannot drift from the challenge.
        Assert.Equal(
            new[] { "https://jf.example.com/sso/SAML/post/idp", "https://jf.example.com/sso/SAML/p/idp" },
            SamlAcsUrlBuilder.ExpectedAcsUrls(Base, "idp"));
    }
}
