// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Localization;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="AcceptLanguage"/> — picking the best loaded culture from a request's
/// Accept-Language header (#913): q-ordering, base-language fallback, q=0 rejection, wildcard, and the
/// safe null result that sends the caller to the English fallback.
/// </summary>
public class AcceptLanguageTests
{
    private static readonly string[] Available = ["en", "de", "fr"];

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Resolve_NullOrBlankHeader_ReturnsNull(string? header)
    {
        Assert.Null(AcceptLanguage.Resolve(header, Available));
    }

    [Fact]
    public void Resolve_ExactTag_IsPicked()
    {
        Assert.Equal("de", AcceptLanguage.Resolve("de", Available));
    }

    [Fact]
    public void Resolve_HighestQualityWins()
    {
        // fr is listed first but de outranks it on quality.
        Assert.Equal("de", AcceptLanguage.Resolve("fr;q=0.5, de;q=0.9", Available));
    }

    [Fact]
    public void Resolve_EqualQuality_KeepsHeaderOrder()
    {
        // Both default to q=1.0; the header's left-to-right order breaks the tie.
        Assert.Equal("de", AcceptLanguage.Resolve("de, fr", Available));
    }

    [Fact]
    public void Resolve_RegionalVariant_FallsBackToBaseLanguage()
    {
        // No "de-CH" catalog, but the base language "de" is available.
        Assert.Equal("de", AcceptLanguage.Resolve("de-CH", Available));
    }

    [Fact]
    public void Resolve_HigherRankedUnavailable_FallsToNextAvailable()
    {
        // es (unavailable, top q) is skipped; fr (available, lower q) wins over the base of es.
        Assert.Equal("fr", AcceptLanguage.Resolve("es;q=0.9, fr;q=0.4", Available));
    }

    [Fact]
    public void Resolve_NoAvailableLanguage_ReturnsNull()
    {
        Assert.Null(AcceptLanguage.Resolve("es, it", Available));
    }

    [Fact]
    public void Resolve_QualityZero_RejectsThatLanguage()
    {
        // de is explicitly refused (q=0); en is the only remaining choice.
        Assert.Equal("en", AcceptLanguage.Resolve("de;q=0, en;q=0.5", Available));
    }

    [Fact]
    public void Resolve_Wildcard_IsNotMatchedToASpecificCulture()
    {
        Assert.Null(AcceptLanguage.Resolve("*", Available));
    }

    [Fact]
    public void Resolve_IsCaseInsensitive()
    {
        Assert.Equal("de", AcceptLanguage.Resolve("DE-de", Available));
    }

    [Fact]
    public void Resolve_MalformedHeader_ReturnsNullNeverThrows()
    {
        // A garbage header parses to nothing usable; the caller falls back to English, never a crash.
        Assert.Null(AcceptLanguage.Resolve(";;;===", Available));
    }
}
