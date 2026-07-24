// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Localization;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SsoLocalizer"/> — the string localizer for the plugin's served surfaces (#913).
/// The lookup resolves through a fallback chain that never blanks: requested culture → base language →
/// English → the key itself.
/// </summary>
public class SsoLocalizerTests
{
    [Fact]
    public void GetString_KnownKey_English_ReturnsTheEnglishValue()
    {
        Assert.Equal("Return to login", SsoLocalizer.GetString("error.return_to_login", "en"));
        Assert.Equal("No matching provider found", SsoLocalizer.GetString("error.no_matching_provider", "en"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GetString_NullOrBlankCulture_ResolvesToEnglish(string? culture)
    {
        Assert.Equal("Invalid or expired state", SsoLocalizer.GetString("error.invalid_state", culture));
    }

    [Fact]
    public void GetString_UnknownCulture_FallsBackToEnglishNeverBlank()
    {
        var value = SsoLocalizer.GetString("error.return_to_login", "xx-YY");

        Assert.Equal("Return to login", value);
    }

    [Fact]
    public void GetString_RegionalVariant_FallsThroughBaseLanguageToEnglish()
    {
        // "en-GB" has no catalog of its own yet; the base-language then English fallback still yields a value.
        Assert.Equal("Return to login", SsoLocalizer.GetString("error.return_to_login", "en-GB"));
    }

    [Fact]
    public void GetString_CultureCaseInsensitive()
    {
        // BCP-47 tags are matched case-insensitively (lower-invariant catalog keys).
        Assert.Equal("Return to login", SsoLocalizer.GetString("error.return_to_login", "EN"));
    }

    [Fact]
    public void GetString_MissingKey_ReturnsTheKeyVerbatim()
    {
        // A key defined in no catalog returns itself — a missing translation is visible, never a blank.
        Assert.Equal("no.such.key", SsoLocalizer.GetString("no.such.key", "en"));
    }

    [Fact]
    public void AvailableCultures_IncludesTheEnglishBaseline()
    {
        Assert.Contains(SsoLocalizer.FallbackCulture, SsoLocalizer.AvailableCultures);
    }
}
