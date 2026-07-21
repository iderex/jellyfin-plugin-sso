// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="ParentalRatingPolicy"/> — the role → parental-rating-score reducer (#736). Fail
/// closed toward the LESS permissive outcome: the feature off, no mapping matched, or an empty allow-list
/// all yield null (leave the existing ceiling), and when several mappings match the MINIMUM (most
/// restrictive) score wins, never the loosest.
/// </summary>
public class ParentalRatingPolicyTests
{
    private static OidConfig Config(bool enabled, params ParentalRatingRoleMap[] maps) => new OidConfig
    {
        EnableParentalRatingRoles = enabled,
        ParentalRatingRoleMappings = new List<ParentalRatingRoleMap>(maps),
    };

    private static ParentalRatingRoleMap Map(int score, params string[] roles) => new ParentalRatingRoleMap { Score = score, Roles = roles };

    [Fact]
    public void Resolve_FeatureOff_ReturnsNull()
        => Assert.Null(ParentalRatingPolicy.Resolve(new[] { "kids" }, Config(enabled: false, Map(5, "kids"))));

    [Fact]
    public void Resolve_NullMappings_ReturnsNull()
        => Assert.Null(ParentalRatingPolicy.Resolve(new[] { "kids" }, new OidConfig { EnableParentalRatingRoles = true, ParentalRatingRoleMappings = null }));

    [Fact]
    public void Resolve_NoRoleMatches_ReturnsNull()
        => Assert.Null(ParentalRatingPolicy.Resolve(new[] { "adults" }, Config(enabled: true, Map(5, "kids"))));

    [Fact]
    public void Resolve_SingleMatch_ReturnsItsScore()
        => Assert.Equal(5, ParentalRatingPolicy.Resolve(new[] { "kids" }, Config(enabled: true, Map(5, "kids"))));

    [Fact]
    public void Resolve_MultipleMatches_ReturnsTheMinimumMostRestrictive()
        => Assert.Equal(3, ParentalRatingPolicy.Resolve(new[] { "a", "b" }, Config(enabled: true, Map(10, "a"), Map(3, "b"), Map(7, "c"))));

    [Fact]
    public void Resolve_MatchAcrossSeparateEntries_TakesTheStricter_EvenWhenTheLooserComesFirst()
        => Assert.Equal(2, ParentalRatingPolicy.Resolve(new[] { "teens", "littles" }, Config(enabled: true, Map(9, "teens"), Map(2, "littles"))));

    [Fact]
    public void Resolve_ZeroScore_IsRespected()
        => Assert.Equal(0, ParentalRatingPolicy.Resolve(new[] { "kids" }, Config(enabled: true, Map(0, "kids"))));

    [Fact]
    public void Resolve_NullEntry_IsSkipped_OtherMatchesStillApply()
        => Assert.Equal(5, ParentalRatingPolicy.Resolve(new[] { "kids" }, Config(enabled: true, null!, Map(5, "kids"))));

    [Fact]
    public void Resolve_MappingWithNoRoles_NeverMatches()
        => Assert.Null(ParentalRatingPolicy.Resolve(new[] { "kids" }, Config(enabled: true, Map(5))));

    [Fact]
    public void Resolve_ConfiguredRoleIsTrimmed()
        => Assert.Equal(5, ParentalRatingPolicy.Resolve(new[] { "kids" }, Config(enabled: true, Map(5, "  kids  "))));

    [Fact]
    public void Resolve_MatchingIsOrdinalCaseSensitive()
        => Assert.Null(ParentalRatingPolicy.Resolve(new[] { "kids" }, Config(enabled: true, Map(5, "Kids"))));
}
