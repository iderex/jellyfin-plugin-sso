using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="RouteSuffix.TryRead"/> — the trim/split/anchor mechanics shared by
/// <see cref="ChallengePath.IsNewPath"/> and <see cref="OidcCallbackPath.RedirectSegment"/> (#509).
/// <see cref="ChallengePathTests"/> and <see cref="OidcCallbackPathTests"/> already cover the two
/// callers' terminal comparisons end to end; these tests cover the reader itself in isolation.
/// </summary>
public class RouteSuffixTests
{
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void TryRead_EmptyOrNullPath_ReturnsFalse(string? path)
    {
        Assert.False(RouteSuffix.TryRead(path, out _));
    }

    [Theory]
    [InlineData("/sso")]
    [InlineData("/sso/OID")]
    [InlineData("sso/OID")]
    public void TryRead_FewerThanThreeSegments_ReturnsFalse(string path)
    {
        Assert.False(RouteSuffix.TryRead(path, out _));
    }

    [Fact]
    public void TryRead_ThreeOrMoreSegments_ReadsTheLastThreeAsTheSuffix()
    {
        Assert.True(RouteSuffix.TryRead("/sso/OID/start/keycloak", out var suffix));
        Assert.Equal("OID", suffix.Protocol);
        Assert.Equal("start", suffix.PathKind);
    }

    [Fact]
    public void TryRead_TrimsOnlyBoundarySlashes()
    {
        // Leading/trailing slashes are trimmed, but the segment count is otherwise untouched.
        Assert.True(RouteSuffix.TryRead("sso/OID/start/keycloak/", out var suffix));
        Assert.Equal("OID", suffix.Protocol);
        Assert.Equal("start", suffix.PathKind);
    }

    [Fact]
    public void TryRead_InternalDoubledSlash_ShiftsTheSuffixInsteadOfCollapsing()
    {
        // The doubled slash inserts an empty segment, so the suffix read off the END of the path no
        // longer names the real protocol/path-kind pair — it must not be silently collapsed away.
        Assert.True(RouteSuffix.TryRead("/sso/OID//start/keycloak", out var suffix));
        Assert.Equal(string.Empty, suffix.Protocol);
        Assert.Equal("start", suffix.PathKind);
    }

    [Fact]
    public void TryRead_IgnoresPrefixSegmentsBeforeTheSuffix()
    {
        // A protocol-like reverse-proxy prefix earlier in the path must not be picked up: only the
        // last three segments count.
        Assert.True(RouteSuffix.TryRead("/OID/start/proxy/sso/SAML/redirect/keycloak", out var suffix));
        Assert.Equal("SAML", suffix.Protocol);
        Assert.Equal("redirect", suffix.PathKind);
    }
}
