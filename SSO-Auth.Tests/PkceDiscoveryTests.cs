using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="PkceDiscovery"/> — reading <c>code_challenge_methods_supported</c> from an
/// OpenID discovery document and failing closed on anything that does not clearly advertise S256 (#141).
/// </summary>
public class PkceDiscoveryTests
{
    [Theory]
    [InlineData("{\"code_challenge_methods_supported\":[\"S256\"]}")]
    [InlineData("{\"code_challenge_methods_supported\":[\"plain\",\"S256\"]}")]
    [InlineData("{\"issuer\":\"https://idp\",\"code_challenge_methods_supported\":[\"S256\"]}")]
    public void S256Advertised_ReturnsTrue(string json)
    {
        Assert.True(PkceDiscovery.SupportsS256(json));
    }

    [Theory]
    [InlineData("{\"code_challenge_methods_supported\":[\"plain\"]}")]
    [InlineData("{\"code_challenge_methods_supported\":[]}")]
    [InlineData("{\"issuer\":\"https://idp\"}")]
    [InlineData("{\"code_challenge_methods_supported\":\"S256\"}")]
    [InlineData("{\"code_challenge_methods_supported\":[256]}")]
    [InlineData("{\"code_challenge_methods_supported\":null}")]
    [InlineData("not-json")]
    [InlineData("")]
    [InlineData(null)]
    public void MissingOrMalformedOrNonS256_ReturnsFalse(string? json)
    {
        Assert.False(PkceDiscovery.SupportsS256(json));
    }

    [Fact]
    public void S256MatchIsCaseSensitive_LowercaseDoesNotCount()
    {
        // The registered value is exactly "S256"; a lowercase "s256" is not RFC-conformant and must not
        // be treated as PKCE support.
        Assert.False(PkceDiscovery.SupportsS256("{\"code_challenge_methods_supported\":[\"s256\"]}"));
    }
}
