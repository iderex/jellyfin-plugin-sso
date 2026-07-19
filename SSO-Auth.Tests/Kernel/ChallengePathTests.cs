using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="ChallengePath.IsNewPath"/> — the new-vs-legacy challenge-route decision that
/// drives the authorization request's redirect_uri spelling. The old inline <c>Contains("/start/")</c>
/// substring test flipped for a provider literally named <c>start</c> reached via the legacy route
/// (<c>/sso/OID/p/start/</c>), minting the wrong redirect_uri that the IdP then rejects (#337).
/// Segment-exact matching keys only on the element right after the protocol.
/// </summary>
public class ChallengePathTests
{
    [Theory]
    [InlineData("/sso/OID/start/keycloak")]
    [InlineData("/sso/SAML/start/adfs")]
    [InlineData("/SSO/OID/Start/keycloak")]
    [InlineData("/jellyfin/sso/OID/start/keycloak")]
    public void IsNewPath_StartRoute_IsTrue(string path)
    {
        Assert.True(ChallengePath.IsNewPath(path));
    }

    [Theory]
    [InlineData("/sso/OID/p/keycloak")]
    [InlineData("/sso/SAML/p/adfs")]
    public void IsNewPath_LegacyRoute_IsFalse(string path)
    {
        Assert.False(ChallengePath.IsNewPath(path));
    }

    [Theory]
    // The #337 fix: a provider NAMED "start" on the legacy route must not flip the spelling —
    // including with a trailing slash, which the old substring "/start/" test wrongly matched.
    [InlineData("/sso/OID/p/start")]
    [InlineData("/sso/OID/p/start/")]
    [InlineData("/sso/SAML/p/start")]
    [InlineData("/sso/OID/p/my-start-provider")]
    public void IsNewPath_ProviderNamedStart_OnLegacyRoute_IsFalse(string path)
    {
        Assert.False(ChallengePath.IsNewPath(path));
    }

    [Fact]
    public void IsNewPath_StartRouteWithProviderNamedStart_IsTrue()
    {
        // The route segment (after the protocol) decides, so the new-path route stays new even when
        // the provider is also named "start".
        Assert.True(ChallengePath.IsNewPath("/sso/OID/start/start"));
    }

    [Theory]
    // A protocol-like reverse-proxy prefix must not decide the spelling: only the route's
    // {protocol}/{path-kind}/{provider} suffix does. The real route below is legacy (OID/p).
    [InlineData("/OID/start/proxy/sso/OID/p/provider")]
    // A doubled internal slash shifts the suffix and must not collapse into a valid new route.
    [InlineData("/sso/OID//start/provider")]
    public void IsNewPath_ProtocolLikePrefixOrInternalEmptySegment_IsFalse(string path)
    {
        Assert.False(ChallengePath.IsNewPath(path));
    }

    [Fact]
    public void IsNewPath_StartRouteBehindProtocolLikePrefix_IsTrue()
    {
        // The suffix is the real route (OID/start/provider); a SAML-like prefix earlier in the path
        // is ignored.
        Assert.True(ChallengePath.IsNewPath("/SAML/prefix/sso/OID/start/provider"));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void IsNewPath_EmptyOrNull_IsFalse(string? path)
    {
        Assert.False(ChallengePath.IsNewPath(path));
    }
}
