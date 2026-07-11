using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcCallbackPath.RedirectSegment"/> — the r/redirect choice for rebuilding
/// the callback's redirect_uri. The token request's redirect_uri must match the authorization
/// request's, and the IdP calls back on exactly the advertised route, so the segment must mirror
/// the callback path. The old inline expression tested for "/start/" (never present on callback
/// routes) and therefore always produced "r", breaking the new-path flow against spec-enforcing
/// IdPs (#98).
/// </summary>
public class OidcCallbackPathTests
{
    [Theory]
    [InlineData("/sso/OID/redirect/keycloak", "redirect")]
    [InlineData("/sso/OID/r/keycloak", "r")]
    [InlineData("/SSO/OID/Redirect/keycloak", "redirect")]
    public void RedirectSegment_MirrorsTheCallbackRoute(string path, string expected)
    {
        Assert.Equal(expected, OidcCallbackPath.RedirectSegment(path));
    }

    [Theory]
    // A provider NAMED "redirect" must never flip the classic route — including with a trailing
    // slash, which a substring "/redirect/" test would wrongly match (the N1 corner both reviews
    // flagged). Segment-exact matching keys only on the element right after "OID".
    [InlineData("/sso/OID/r/redirect")]
    [InlineData("/sso/OID/r/redirect/")]
    [InlineData("/sso/OID/r/my-redirect-provider")]
    public void RedirectSegment_ProviderNamedRedirect_OnClassicRoute_StaysR(string path)
    {
        Assert.Equal("r", OidcCallbackPath.RedirectSegment(path));
    }

    [Fact]
    public void RedirectSegment_RedirectRouteWithProviderNamedRedirect_IsRedirect()
    {
        // The new-path route with a provider also named "redirect": the route segment (after OID)
        // decides, so this is correctly "redirect".
        Assert.Equal("redirect", OidcCallbackPath.RedirectSegment("/sso/OID/redirect/redirect"));
    }

    [Fact]
    public void RedirectSegment_EmptyPath_DefaultsToClassic()
    {
        Assert.Equal("r", OidcCallbackPath.RedirectSegment(string.Empty));
    }

    [Fact]
    public void RedirectSegment_NullPath_DefaultsToClassic()
    {
        Assert.Equal("r", OidcCallbackPath.RedirectSegment(null));
    }
}
