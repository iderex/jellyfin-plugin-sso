// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
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

    [Theory]
    // A protocol-like reverse-proxy prefix that itself spells "OID/redirect" must not flip the
    // classic route: only the {protocol}/{path-kind}/{provider} suffix decides, so the real "r"
    // route stays "r" no matter what the mount prefix looks like (#411).
    [InlineData("/OID/redirect/proxy/sso/OID/r/keycloak", "r")]
    // The mirror: a prefix spelling "OID/r" must not flip a real new-path route away from "redirect".
    [InlineData("/OID/r/proxy/sso/OID/redirect/keycloak", "redirect")]
    public void RedirectSegment_ProtocolLikePrefix_LetsTheSuffixDecide(string path, string expected)
    {
        Assert.Equal(expected, OidcCallbackPath.RedirectSegment(path));
    }

    [Fact]
    public void RedirectSegment_LegitReverseProxyBasePath_KeepsNewPathRoute()
    {
        // A benign reverse-proxy base path in front of a real new-path callback keeps the intact
        // OID/redirect/{provider} suffix, so it is still correctly "redirect" — the suffix anchoring
        // must not misclassify legitimate mounts.
        Assert.Equal("redirect", OidcCallbackPath.RedirectSegment("/jellyfin/apps/sso/OID/redirect/keycloak"));
    }

    [Fact]
    public void RedirectSegment_InternalDoubledSlash_FailsSafeToClassic()
    {
        // An internal doubled slash inserts an empty segment that shifts the suffix, so the malformed
        // path no longer matches OID/redirect/{provider} and fails safe to the classic "r" spelling
        // rather than being silently collapsed into a valid new-path route (#411).
        Assert.Equal("r", OidcCallbackPath.RedirectSegment("/sso/OID/redirect//keycloak"));
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
