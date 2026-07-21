// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcLogout"/> — the RP-initiated end_session URL builder (#727, SLO-2). The security
/// pins: the endpoint must be host-bound to the discovered issuer, and the post_logout_redirect_uri must be
/// allow-listed against this server's canonical base, so a logout can never navigate the browser to an
/// attacker host. A missing endpoint yields null (local-only logout).
/// </summary>
public class OidcLogoutTests
{
    private const string Issuer = "https://idp.example.com";
    private const string EndSession = "https://idp.example.com/protocol/openid-connect/logout";
    private const string Base = "https://jellyfin.example.com";

    [Fact]
    public void Build_HappyPath_IncludesHintClientIdAndAllowedReturn_Escaped()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, "raw.id.token", "jellyfin-client", Base + "/web/", Base);

        Assert.StartsWith(EndSession + "?", url, System.StringComparison.Ordinal);
        Assert.Contains("id_token_hint=raw.id.token", url, System.StringComparison.Ordinal);
        Assert.Contains("client_id=jellyfin-client", url, System.StringComparison.Ordinal);
        // The return URL is present and percent-encoded (the "://" becomes %3A%2F%2F).
        Assert.Contains("post_logout_redirect_uri=https%3A%2F%2Fjellyfin.example.com", url, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Build_NoEndSessionEndpoint_ReturnsNull_ForLocalOnlyLogout()
    {
        Assert.Null(OidcLogout.BuildEndSessionUrl(null, Issuer, "t", "c", Base, Base));
        Assert.Null(OidcLogout.BuildEndSessionUrl("   ", Issuer, "t", "c", Base, Base));
        Assert.Null(OidcLogout.BuildEndSessionUrl("not-a-url", Issuer, "t", "c", Base, Base));
    }

    [Fact]
    public void Build_EndSessionOnADifferentHostThanTheIssuer_ReturnsNull()
    {
        // Host-binding: a discovery document pointing end_session at an attacker host must not redirect there.
        Assert.Null(OidcLogout.BuildEndSessionUrl("https://evil.example.net/logout", Issuer, "t", "c", Base, Base));
        // A different port is also a different authority.
        Assert.Null(OidcLogout.BuildEndSessionUrl("https://idp.example.com:8443/logout", Issuer, "t", "c", Base, Base));
    }

    [Fact]
    public void Build_PostLogoutRedirectOnAnAttackerHost_IsOmitted_NotIncluded()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, "t", "c", "https://evil.example.net/steal", Base);

        Assert.NotNull(url);
        Assert.DoesNotContain("post_logout_redirect_uri", url, System.StringComparison.Ordinal);
        Assert.DoesNotContain("evil.example.net", url, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Build_PostLogoutRedirectUnderTheCanonicalBase_IsAllowed()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, "t", "c", Base + "/sso/goodbye", Base);
        Assert.Contains("post_logout_redirect_uri=", url, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Build_PostLogoutRedirectOnASiblingPrefixHost_IsRejected()
    {
        // A host that merely starts with the base host string is a different authority — must not pass.
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, "t", "c", "https://jellyfin.example.com.evil.net/", Base);
        Assert.DoesNotContain("post_logout_redirect_uri", url, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Build_EndpointWithExistingQuery_AppendsWithAmpersand()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession + "?ui_locales=en", Issuer, "t", "c", null, Base);
        Assert.StartsWith(EndSession + "?ui_locales=en&", url, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Build_NoHintNoReturn_ReturnsTheEndpointWithOnlyClientId()
    {
        var url = OidcLogout.BuildEndSessionUrl(EndSession, Issuer, null, "c", null, Base);
        Assert.Equal(EndSession + "?client_id=c", url);
    }
}
