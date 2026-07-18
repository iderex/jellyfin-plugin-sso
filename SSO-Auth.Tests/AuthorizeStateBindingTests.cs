using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Behavioral tests for <see cref="AuthorizeStateBinding"/> (#192) — the <c>__Host-sso_*_state_binding</c>
/// browser-binding cookie that is the CSRF / forced-login (session-fixation) defense on both the OpenID
/// (#326) and SAML (#415) callbacks. The helper is pure and previously entirely unasserted, so a refactor
/// could silently weaken the anti-forgery guarantee. These pins fail closed on every hardening property so
/// that flipping <c>HttpOnly</c>/<c>Secure</c> off, widening <c>SameSite</c>, loosening the fail-closed
/// <see cref="AuthorizeStateBinding.Matches"/> gate (e.g. accepting empty/null or a case-insensitive
/// compare), dropping the <c>__Host-</c> constraints (Path=/, no Domain), or shrinking the id entropy each
/// break a test.
/// </summary>
public class AuthorizeStateBindingTests
{
    // --- Matches: true ONLY for two present, byte-equal ids; fail closed otherwise ---

    [Theory]
    [InlineData("state-binding-abc", "state-binding-abc", true)] // equal -> the only match case
    [InlineData("state-binding-abc", "state-binding-xyz", false)] // different value
    [InlineData("state-binding-abc", "STATE-BINDING-ABC", false)] // ordinal: case matters, no OrdinalIgnoreCase
    [InlineData("state-binding-abc", "state-binding-ab", false)] // a prefix is not equal
    [InlineData("state-binding-abc", "", false)] // presented empty -> no match
    [InlineData("", "state-binding-abc", false)] // stored empty -> fail closed (IsNullOrEmpty guard)
    [InlineData("", "", false)] // both empty -> never a match
    public void Matches_IsTrueOnlyForEqualNonEmptyIds(string stored, string presented, bool expected)
        => Assert.Equal(expected, AuthorizeStateBinding.Matches(stored, presented));

    [Fact]
    public void Matches_StoredNull_FailsClosed()
        => Assert.False(AuthorizeStateBinding.Matches(null!, "state-binding-abc"));

    [Fact]
    public void Matches_PresentedNull_FailsClosed()
        => Assert.False(AuthorizeStateBinding.Matches("state-binding-abc", null!));

    [Fact]
    public void Matches_BothNull_FailsClosed()
        => Assert.False(AuthorizeStateBinding.Matches(null!, null!));

    // --- NewId: a fresh, high-entropy, uniquely-minted id every call ---

    [Fact]
    public void NewId_Is64UppercaseHexChars()
    {
        // 256-bit CSPRNG value hex-encoded: 32 bytes -> 64 hex chars, uppercase (Convert.ToHexString).
        // Shrinking the byte count or changing the encoding (which would weaken the unguessability the
        // whole binding relies on) fails here.
        var id = AuthorizeStateBinding.NewId();

        Assert.Equal(64, id.Length);
        Assert.Matches("^[0-9A-F]{64}$", id);
    }

    [Fact]
    public void NewId_TwoCalls_Differ()
        => Assert.NotEqual(AuthorizeStateBinding.NewId(), AuthorizeStateBinding.NewId());

    [Fact]
    public void NewId_ManyCalls_AreAllDistinct()
    {
        // Uniqueness across a large batch: a constant or low-entropy id (a collision) would let one
        // browser's cookie satisfy another's binding check.
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < 1000; i++)
        {
            Assert.True(seen.Add(AuthorizeStateBinding.NewId()), "NewId produced a duplicate id");
        }
    }

    // --- CookieOptions: the __Host- hardened policy ---

    [Fact]
    public void CookieOptions_SetsTheHardenedSecurityAttributes()
    {
        var lifetime = TimeSpan.FromMinutes(15);

        var options = AuthorizeStateBinding.CookieOptions(lifetime);

        Assert.True(options.HttpOnly); // no script access to the binding value
        Assert.True(options.Secure); // HTTPS-only, required by the __Host- prefix
        Assert.Equal(SameSiteMode.Lax, options.SameSite); // Lax, not Strict: sent on the IdP's top-level return nav
        Assert.Equal("/", options.Path); // __Host- constraint: whole-app path
        Assert.Null(options.Domain); // __Host- constraint: host-only, no Domain (blocks sibling-subdomain cookie tossing)
        Assert.Equal(lifetime, options.MaxAge); // bounded to the authorize-state lifetime
    }

    [Theory]
    [InlineData(15)]
    [InlineData(5)]
    public void CookieOptions_MaxAge_MirrorsTheGivenLifetime(int minutes)
    {
        // The cookie's lifetime is exactly the caller-supplied state lifetime (OIDC and SAML pass their
        // own), never a hard-coded value — so the cookie cannot outlive the state it binds.
        var lifetime = TimeSpan.FromMinutes(minutes);

        Assert.Equal(lifetime, AuthorizeStateBinding.CookieOptions(lifetime).MaxAge);
    }

    // --- Cookie names: __Host- prefix + separate OIDC/SAML cookies so neither flow satisfies the other ---

    [Fact]
    public void CookieNames_CarryTheHostPrefix_AndAreDistinctPerFlow()
    {
        Assert.Equal("__Host-sso_oid_state_binding", AuthorizeStateBinding.CookieName);
        Assert.Equal("__Host-sso_saml_state_binding", AuthorizeStateBinding.SamlCookieName);
        Assert.StartsWith("__Host-", AuthorizeStateBinding.CookieName, StringComparison.Ordinal);
        Assert.StartsWith("__Host-", AuthorizeStateBinding.SamlCookieName, StringComparison.Ordinal);

        // Separate names: a SAML binding cookie must not cross-satisfy the OpenID binding check (#415).
        Assert.NotEqual(AuthorizeStateBinding.CookieName, AuthorizeStateBinding.SamlCookieName);
    }
}
