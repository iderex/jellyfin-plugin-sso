// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="LoginButtonInjector"/> — the pure render/merge core of the managed login-page
/// buttons (#722). The output is HTML rendered on the anonymous, pre-auth login page, so the encoding tests
/// are the security pins: a hostile provider name or button label must never break out into markup.
/// </summary>
public class LoginButtonInjectorTests
{
    private static IReadOnlyList<LoginButton> One(string name, string text, LoginButtonProtocol protocol = LoginButtonProtocol.Oidc)
        => new[] { new LoginButton(protocol, name, text) };

    [Fact]
    public void BuildBlock_NoButtons_IsEmpty()
    {
        Assert.Equal(string.Empty, LoginButtonInjector.BuildBlock(new List<LoginButton>()));
    }

    [Fact]
    public void BuildBlock_IsFencedByTheMarkers()
    {
        var block = LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak"));
        Assert.StartsWith(LoginButtonInjector.BeginMarker, block, System.StringComparison.Ordinal);
        Assert.EndsWith(LoginButtonInjector.EndMarker, block, System.StringComparison.Ordinal);
    }

    [Fact]
    public void BuildBlock_LinksToTheProtocolStartRoute()
    {
        Assert.Contains("href=\"/sso/OID/start/keycloak\"", LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak")));
        Assert.Contains(
            "href=\"/sso/SAML/start/corp\"",
            LoginButtonInjector.BuildBlock(One("corp", "Corp", LoginButtonProtocol.Saml)));
    }

    [Fact]
    public void BuildBlock_HtmlEncodesAHostileLabel_NoScriptSurvives()
    {
        // The XSS pin: a label with markup must render inert. The raw < and " must not appear unencoded, and
        // the literal <script> tag must be gone.
        var block = LoginButtonInjector.BuildBlock(One("prov", "\"><script>alert(1)</script>"));

        Assert.DoesNotContain("<script>", block, System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("&lt;script&gt;", block, System.StringComparison.Ordinal);
        // The label's leading quote+bracket is encoded, so it cannot close the href attribute or the anchor.
        Assert.Contains("&quot;&gt;&lt;script&gt;", block, System.StringComparison.Ordinal);
    }

    [Fact]
    public void BuildBlock_HtmlEncodesAHostileName_InBothHrefAndFallbackLabel()
    {
        // A name is both URL-encoded into the href and (when it is the label) HTML-encoded. Even though names
        // are validated to exclude these characters (#336), the injector must not rely on that.
        var block = LoginButtonInjector.BuildBlock(One("a\"b<c", "a\"b<c"));

        Assert.DoesNotContain("<c", block, System.StringComparison.Ordinal);
        Assert.DoesNotContain("\"b", block, System.StringComparison.Ordinal);
        // URL-encoded in the href (double-encoded: Uri.EscapeDataString then HtmlEncode leaves %-escapes intact).
        Assert.Contains("/sso/OID/start/a%22b%3Cc", block, System.StringComparison.Ordinal);
    }

    [Fact]
    public void BuildBlock_HtmlEncodesAHostileName_OnTheSamlStartRouteToo()
    {
        // The SAML sibling of the pin above (#928 U4): the encoding runs through the shared builder, but the
        // SAML start route was only ever asserted with a clean name — this pins the hostile case per route so
        // a route-specific regression cannot hide behind the shared-code argument.
        var block = LoginButtonInjector.BuildBlock(One("a\"b<c", "a\"b<c", LoginButtonProtocol.Saml));

        Assert.DoesNotContain("<c", block, System.StringComparison.Ordinal);
        Assert.DoesNotContain("\"b", block, System.StringComparison.Ordinal);
        Assert.Contains("/sso/SAML/start/a%22b%3Cc", block, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Merge_AppendsWhenNoRegionExists_PreservingAdminContent()
    {
        var block = LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak"));
        var merged = LoginButtonInjector.Merge("Welcome to our server.", block);

        Assert.StartsWith("Welcome to our server.", merged, System.StringComparison.Ordinal);
        Assert.Contains(LoginButtonInjector.BeginMarker, merged, System.StringComparison.Ordinal);
        Assert.EndsWith(LoginButtonInjector.EndMarker, merged, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Merge_IsIdempotent_ReApplyReplacesOnlyTheManagedRegion()
    {
        var first = LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak"));
        var second = LoginButtonInjector.BuildBlock(One("authelia", "Authelia"));

        var once = LoginButtonInjector.Merge("Admin note.", first);
        var twice = LoginButtonInjector.Merge(once, second);
        var thrice = LoginButtonInjector.Merge(twice, second);

        // Re-applying the same block is a fixed point (no growth, no duplicate region).
        Assert.Equal(twice, thrice);
        // The managed region was REPLACED, not appended: the first provider is gone, the second present, once.
        Assert.DoesNotContain("keycloak", twice, System.StringComparison.Ordinal);
        Assert.Contains("authelia", twice, System.StringComparison.Ordinal);
        Assert.Equal(1, CountOccurrences(twice, LoginButtonInjector.BeginMarker));
        // Admin content outside the region survives every re-apply.
        Assert.StartsWith("Admin note.", twice, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Merge_EmptyBlock_RemovesTheRegion_RestoringSurroundingContent()
    {
        var block = LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak"));
        var withRegion = LoginButtonInjector.Merge("Before.\n\nAfter.", block);

        // Sanity: the region landed between the admin content.
        Assert.Contains(LoginButtonInjector.BeginMarker, withRegion, System.StringComparison.Ordinal);

        var removed = LoginButtonInjector.Merge(withRegion, string.Empty);
        Assert.DoesNotContain(LoginButtonInjector.BeginMarker, removed, System.StringComparison.Ordinal);
        Assert.DoesNotContain(LoginButtonInjector.EndMarker, removed, System.StringComparison.Ordinal);
        Assert.DoesNotContain("keycloak", removed, System.StringComparison.Ordinal);
        // The surrounding admin content is preserved.
        Assert.Contains("Before.", removed, System.StringComparison.Ordinal);
        Assert.Contains("After.", removed, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Merge_EmptyBlock_OnDisclaimerWithNoRegion_IsUnchanged()
    {
        Assert.Equal("Just an admin disclaimer.", LoginButtonInjector.Merge("Just an admin disclaimer.", string.Empty));
        Assert.Equal(string.Empty, LoginButtonInjector.Merge(null, string.Empty));
    }

    [Fact]
    public void Merge_MalformedFence_IsTreatedAsNoRegion_NeverCorruptsContent()
    {
        // Only a BEGIN marker (END hand-deleted): not a well-formed region, so a fresh block appends rather
        // than trying to parse the partial fence — the mangled content is preserved untouched.
        var mangled = "Note.\n" + LoginButtonInjector.BeginMarker + "\nleftover";
        var block = LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak"));
        var merged = LoginButtonInjector.Merge(mangled, block);

        Assert.Contains("leftover", merged, System.StringComparison.Ordinal);
        Assert.EndsWith(LoginButtonInjector.EndMarker, merged, System.StringComparison.Ordinal);
    }

    [Fact]
    public void BuildBlock_HostilePayload_LeavesNoUnescapedMarkupFromInput()
    {
        // Stronger inertness proof than a per-payload substring check: after removing the ONLY markup the
        // template itself emits (the marker comments, the wrapping div, and the fixed anchor tags), no '<'
        // from the input survives — so no provider name or label can introduce an element on the login page.
        var block = LoginButtonInjector.BuildBlock(One("<x>", "<img src=x onerror=alert(1)>"));

        var stripped = block
            .Replace(LoginButtonInjector.BeginMarker, string.Empty, System.StringComparison.Ordinal)
            .Replace(LoginButtonInjector.EndMarker, string.Empty, System.StringComparison.Ordinal)
            .Replace("<div class=\"sso-login-buttons\">", string.Empty, System.StringComparison.Ordinal)
            .Replace("</div>", string.Empty, System.StringComparison.Ordinal)
            .Replace("</a>", string.Empty, System.StringComparison.Ordinal);
        // The anchor open tag's href value is encoded (contains no quote), so [^"]* matches it exactly.
        stripped = Regex.Replace(stripped, "<a class=\"[^\"]*\" href=\"[^\"]*\">", string.Empty);

        Assert.DoesNotContain("<", stripped, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Merge_StrayEndMarkerBeforeARegion_ConvergesWithoutUnboundedGrowth()
    {
        // A hand-mangled disclaimer with a stray END marker BEFORE a real region must not make Merge re-append
        // a fresh block on every sync (which would grow the login disclaimer once per login, as a login's
        // canonical-link write also raises the config-changed event). The closing fence is searched only after
        // the opener, so the real region is replaced in place and the result is a fixed point.
        var region = LoginButtonInjector.Merge("Admin.", LoginButtonInjector.BuildBlock(One("keycloak", "Keycloak")));
        var mangled = LoginButtonInjector.EndMarker + "\nstray\n" + region;

        var next = LoginButtonInjector.BuildBlock(One("authelia", "Authelia"));
        var once = LoginButtonInjector.Merge(mangled, next);
        var twice = LoginButtonInjector.Merge(once, next);

        Assert.Equal(once, twice); // converges — no per-sync growth
        Assert.Equal(1, CountOccurrences(once, LoginButtonInjector.BeginMarker));
        Assert.Contains("authelia", once, System.StringComparison.Ordinal);
        Assert.DoesNotContain("keycloak", once, System.StringComparison.Ordinal);
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var index = 0;
        while ((index = haystack.IndexOf(needle, index, System.StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }

        return count;
    }
}
