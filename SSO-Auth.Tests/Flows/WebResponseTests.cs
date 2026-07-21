// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="WebResponse"/> — the auth-completion page returned to the browser. The
/// server-controlled <c>data</c> value (base64 SAML XML / an OpenID state id) is embedded into the
/// page's JavaScript; it must be emitted as an encoded string literal so it cannot break out of the
/// script context, independent of the base64 shape the callers currently pass.
/// </summary>
public class WebResponseTests
{
    [Fact]
    public void Generator_EmitsDataAsEncodedJsonStringLiteral()
    {
        // A value chosen to break out of a single-quoted literal and inject markup, if unescaped.
        var hostileData = "abc'; </script><script>alert(1)</script>//";

        var html = WebResponse.Generator(hostileData, "keycloak", "https://jf.example.com", "SAML", "n0nce");

        // Emitted via JSON serialization (double-quoted, encoded) rather than a raw single-quoted
        // concatenation.
        Assert.Contains("var data = " + JsonSerializer.Serialize(hostileData) + ";", html);
        // Security property: the injected closing </script> tag must not appear literally in the
        // page, so it cannot terminate the surrounding script and inject markup.
        Assert.DoesNotContain("</script><script>alert(1)", html);
    }

    [Fact]
    public void Generator_BenignBase64Data_RoundTripsAsSameString()
    {
        // The normal case: the embedded value is the same string, only re-quoted. Whatever encoding
        // the serializer applies to individual characters, the requirement is that the runtime
        // value the browser sends back is unchanged; this vector is chosen so the literal is also
        // textually identical.
        var base64 = "PHNhbWxwOlJlc3BvbnNlLz4=";

        var html = WebResponse.Generator(base64, "authelia", "https://jf.example.com", "OID", "n0nce");

        Assert.Contains("var data = \"" + base64 + "\";", html);
    }

    [Fact]
    public void Generator_EmitsProviderAsEncodedConstant_NotRawInUrl()
    {
        // A provider name that would break out of a single-quoted JS/URL literal if interpolated raw.
        var hostileProvider = "p';alert(1);//";

        var html = WebResponse.Generator("ZGF0YQ==", hostileProvider, "https://jf.example.com", "SAML", "n0nce");

        // The provider is emitted once as a JSON-encoded constant and used through
        // encodeURIComponent in the URLs, never concatenated raw.
        Assert.Contains("const ssoProvider = " + JsonSerializer.Serialize(hostileProvider) + ";", html);
        Assert.Contains("encodeURIComponent(ssoProvider)", html);
        Assert.DoesNotContain("';alert(1);//", html);
    }

    [Fact]
    public void Generator_EmitsBaseUrlAsEncodedConstant()
    {
        // The base URL derives from the request host, so it is treated as untrusted and emitted as
        // a JSON-encoded constant rather than interpolated into the script.
        var html = WebResponse.Generator("ZGF0YQ==", "keycloak", "https://jf.example.com", "SAML", "n0nce");

        Assert.Contains("const ssoBaseUrl = \"https://jf.example.com\";", html);
        // URLs are built from the constant, not a raw host string.
        Assert.Contains("ssoBaseUrl + '/web/index.html'", html);
    }

    [Fact]
    public void Generator_EmitsNonceOnInlineScriptAndStyle()
    {
        var html = WebResponse.Generator("ZGF0YQ==", "keycloak", "https://jf.example.com", "OID", "r4nd0mNonce==");

        // The per-response nonce authorizes the page's single inline script and style under the CSP.
        Assert.Contains("<style nonce=\"r4nd0mNonce==\">", html);
        Assert.Contains("<script nonce=\"r4nd0mNonce==\">", html);
        // The placeholder must be fully substituted — no literal token may leak into the page.
        Assert.DoesNotContain("{{NONCE}}", html);
    }

    [Fact]
    public void Generator_UsesNoInlineStyleAttribute_SoStyleSrcNonceHolds()
    {
        // A nonce covers <style> elements but not inline style="" attributes; the iframe's positioning
        // therefore lives in the nonce'd <style> block (#iframe-main), leaving no inline style behind.
        var html = WebResponse.Generator("ZGF0YQ==", "keycloak", "https://jf.example.com", "OID", "n0nce");

        Assert.DoesNotContain("style='", html);
        Assert.DoesNotContain("style=\"", html);
        Assert.Contains("#iframe-main", html);
    }

    [Theory]
    [InlineData("https://jf.example.com", "const ssoBaseUrl = \"https://jf.example.com\";")]
    [InlineData("http://jf.example.com", "const ssoBaseUrl = \"http://jf.example.com\";")]
    public void Generator_SplitsProtocolFromDomain_PreservingScheme(string baseUrl, string expected)
    {
        // The `//` protocol separator is located ordinally (independent of the current culture) and
        // the scheme is preserved verbatim while the domain is punycode-mapped and reassembled. The
        // http/https cases put the separator at different offsets, exercising the split itself.
        var html = WebResponse.Generator("ZGF0YQ==", "keycloak", baseUrl, "OID", "n0nce");

        Assert.Contains(expected, html);
    }

    [Theory]
    [InlineData(true, "if (true) {")]
    [InlineData(false, "if (false) {")]
    public void Generator_EmitsIsLinkingAsJsBooleanLiteral(bool isLinking, string expected)
    {
        // isLinking guards the link leg as a bare JS boolean literal; it must render exactly as
        // `true`/`false` (culture-invariant), never `True`/`False` or a localized casing.
        var html = WebResponse.Generator("ZGF0YQ==", "keycloak", "https://jf.example.com", "SAML", "n0nce", isLinking);

        Assert.Contains(expected, html);
    }

    [Fact]
    public void Generator_SuccessfulLink_IsTerminal_ShowsSuccessAndDoesNotPostToAuthUnconditionally()
    {
        // #614: a successful link (a 2xx from .../Link) is a terminal SUCCESS on the page — it renders a
        // clear success message and must NOT fall through to post the same one-time-consumed assertion /
        // state on to .../Auth (which could never redeem it, so the page showed a misleading login failure).
        var html = WebResponse.Generator("ZGF0YQ==", "keycloak", "https://jf.example.com", "SAML", "n0nce", isLinking: true);

        // The success branch renders the account-linked message keyed on the 2xx range.
        Assert.Contains("linkStatus >= 200 && linkStatus < 300", html);
        Assert.Contains("Account linked. You can now log in with SSO.", html);

        // A definitive link outcome (any non-undefined status) stops the flow before the auth leg. The
        // former `linkStatus < 200 || linkStatus >= 300` condition let a 2xx fall through to .../Auth; that
        // exact predicate must be gone so a successful link can no longer proceed to a login post.
        Assert.DoesNotContain("linkStatus < 200 || linkStatus >= 300", html);
        Assert.Contains("if (linkStatus !== undefined) {", html);

        // The terminality is enforced by a `return;` inside the definitive-status branch, BEFORE the
        // fall-through to the .../Auth post. Assert the ordering directly, so deleting that `return;`
        // (which would silently reintroduce the #614 fall-through) fails this test.
        var gateIdx = html.IndexOf("if (linkStatus !== undefined) {", System.StringComparison.Ordinal);
        var returnAfterGate = html.IndexOf("return;", gateIdx, System.StringComparison.Ordinal);
        var authPostAfterGate = html.IndexOf("/Auth/", gateIdx, System.StringComparison.Ordinal);
        Assert.True(returnAfterGate >= 0 && authPostAfterGate >= 0);
        Assert.True(
            returnAfterGate < authPostAfterGate,
            "a definitive link status must return before the .../Auth post");
    }

    [Fact]
    public void Generator_LinkingPage_KeepsRejectedLinkMessages()
    {
        // The failure path is preserved (#344): a genuinely rejected link still surfaces its own message
        // rather than the login-failure text — a throttled attempt (429) and any other non-2xx are distinct.
        var html = WebResponse.Generator("ZGF0YQ==", "keycloak", "https://jf.example.com", "SAML", "n0nce", isLinking: true);

        Assert.Contains("Too many attempts. Please wait a moment and try again.", html);
        Assert.Contains("Could not link this account. The provider may be disabled, or linking is not permitted.", html);
    }

    [Fact]
    public void Generator_AnnouncesStatusToAssistiveTech_AndDeclaresLanguage()
    {
        // #667: the served page is reached directly by end users. The status line must be an
        // aria-live region so its message swap after the async login attempt is announced, and the
        // document must declare its language.
        var html = WebResponse.Generator("ZGF0YQ==", "keycloak", "https://jf.example.com", "OID", "n0nce");

        Assert.Contains("<html lang='en'>", html);
        Assert.Contains("role='status'", html);
        Assert.Contains("aria-live='polite'", html);
    }

    [Fact]
    public void Generator_TerminalFailure_OffersReturnToLoginLink()
    {
        // #667: a failed or throttled attempt must not dead-end. Both terminal-failure branches call
        // showReturnLink(), which builds a "Return to login" anchor to the known-safe base URL.
        var html = WebResponse.Generator("ZGF0YQ==", "keycloak", "https://jf.example.com", "OID", "n0nce", isLinking: true);

        Assert.Contains("function showReturnLink()", html);
        Assert.Contains("'Return to login'", html);
        Assert.Contains("ssoBaseUrl + '/web/index.html'", html);
        // The login-failure branch and the rejected-link branch both invoke it; success paths do not.
        Assert.Contains("showReturnLink();", html);
        // Pin that the linking branch guards the call behind the failure condition, so a successful
        // (2xx) link does not offer a "return to login" as if it had failed. Deleting the `if (!linked)`
        // guard (which would make the link appear on a successful link too) must fail this test.
        Assert.Contains("if (!linked) {", html);
    }

    [Theory]
    [InlineData("jf.example.com")]
    [InlineData("")]
    public void Generator_BaseUrlWithoutProtocolSeparator_ThrowsInsteadOfMisSplitting(string baseUrl)
    {
        // #679: a baseUrl lacking the "//" separator would otherwise silently mis-split via
        // Substring(0, 1) / Substring(1) and build a corrupt ssoBaseUrl; it must fail closed.
        Assert.Throws<System.ArgumentException>(
            () => WebResponse.Generator("ZGF0YQ==", "keycloak", baseUrl, "OID", "n0nce"));
    }
}
