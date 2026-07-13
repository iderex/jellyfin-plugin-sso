using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth;
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
}
