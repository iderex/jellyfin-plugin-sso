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

        var html = WebResponse.Generator(hostileData, "keycloak", "https://jf.example.com", "SAML");

        // Emitted via JSON serialization (double-quoted, fully escaped) rather than a raw
        // single-quoted concatenation.
        Assert.Contains("var data = " + JsonSerializer.Serialize(hostileData) + ";", html);
        // The raw break-out sequence must not survive into the page (the default encoder escapes
        // "<" to <, so the injected script tags cannot terminate the surrounding script).
        Assert.DoesNotContain("</script><script>alert(1)", html);
    }

    [Fact]
    public void Generator_BenignBase64Data_RoundTripsAsSameString()
    {
        // A base64 value without '+' (which the encoder would escape to +): it serializes
        // byte-identically, so the embedded literal is the same string, only re-quoted. Base64 with
        // '+' still round-trips at runtime (+ parses back to '+') — the wire value is unchanged.
        var base64 = "PHNhbWxwOlJlc3BvbnNlLz4=";

        var html = WebResponse.Generator(base64, "authelia", "https://jf.example.com", "OID");

        Assert.Contains("var data = \"" + base64 + "\";", html);
    }
}
