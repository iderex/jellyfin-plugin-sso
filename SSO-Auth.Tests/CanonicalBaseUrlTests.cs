using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="CanonicalBaseUrl"/> — the helper that decides whether a per-provider base-URL
/// override (#139) is a usable absolute http/https origin and normalizes it. This is the point that
/// keeps a spoofable request Host out of the redirect_uri when an override is set, and the point that
/// rejects a malformed override at save time so it can never reach the login path.
/// </summary>
public class CanonicalBaseUrlTests
{
    [Theory]
    [InlineData("https://jellyfin.example.com", "https://jellyfin.example.com")]
    [InlineData("http://jellyfin.example.com", "http://jellyfin.example.com")]
    [InlineData("https://jellyfin.example.com:8920", "https://jellyfin.example.com:8920")]
    [InlineData("https://jellyfin.example.com/", "https://jellyfin.example.com")] // trailing slash trimmed
    [InlineData("https://example.com/jellyfin/", "https://example.com/jellyfin")] // path base kept, slash trimmed
    [InlineData("  https://jellyfin.example.com  ", "https://jellyfin.example.com")] // surrounding whitespace
    [InlineData("HTTPS://Jellyfin.Example.COM", "https://jellyfin.example.com")] // scheme/host lowercased
    public void TryNormalize_ValidBase_NormalizesAndAccepts(string raw, string expected)
    {
        Assert.True(CanonicalBaseUrl.TryNormalize(raw, out var normalized));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryNormalize_Blank_IsNotAnOverride(string? raw)
    {
        Assert.False(CanonicalBaseUrl.TryNormalize(raw, out var normalized));
        Assert.Null(normalized);
    }

    [Theory]
    [InlineData("jellyfin.example.com")] // no scheme -> relative
    [InlineData("//jellyfin.example.com")] // parses as an absolute file:// URI -> rejected by the scheme check
    [InlineData("ftp://jellyfin.example.com")] // wrong scheme
    [InlineData("file:///etc/passwd")] // wrong scheme
    [InlineData("https://")] // no host
    [InlineData("https://example.com?next=/evil")] // query would corrupt every derived redirect_uri
    [InlineData("https://example.com#frag")] // fragment likewise
    [InlineData("https://user:pass@example.com")] // userinfo can mask the real host
    [InlineData("not a url")]
    public void TryNormalize_Malformed_Rejected(string raw)
    {
        Assert.False(CanonicalBaseUrl.TryNormalize(raw, out var normalized));
        Assert.Null(normalized);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("https://jellyfin.example.com", false)]
    [InlineData("https://example.com/jellyfin/", false)]
    [InlineData("ftp://example.com", true)]
    [InlineData("jellyfin.example.com", true)]
    [InlineData("https://example.com?a=b", true)]
    public void IsInvalidOverride_OnlyNonBlankMalformedValues_AreInvalid(string? raw, bool expected)
    {
        Assert.Equal(expected, CanonicalBaseUrl.IsInvalidOverride(raw));
    }

    // The OID/SAML Add endpoints persist through MutateConfiguration (the live config object), which
    // bypasses ProviderConfigStore.Save's save-time validation, so they gate the incoming override
    // themselves via SSOController.RejectInvalidBaseUrlOverride. Pin that decision so the Add paths cannot
    // regress into persisting a malformed override that then silently falls back to the request Host.

    [Theory]
    [InlineData("not-a-url")]
    [InlineData("ftp://example.com")]
    [InlineData("jellyfin.example.com")]
    public void RejectInvalidBaseUrlOverride_Malformed_Throws(string raw)
    {
        Assert.Throws<System.ArgumentException>(() => SSOController.RejectInvalidBaseUrlOverride(raw));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("https://jellyfin.example.com")]
    [InlineData("https://example.com/jellyfin/")]
    public void RejectInvalidBaseUrlOverride_BlankOrValid_DoesNotThrow(string? raw)
    {
        var exception = Record.Exception(() => SSOController.RejectInvalidBaseUrlOverride(raw));

        Assert.Null(exception);
    }

    // Resolve (#242): the base-URL decision GetRequestBase used to make inline against the live Request.
    // A valid override is authoritative and returned verbatim; otherwise the request-derived host fallback
    // applies (default-port elision, scheme-override allowlist, path-base + trailing-slash handling).

    [Fact]
    public void Resolve_ValidOverride_IsAuthoritative_IgnoresRequestValues()
    {
        var result = CanonicalBaseUrl.Resolve("https://canonical.example.com/", "http", "spoofed.host", 8096, "/pathbase", "http", 1234);

        Assert.Equal("https://canonical.example.com", result);
    }

    [Fact]
    public void Resolve_MalformedNonBlankOverride_ThrowsFailClosed()
    {
        Assert.Throws<System.InvalidOperationException>(
            () => CanonicalBaseUrl.Resolve("ftp://bad", "https", "host.example.com", 443, "", null, null));
    }

    [Theory]
    [InlineData("http", 80, "http://host.example.com")] // default http port elided
    [InlineData("https", 443, "https://host.example.com")] // default https port elided
    [InlineData("https", 80, "https://host.example.com:80")] // non-default for the scheme kept
    [InlineData("http", 8096, "http://host.example.com:8096")] // custom port kept
    public void Resolve_BlankOverride_ElidesDefaultPortOnly(string scheme, int port, string expected)
    {
        var result = CanonicalBaseUrl.Resolve(null, scheme, "host.example.com", port, string.Empty, null, null);

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("http", "http://host.example.com:8096")] // literal http honored
    [InlineData("https", "https://host.example.com:8096")] // literal https honored
    [InlineData("ftp", "https://host.example.com:8096")] // anything else falls back to the request scheme
    [InlineData("HTTP", "https://host.example.com:8096")] // case-sensitive: not honored
    [InlineData("", "https://host.example.com:8096")]
    public void Resolve_SchemeOverride_OnlyLiteralHttpOrHttpsHonored(string schemeOverride, string expected)
    {
        // Non-default port so port elision does not mask the scheme decision.
        var result = CanonicalBaseUrl.Resolve(null, "https", "host.example.com", 8096, string.Empty, schemeOverride, null);

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("http", "https", 443, "https://host.example.com")] // TLS-terminating proxy: http request, https override, 443 elided
    [InlineData("https", "http", 80, "http://host.example.com")] // symmetric: https request, http override, 80 elided
    public void Resolve_ElidesDefaultPortForTheEffectiveScheme(string requestScheme, string schemeOverride, int port, string expected)
    {
        // The default-port elision must decide against the scheme that actually appears in the URL
        // (schemeOverride), not the request scheme — otherwise the canonical URL keeps an explicit
        // :443 / :80 (#272).
        var result = CanonicalBaseUrl.Resolve(null, requestScheme, "host.example.com", port, string.Empty, schemeOverride, null);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void Resolve_PortOverride_WinsOverRequestPort()
    {
        var result = CanonicalBaseUrl.Resolve(null, "https", "host.example.com", 443, string.Empty, null, 8443);

        Assert.Equal("https://host.example.com:8443", result);
    }

    [Theory]
    [InlineData("/jellyfin", "https://host.example.com/jellyfin")] // path base kept
    [InlineData("/jellyfin/", "https://host.example.com/jellyfin")] // trailing slash trimmed
    public void Resolve_PathBase_IsKept_AndTrailingSlashTrimmed(string pathBase, string expected)
    {
        var result = CanonicalBaseUrl.Resolve(null, "https", "host.example.com", 443, pathBase, null, null);

        Assert.Equal(expected, result);
    }
}
