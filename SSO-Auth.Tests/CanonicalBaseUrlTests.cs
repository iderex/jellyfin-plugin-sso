using Jellyfin.Plugin.SSO_Auth.Api;
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
    // bypasses SSOPlugin.UpdateConfiguration's save-time validation, so they gate the incoming override
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
        SSOController.RejectInvalidBaseUrlOverride(raw);
    }
}
