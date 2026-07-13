using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="AuthPageCsp"/> — the Content-Security-Policy served with the auth page. The
/// policy must deny everything by default, allow only the nonce'd inline script and style, and keep
/// fetch/frame same-origin so the login script can reach <c>/sso/*/Auth</c> and the iframe.
/// </summary>
public class AuthPageCspTests
{
    [Fact]
    public void Build_BindsScriptAndStyleToTheNonce()
    {
        var csp = AuthPageCsp.Build("r4nd0mNonce==");

        Assert.Contains("script-src 'nonce-r4nd0mNonce=='", csp);
        Assert.Contains("style-src 'nonce-r4nd0mNonce=='", csp);
    }

    [Fact]
    public void Build_DeniesByDefaultAndPinsSameOrigin()
    {
        var csp = AuthPageCsp.Build("n0nce");

        Assert.StartsWith("default-src 'none';", csp);
        Assert.Contains("connect-src 'self'", csp);
        Assert.Contains("frame-src 'self'", csp);
        Assert.Contains("base-uri 'none'", csp);
        Assert.Contains("form-action 'none'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
    }

    [Fact]
    public void Build_DoesNotAllowUnsafeInlineOrEval()
    {
        var csp = AuthPageCsp.Build("n0nce");

        // A nonce is the whole point; 'unsafe-inline'/'unsafe-eval' would defeat it.
        Assert.DoesNotContain("unsafe-inline", csp);
        Assert.DoesNotContain("unsafe-eval", csp);
    }
}
