using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="BrowserErrorPage"/> — the re-render of a browser-navigated login rejection (#668).
/// A plain-text error reached by a browser becomes a styled HTML page with a return link; the XHR Auth leg
/// (Accept: application/json) and every non-error result pass through unchanged.
/// </summary>
public class BrowserErrorPageTests
{
    private static HttpContext Context(string accept)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Accept = accept;
        return ctx;
    }

    private static ContentResult PlainError(int status, string message) => new ContentResult
    {
        Content = message,
        ContentType = "text/plain",
        StatusCode = status,
    };

    [Fact]
    public void Wrap_PlainTextError_BrowserAccept_RendersStyledHtmlPreservingStatus()
    {
        var ctx = Context("text/html,application/xhtml+xml");

        var result = Assert.IsType<ContentResult>(
            BrowserErrorPage.Wrap(PlainError(400, "Invalid or expired state"), ctx.Request, ctx.Response));

        Assert.Equal("text/html", result.ContentType);
        Assert.Equal(400, result.StatusCode);
        Assert.Contains("Invalid or expired state", result.Content);
        Assert.Contains("Return to login", result.Content);
        Assert.Contains("href='/web/index.html'", result.Content);
        Assert.Contains("#101010", result.Content); // the dark shell
    }

    [Fact]
    public void Wrap_HtmlEncodesTheMessage_SoIdpSuppliedTextCannotInjectMarkup()
    {
        // A callback error body can interpolate an identity-provider error_description; a hostile value
        // must be encoded, never break out of the <p>.
        var ctx = Context("text/html");
        var hostile = "Error preparing login: </p><script>alert(1)</script>";

        var result = Assert.IsType<ContentResult>(
            BrowserErrorPage.Wrap(PlainError(400, hostile), ctx.Request, ctx.Response));

        Assert.DoesNotContain("<script>alert(1)</script>", result.Content);
        Assert.Contains("&lt;script&gt;", result.Content);
    }

    [Fact]
    public void Wrap_SetsScriptlessCspNonceAndDefensiveHeaders_NonceMatchesTheStyleTag()
    {
        var ctx = Context("text/html");

        var result = Assert.IsType<ContentResult>(
            BrowserErrorPage.Wrap(PlainError(401, "Login denied."), ctx.Request, ctx.Response));

        var csp = ctx.Response.Headers.ContentSecurityPolicy.ToString();
        Assert.Contains("default-src 'none'", csp);
        Assert.DoesNotContain("script-src", csp); // no script on this page
        Assert.Equal("DENY", ctx.Response.Headers["X-Frame-Options"].ToString());
        Assert.Equal("nosniff", ctx.Response.Headers["X-Content-Type-Options"].ToString());
        Assert.Equal("no-store", ctx.Response.Headers.CacheControl.ToString());
        Assert.Contains("camera=()", ctx.Response.Headers["Permissions-Policy"].ToString());

        // The nonce authorizing the inline <style> must be the exact nonce bound in the CSP.
        var nonce = Regex.Match(csp, "style-src 'nonce-([^']+)'").Groups[1].Value;
        Assert.NotEqual(string.Empty, nonce);
        Assert.Contains("<style nonce='" + nonce + "'>", result.Content);
    }

    [Fact]
    public void Wrap_XhrJsonAccept_PassesThroughUnchanged()
    {
        // The XHR Auth leg reads the status, not the body; it must keep the plain-text shape.
        var ctx = Context("application/json");
        var original = PlainError(401, "Login denied.");

        var result = BrowserErrorPage.Wrap(original, ctx.Request, ctx.Response);

        Assert.Same(original, result);
        Assert.True(ctx.Response.Headers.ContentSecurityPolicy.Count == 0);
    }

    [Fact]
    public void Wrap_StringObjectResultError_BrowserAccept_IsRestyled()
    {
        var ctx = Context("text/html");

        var result = Assert.IsType<ContentResult>(
            BrowserErrorPage.Wrap(new BadRequestObjectResult("No matching provider found"), ctx.Request, ctx.Response));

        Assert.Equal("text/html", result.ContentType);
        Assert.Equal(400, result.StatusCode);
        Assert.Contains("No matching provider found", result.Content);
    }

    [Fact]
    public void Wrap_SuccessResult_PassesThroughUnchanged()
    {
        var ctx = Context("text/html");
        var ok = new OkObjectResult(new { session = "x" });

        Assert.Same(ok, BrowserErrorPage.Wrap(ok, ctx.Request, ctx.Response));
    }

    [Fact]
    public void Wrap_AlreadyHtmlResult_PassesThroughUnchanged()
    {
        // The auth-completion page is text/html; it is not a plain-text error and must not be re-wrapped.
        var ctx = Context("text/html");
        var authPage = new ContentResult { Content = "<html></html>", ContentType = "text/html" };

        Assert.Same(authPage, BrowserErrorPage.Wrap(authPage, ctx.Request, ctx.Response));
    }
}
