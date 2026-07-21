// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins the shared HTTP result shapes both login flows render (#160): the plain-text error, the
/// security-headered intermediate auth page, and the manual-link write mapping. These builders decide
/// the exact status, body, content-type, and defensive headers on the wire, so each behaviour gets an
/// assertion against the actual output rather than the intent.
/// </summary>
public class FlowResponsesTests
{
    [Fact]
    public void PlainTextError_CarriesTheStatusBodyAndPlainContentType()
    {
        var result = FlowResponses.PlainTextError(503, "store at capacity");

        Assert.Equal(503, result.StatusCode);
        Assert.Equal("store at capacity", result.Content);
        Assert.Equal("text/plain", result.ContentType);
    }

    [Fact]
    public void PlainTextError_PreservesTheGivenStatusVerbatim()
    {
        // The code is passed straight through — a 400 request error and a 500 server error stay distinct.
        Assert.Equal(400, FlowResponses.PlainTextError(400, "bad").StatusCode);
        Assert.Equal(500, FlowResponses.PlainTextError(500, "boom").StatusCode);
    }

    [Fact]
    public void AuthPage_RendersTheDelegateOutputAsHtml()
    {
        var response = new DefaultHttpContext().Response;

        var result = FlowResponses.AuthPage(response, nonce => "<html>body</html>");

        Assert.Equal("<html>body</html>", result.Content);
        Assert.Equal("text/html", result.ContentType);
        // The auth page is the login completion surface, never an error: no status override, so it 200s.
        Assert.Null(result.StatusCode);
    }

    [Fact]
    public void AuthPage_SetsEveryDefensiveHeader()
    {
        var response = new DefaultHttpContext().Response;

        FlowResponses.AuthPage(response, nonce => "<html></html>");

        // The page carries the one-time state token / signed assertion, so it must not be framed,
        // MIME-sniffed, cached, or leak its URL via Referer.
        Assert.Equal("DENY", response.Headers["X-Frame-Options"]);
        Assert.Equal("nosniff", response.Headers["X-Content-Type-Options"]);
        Assert.Equal("no-referrer", response.Headers["Referrer-Policy"]);
        Assert.Equal("no-store", response.Headers.CacheControl.ToString());
        // A restrictive Permissions-Policy denies powerful features the login-completion page never uses.
        var permissionsPolicy = response.Headers["Permissions-Policy"].ToString();
        Assert.Contains("camera=()", permissionsPolicy);
        Assert.Contains("geolocation=()", permissionsPolicy);
        Assert.Contains("microphone=()", permissionsPolicy);
        Assert.False(string.IsNullOrEmpty(response.Headers.ContentSecurityPolicy.ToString()));
    }

    [Fact]
    public void AuthPage_ThreadsTheSamePerResponseNonceIntoBothTheCspAndTheRenderer()
    {
        var response = new DefaultHttpContext().Response;
        string? renderedNonce = null;

        FlowResponses.AuthPage(response, nonce =>
        {
            renderedNonce = nonce;
            return "<html></html>";
        });

        Assert.NotNull(renderedNonce);
        // The renderer's nonce is exactly the one the CSP header locks the inline script/style to;
        // AuthPageCsp.Build reproduced from that same nonce must equal the emitted policy.
        Assert.Equal(AuthPageCsp.Build(renderedNonce!), response.Headers.ContentSecurityPolicy.ToString());
        Assert.Contains($"'nonce-{renderedNonce}'", response.Headers.ContentSecurityPolicy.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void AuthPage_NonceIsSixteenFreshRandomBytesPerCall()
    {
        var response = new DefaultHttpContext().Response;

        string? first = null;
        string? second = null;
        FlowResponses.AuthPage(new DefaultHttpContext().Response, n => { first = n; return string.Empty; });
        FlowResponses.AuthPage(response, n => { second = n; return string.Empty; });

        Assert.NotNull(first);
        Assert.NotNull(second);
        // 128 bits of entropy, base64-encoded — decodes back to 16 bytes.
        Assert.Equal(16, Convert.FromBase64String(first!).Length);
        // A fresh nonce per response: reuse would let one page's script run under another page's policy.
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void MapCanonicalLinkWrite_Created_IsA204NoContent()
    {
        var result = FlowResponses.MapCanonicalLinkWrite(CanonicalLinkWriteResult.Created);

        var noContent = Assert.IsType<NoContentResult>(result);
        Assert.Equal(204, noContent.StatusCode);
    }

    [Fact]
    public void MapCanonicalLinkWrite_EmptyKey_IsA400WithTheIdentityBody()
    {
        var result = FlowResponses.MapCanonicalLinkWrite(CanonicalLinkWriteResult.EmptyKey);

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(400, badRequest.StatusCode);
        Assert.Equal("The SSO login did not resolve an identity.", badRequest.Value);
    }

    [Fact]
    public void MapCanonicalLinkWrite_UnknownProvider_IsA400WithTheSharedProviderMessage()
    {
        var result = FlowResponses.MapCanonicalLinkWrite(CanonicalLinkWriteResult.UnknownProvider);

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(400, badRequest.StatusCode);
        // Reuses the mapper's constant so the empty-key and unknown-provider refusals keep distinct wording.
        Assert.Equal(LoginStatusMapper.NoMatchingProviderMessage, badRequest.Value);
        Assert.NotEqual("The SSO login did not resolve an identity.", badRequest.Value);
    }

    [Fact]
    public void MapCanonicalLinkWrite_EveryDefinedResult_MapsWithoutThrowing()
    {
        // Totality guard: a new CanonicalLinkWriteResult member without a mapping arm fails here.
        foreach (var value in Enum.GetValues<CanonicalLinkWriteResult>())
        {
            var result = FlowResponses.MapCanonicalLinkWrite(value);
            Assert.NotNull(result);
        }
    }

    [Fact]
    public void MapCanonicalLinkWrite_UnhandledResult_ThrowsInsteadOfDefaultAccepting()
    {
        // Fail closed: an out-of-range value is a wiring fault and throws (500), never a silent wrong status.
        Assert.Throws<InvalidOperationException>(() =>
            FlowResponses.MapCanonicalLinkWrite((CanonicalLinkWriteResult)999));
    }
}
