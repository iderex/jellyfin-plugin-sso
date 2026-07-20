using System;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using MediaBrowser.Controller.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins the single outcome-to-HTTP translation (#318): every public rejection category maps to
/// exactly one status and fixed plain-text body, byte-identical to the ReturnError responses the
/// mapper replaced, and the closed sum admits no path to a client-caused 500.
/// </summary>
public class LoginStatusMapperTests
{
    [Fact]
    public void Rejected_MapsEveryReasonToTheExactStatusAndBody()
    {
        // A table Fact rather than a Theory: PublicReason is internal, and a public Theory parameter
        // may not be less accessible than the test method.
        var expected = new (PublicReason Reason, int Status, string Body)[]
        {
            (PublicReason.UnknownProvider, 400, "No matching provider found"),
            (PublicReason.InvalidState, 400, "Invalid or expired state"),
            (PublicReason.AccountLinkForbidden, 403, "SSO login is not permitted for this account."),
            (PublicReason.SsoResponseInvalid, 400, "SSO response validation failed"),
            (PublicReason.SamlResponseInvalid, 400, "SAML response validation failed"),
            (PublicReason.PkceNotSupported, 400, "The identity provider does not advertise the required PKCE (S256) support."),
            (PublicReason.EmailNotVerified, 403, "A verified email is required to log in."),
            (PublicReason.AwaitingApproval, 403, "Your account is not active. It is awaiting administrator approval."),
        };

        // The table itself must stay total: a new member without a row fails here.
        Assert.Equal(Enum.GetValues<PublicReason>().Order(), expected.Select(e => e.Reason).Order());

        foreach (var (reason, status, body) in expected)
        {
            var result = Assert.IsType<ContentResult>(LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(reason)));

            Assert.Equal(status, result.StatusCode);
            Assert.Equal(body, result.Content);
            Assert.Equal("text/plain", result.ContentType);
        }
    }

    [Fact]
    public void EveryPublicReason_MapsWithoutThrowing_AndNeverToA5xx()
    {
        // The executable form of "client-caused conditions structurally cannot become 500s": a future
        // PublicReason member without a mapper entry, or one mapped to a 5xx, fails here before it
        // can ship.
        foreach (var reason in Enum.GetValues<PublicReason>())
        {
            var result = Assert.IsType<ContentResult>(LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(reason)));
            Assert.True(result.StatusCode < 500, $"{reason} must not map to a server-error status");
        }
    }

    [Fact]
    public void UnmappedReasonValue_ThrowsInsteadOfDefaultAccepting()
    {
        Assert.Throws<InvalidOperationException>(() =>
            LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected((PublicReason)999)));
    }

    [Fact]
    public void ForeignOutcomeSubtype_ThrowsInsteadOfDefaultAccepting()
    {
        // The record copy constructor lets an in-assembly (or InternalsVisibleTo) type slip past the
        // private primary constructor — exactly the loophole the sum's doc names. The mapper's unknown-
        // subtype arm turns that misuse into a throw (genuine 500), never a default-accept.
        Assert.Throws<InvalidOperationException>(() =>
            LoginStatusMapper.ToActionResult(new ForeignOutcome(new LoginOutcome.Denied())));
    }

    private sealed record ForeignOutcome : LoginOutcome
    {
        public ForeignOutcome(LoginOutcome original)
            : base(original)
        {
        }
    }

    [Fact]
    public void Denied_MapsToTheUniformUninformative401()
    {
        var result = Assert.IsType<ContentResult>(LoginStatusMapper.ToActionResult(new LoginOutcome.Denied()));

        Assert.Equal(401, result.StatusCode);
        Assert.Equal("Login denied. Your account is not permitted to sign in through this provider.", result.Content);
        Assert.Equal("text/plain", result.ContentType);
    }

    [Fact]
    public void Success_ReturnsTheSameSessionInstanceAs200Json()
    {
        var session = new AuthenticationResult();

        var result = Assert.IsType<OkObjectResult>(LoginStatusMapper.ToActionResult(new LoginOutcome.Success(session)));

        Assert.Same(session, result.Value);
    }

    [Fact]
    public void Throttled_MapsToThe429WithRetryAfter_ByteIdenticalToTheFormerDirectEmission()
    {
        // Characterization of the pre-#474 rate-limit response, now produced only by the mapper: a 429 with
        // the fixed plain-text body and the whole-seconds Retry-After header set to the outcome's value. A
        // fixed retryAfterSeconds keeps the header assertion deterministic (the controller path derives the
        // number from the clock; the exact string it emits is what this pins).
        var response = new DefaultHttpContext().Response;

        var result = Assert.IsType<ContentResult>(LoginStatusMapper.ToActionResult(new LoginOutcome.Throttled(42), response));

        Assert.Equal(429, result.StatusCode);
        Assert.Equal("Too many attempts. Please wait a moment and try again.", result.Content);
        Assert.Equal("text/plain", result.ContentType);
        Assert.Equal("42", response.Headers.RetryAfter.ToString());
    }

    [Fact]
    public void Throttled_ThroughThePureOverload_ThrowsInsteadOfEmittingA429WithoutRetryAfter()
    {
        // Fail closed: the pure overload cannot set Retry-After, so a Throttled that reaches it is a wiring
        // fault and throws (500) rather than silently shipping a 429 with no retry hint.
        Assert.Throws<InvalidOperationException>(() =>
            LoginStatusMapper.ToActionResult(new LoginOutcome.Throttled(5)));
    }

    [Fact]
    public void ResponseAwareOverload_DefersNonThrottledOutcomes_AndSetsNoRetryAfter()
    {
        // The response-aware overload is a superset a caller can route every outcome through: a non-Throttled
        // outcome maps exactly as the pure overload does and leaves the response untouched (no Retry-After).
        var response = new DefaultHttpContext().Response;

        var denied = Assert.IsType<ContentResult>(LoginStatusMapper.ToActionResult(new LoginOutcome.Denied(), response));
        Assert.Equal(401, denied.StatusCode);
        Assert.Equal("Login denied. Your account is not permitted to sign in through this provider.", denied.Content);

        var session = new AuthenticationResult();
        var success = Assert.IsType<OkObjectResult>(LoginStatusMapper.ToActionResult(new LoginOutcome.Success(session), response));
        Assert.Same(session, success.Value);

        Assert.False(response.Headers.ContainsKey("Retry-After"));
    }
}
