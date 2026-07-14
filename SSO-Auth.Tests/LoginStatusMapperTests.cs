using System;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api;
using MediaBrowser.Controller.Authentication;
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
            (PublicReason.PkceUnverifiable, 400, "The identity provider's PKCE (S256) support could not be verified."),
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
        Assert.Equal("Error. Check permissions.", result.Content);
        Assert.Equal("text/plain", result.ContentType);
    }

    [Fact]
    public void Success_ReturnsTheSameSessionInstanceAs200Json()
    {
        var session = new AuthenticationResult();

        var result = Assert.IsType<OkObjectResult>(LoginStatusMapper.ToActionResult(new LoginOutcome.Success(session)));

        Assert.Same(session, result.Value);
    }
}
