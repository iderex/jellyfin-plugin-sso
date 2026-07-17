using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Unit tests for the <see cref="VerifiedIdentity"/> keystone (#473): both protocols must funnel their
/// validated result into the identical shape the shared mint path consumes, and the type must be
/// unforgeable — obtainable only through the two validation factories. The behavioral proof that a raw or
/// unvalidated response cannot reach the mint lives in the controller suites (an invalid SAML signature or
/// an unredeemed OpenID state is rejected before any provisioning: e.g.
/// <c>SamlAuth_SignedByAnotherCertificate_Returns400</c>, <c>OidAuth</c>'s invalid-state rejections); the
/// structural proof that no third construction path can even compile lives in
/// <c>ArchitectureConformanceTests.VerifiedIdentity_IsConstructedOnlyByProtocolValidators</c>. These tests
/// pin the field mapping each factory performs so the two protocols stay in lock-step.
/// </summary>
public class VerifiedIdentityTests
{
    [Fact]
    public void FromOidcRedemption_MapsEveryFieldFromTheRoleGateResult()
    {
        var derived = new OidcAuthorizeStateBuilder.OidcAuthorizeState(
            Username: "alice",
            Subject: "sub-123",
            EmailVerified: true,
            Valid: true,
            Admin: true,
            EnableLiveTv: true,
            EnableLiveTvManagement: false,
            Folders: new List<string> { "movies", "shows" },
            AvatarUrl: "https://idp.example/a.png");

        var identity = VerifiedIdentity.FromOidcRedemption("keycloak", derived);

        // The two protocol-facing labels drive the link namespace and the audit line.
        Assert.Equal("oid", identity.LinkMode);
        Assert.Equal("OpenID", identity.AuditProtocol);
        Assert.Equal("keycloak", identity.Provider);

        // OpenID keys the link on the stable subject; the username is derived independently.
        Assert.Equal("sub-123", identity.Subject);
        Assert.Equal("alice", identity.Username);
        Assert.Equal(true, identity.EmailVerified);
        Assert.True(identity.Admin);
        Assert.Equal(new[] { "movies", "shows" }, identity.Folders);
        Assert.True(identity.EnableLiveTv);
        Assert.False(identity.EnableLiveTvManagement);
        Assert.Equal("https://idp.example/a.png", identity.AvatarUrl);
    }

    [Fact]
    public void FromValidatedSaml_KeysSubjectAndUsernameOnTheNameId_AndCarriesNoEmailOrAvatar()
    {
        var privileges = new SamlAuthorizeStateBuilder.SamlAuthorizeState(
            Admin: true,
            EnableLiveTv: false,
            EnableLiveTvManagement: true,
            Folders: new List<string> { "movies" });

        var identity = VerifiedIdentity.FromValidatedSaml("okta", "alice@example.com", privileges);

        Assert.Equal("saml", identity.LinkMode);
        Assert.Equal("SAML", identity.AuditProtocol);
        Assert.Equal("okta", identity.Provider);

        // SAML keys the link directly on the NameID: subject and username are the same value.
        Assert.Equal("alice@example.com", identity.Subject);
        Assert.Equal("alice@example.com", identity.Username);

        // SAML carries no email_verified claim and no avatar, so the adoption gate and avatar step are inert.
        Assert.Null(identity.EmailVerified);
        Assert.Null(identity.AvatarUrl);

        Assert.True(identity.Admin);
        Assert.Equal(new[] { "movies" }, identity.Folders);
        Assert.False(identity.EnableLiveTv);
        Assert.True(identity.EnableLiveTvManagement);
    }

    [Fact]
    public void Constructor_IsNotReachableFromOutside_SoTheTypeIsUnforgeable()
    {
        // The security contract at the unit level: nothing outside VerifiedIdentity can construct one, so a
        // caller must go through a validation factory. No declared instance constructor is public, internal,
        // or protected-internal (a sealed record's own copy constructor is unreachable and ignored).
        var reachable = typeof(VerifiedIdentity)
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly)
            .Where(c => c.IsPublic || c.IsAssembly || c.IsFamilyOrAssembly)
            .ToList();

        Assert.Empty(reachable);
    }
}
