using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
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
    public void FromValidatedOidc_SetsTheOpenIdLabels_AndCopiesEveryValidatedField()
    {
        var login = new ValidatedLogin
        {
            Provider = "keycloak",
            Subject = "sub-123",
            Issuer = "https://issuer.example",
            Username = "alice",
            EmailVerified = true,
            Admin = true,
            Folders = new List<string> { "movies", "shows" },
            EnableLiveTv = true,
            EnableLiveTvManagement = false,
            AvatarUrl = "https://idp.example/a.png",
            PermissionGrants = Array.Empty<PermissionGrant>(),
        };

        var identity = VerifiedIdentity.FromValidatedOidc(login);

        // The factory sets the two protocol-facing labels that drive the link namespace and the audit line...
        Assert.Equal(ProviderMode.Oid, identity.LinkMode);
        Assert.Equal("OpenID", identity.AuditProtocol);

        // ...and copies every validated field verbatim. OpenID keys the link on the stable subject; the
        // issuer is carried onto the identity to issuer-bind the canonical link (#186).
        Assert.Equal("keycloak", identity.Provider);
        Assert.Equal("sub-123", identity.Subject);
        Assert.Equal("https://issuer.example", identity.Issuer);
        Assert.Equal("alice", identity.Username);
        Assert.Equal(true, identity.EmailVerified);
        Assert.True(identity.Admin);
        Assert.Equal(new[] { "movies", "shows" }, identity.Folders);
        Assert.True(identity.EnableLiveTv);
        Assert.False(identity.EnableLiveTvManagement);
        Assert.Equal("https://idp.example/a.png", identity.AvatarUrl);
    }

    [Fact]
    public void FromValidatedSaml_SetsTheSamlLabels_AndCopiesEveryValidatedField()
    {
        var login = new ValidatedLogin
        {
            Provider = "okta",
            Subject = "alice@example.com",
            Issuer = null,
            Username = "alice@example.com",
            EmailVerified = null,
            Admin = true,
            Folders = new List<string> { "movies" },
            EnableLiveTv = false,
            EnableLiveTvManagement = true,
            AvatarUrl = null,
            PermissionGrants = Array.Empty<PermissionGrant>(),
        };

        var identity = VerifiedIdentity.FromValidatedSaml(login);

        Assert.Equal(ProviderMode.Saml, identity.LinkMode);
        Assert.Equal("SAML", identity.AuditProtocol);
        Assert.Equal("okta", identity.Provider);
        Assert.Equal("alice@example.com", identity.Subject);
        Assert.Equal("alice@example.com", identity.Username);
        Assert.Null(identity.EmailVerified);
        Assert.Null(identity.AvatarUrl);
        Assert.Null(identity.Issuer);
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
