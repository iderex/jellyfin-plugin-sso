using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="AdoptionEligibilityResolver"/> — the fail-closed gate that hardens same-named
/// account adoption (#218). Two protocol-agnostic rules: an administrator target is never adopted by name,
/// and when the provider requires it the login must carry <c>email_verified == true</c>. The full decision
/// matrix (admin × require × claim) is pinned here so a regression cannot silently re-open the takeover.
/// </summary>
public class AdoptionEligibilityResolverTests
{
    [Theory]
    [InlineData(false, null)]  // gate off, no claim
    [InlineData(false, true)]  // gate off, verified
    [InlineData(true, true)]   // gate on, verified
    public void AdminTarget_IsAlwaysRefused(bool requireVerifiedEmail, bool? emailVerified)
    {
        var verdict = AdoptionEligibilityResolver.Resolve(
            targetIsAdministrator: true,
            new AdoptionGate(requireVerifiedEmail, emailVerified));

        Assert.Equal(AdoptionVerdict.RefusePrivileged, verdict);
    }

    [Theory]
    [InlineData(null)] // claim absent
    [InlineData(true)] // verified
    [InlineData(false)] // explicitly unverified
    public void NonAdmin_GateOff_IsAlwaysAllowed(bool? emailVerified)
    {
        // Default posture: adoption proceeds without a verified-email requirement, preserving current
        // AllowExistingAccountLink deployments.
        var verdict = AdoptionEligibilityResolver.Resolve(
            targetIsAdministrator: false,
            new AdoptionGate(RequireVerifiedEmail: false, emailVerified));

        Assert.Equal(AdoptionVerdict.Allow, verdict);
    }

    [Fact]
    public void NonAdmin_GateOn_VerifiedTrue_IsAllowed()
    {
        var verdict = AdoptionEligibilityResolver.Resolve(
            targetIsAdministrator: false,
            new AdoptionGate(RequireVerifiedEmail: true, EmailVerified: true));

        Assert.Equal(AdoptionVerdict.Allow, verdict);
    }

    [Theory]
    [InlineData(false)] // email_verified == false
    [InlineData(null)]  // claim absent — treated like false (fail closed)
    public void NonAdmin_GateOn_ClaimFalseOrAbsent_IsRefused(bool? emailVerified)
    {
        var verdict = AdoptionEligibilityResolver.Resolve(
            targetIsAdministrator: false,
            new AdoptionGate(RequireVerifiedEmail: true, emailVerified));

        Assert.Equal(AdoptionVerdict.RefuseUnverifiedEmail, verdict);
    }

    [Fact]
    public void None_IsTheOpenPosture_ForANonAdminTarget()
    {
        // AdoptionGate.None is what SAML and the legacy call sites pass: no verified-email requirement.
        Assert.Equal(AdoptionVerdict.Allow, AdoptionEligibilityResolver.Resolve(targetIsAdministrator: false, AdoptionGate.None));
    }
}
