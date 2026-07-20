#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>
/// The outcome of the adoption-eligibility gate: whether a name-matched pre-existing account may be
/// adopted, or the specific reason it is refused. Closed by convention (the caller throws on an
/// unhandled arm), so a new reason forces a new mapping rather than a silent fall-through.
/// </summary>
internal enum AdoptionVerdict
{
    /// <summary>The pre-existing account may be adopted.</summary>
    Allow,

    /// <summary>Refused: the target account is privileged (administrator) and must be linked explicitly.</summary>
    RefusePrivileged,

    /// <summary>Refused: the provider requires a verified email for adoption and the login carried none (absent or false).</summary>
    RefuseUnverifiedEmail,
}

/// <summary>
/// What the login can prove for a same-named adoption: whether the provider requires a verified email
/// before adopting, and the <c>email_verified</c> claim the login actually carried (null when the claim
/// is absent). SAML has no <c>email_verified</c> concept, so it always passes <see cref="None"/>.
/// </summary>
/// <param name="RequireVerifiedEmail">Whether the provider gates adoption on a verified email.</param>
/// <param name="EmailVerified">The login's <c>email_verified</c> claim: true, false, or null when absent.</param>
internal readonly record struct AdoptionGate(bool RequireVerifiedEmail, bool? EmailVerified)
{
    /// <summary>Gets the no-op gate: no verified-email requirement and no claim (the SAML and default posture).</summary>
    internal static AdoptionGate None => new AdoptionGate(false, null);
}

/// <summary>
/// Decides whether an SSO login may adopt the pre-existing, unlinked Jellyfin account that merely shares
/// its name. Adoption keys on the mutable display name (<c>GetUserByName</c>), so on its own it trusts the
/// identity provider to make usernames unique and non-reassignable (#218). Two protocol-agnostic gates
/// raise that bar, both fail closed:
/// <list type="bullet">
/// <item>An administrator account is NEVER adopted by name-matching — it is the highest-value takeover
/// target, so the operator must link it explicitly through the admin link endpoint. This holds regardless
/// of the verified-email gate or protocol.</item>
/// <item>When the provider sets <c>RequireVerifiedEmailForAdoption</c>, the login must additionally carry
/// <c>email_verified == true</c>; an absent or false claim is refused. Jellyfin accounts store no email to
/// cross-check against, so this proves the principal holds a provider-verified email rather than matching
/// it to the target account — it does not replace the IdP's unique-username assumption, it narrows who can
/// exploit it. Off by default so a conformant deployment that already relies on name-based adoption is not
/// silently locked out on upgrade; opt in once the provider is confirmed to emit <c>email_verified</c>
/// (which needs the <c>email</c> scope).</item>
/// </list>
/// Pure so the whole matrix is unit-testable; the caller resolves the target's admin flag and supplies the
/// gate, then maps a refusal to <see cref="AccountLinkForbiddenException"/> (the existing 403).
/// </summary>
internal static class AdoptionEligibilityResolver
{
    /// <summary>
    /// Decides whether the name-matched account may be adopted.
    /// </summary>
    /// <param name="targetIsAdministrator">Whether the account about to be adopted holds administrator rights.</param>
    /// <param name="gate">What the login can prove (the verified-email requirement and the asserted claim).</param>
    /// <returns>The adoption verdict.</returns>
    internal static AdoptionVerdict Resolve(bool targetIsAdministrator, AdoptionGate gate)
    {
        if (targetIsAdministrator)
        {
            return AdoptionVerdict.RefusePrivileged;
        }

        if (gate.RequireVerifiedEmail && gate.EmailVerified != true)
        {
            return AdoptionVerdict.RefuseUnverifiedEmail;
        }

        return AdoptionVerdict.Allow;
    }
}
