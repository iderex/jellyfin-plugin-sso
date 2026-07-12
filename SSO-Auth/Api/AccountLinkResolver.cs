using System;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The action to take when resolving an SSO identity to a Jellyfin account.
/// </summary>
internal enum AccountLinkAction
{
    /// <summary>Use the account already linked to this SSO identity.</summary>
    UseExistingLink,

    /// <summary>Adopt a pre-existing Jellyfin account that happens to share the identity's name.</summary>
    AdoptExistingAccount,

    /// <summary>Create a brand-new Jellyfin account for this SSO identity.</summary>
    CreateNewAccount,

    /// <summary>Refuse: the name is taken by an account we are not permitted to adopt.</summary>
    RejectNameTaken,
}

/// <summary>
/// A resolved account-link decision: the action and the Jellyfin user id it applies to.
/// </summary>
internal readonly struct AccountLinkDecision
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AccountLinkDecision"/> struct.
    /// </summary>
    /// <param name="action">The action to take.</param>
    /// <param name="userId">The Jellyfin user id the action applies to (empty when creating/rejecting).</param>
    internal AccountLinkDecision(AccountLinkAction action, Guid userId)
    {
        Action = action;
        UserId = userId;
    }

    /// <summary>Gets the action to take.</summary>
    internal AccountLinkAction Action { get; }

    /// <summary>Gets the Jellyfin user id the action applies to.</summary>
    internal Guid UserId { get; }
}

/// <summary>
/// Pure decision logic mapping an SSO identity to a Jellyfin account. An identity already linked to
/// an account always uses that link. Otherwise a pre-existing account that merely shares the SSO
/// name is adopted ONLY when the administrator has opted in; by default the login fails closed. This
/// stops an attacker whose identity provider name matches an existing account (e.g. "admin") from
/// taking that account over on first login.
/// </summary>
internal static class AccountLinkResolver
{
    /// <summary>
    /// Decides how to resolve an SSO login to a Jellyfin account.
    /// </summary>
    /// <param name="linkedUserId">User id already linked to this SSO identity, if any and still valid.</param>
    /// <param name="existingAccountUserId">User id of a pre-existing account matching the name, if any.</param>
    /// <param name="allowExistingAccountLink">Whether adopting a same-named pre-existing account is permitted.</param>
    /// <returns>The resolved decision.</returns>
    internal static AccountLinkDecision Resolve(
        Guid? linkedUserId,
        Guid? existingAccountUserId,
        bool allowExistingAccountLink)
    {
        if (linkedUserId.HasValue)
        {
            return new AccountLinkDecision(AccountLinkAction.UseExistingLink, linkedUserId.Value);
        }

        if (existingAccountUserId.HasValue)
        {
            return allowExistingAccountLink
                ? new AccountLinkDecision(AccountLinkAction.AdoptExistingAccount, existingAccountUserId.Value)
                : new AccountLinkDecision(AccountLinkAction.RejectNameTaken, Guid.Empty);
        }

        return new AccountLinkDecision(AccountLinkAction.CreateNewAccount, Guid.Empty);
    }

    /// <summary>
    /// Resolves which existing account link (if any) an OpenID login maps to, preferring the stable
    /// subject-keyed link and falling back to a legacy name-keyed link left over from before #155.
    /// Pure: the caller resolves the two candidate links (and confirms their target users still exist)
    /// before calling, and performs the re-key I/O when <c>MigrateLegacy</c> is set.
    /// </summary>
    /// <param name="subjectKeyedUserId">
    /// The user id linked under the stable subject key, if that link exists and its user still exists.
    /// </param>
    /// <param name="legacyNameKeyedUserId">
    /// The user id linked under the legacy username key, if that link exists and its user still exists.
    /// Pass <c>null</c> when the subject and username are identical (there is nothing to migrate).
    /// </param>
    /// <returns>
    /// The linked user id (or null when neither link resolves), and whether the legacy link must be
    /// re-keyed to the subject. Migration is requested only when there is no subject-keyed link yet but
    /// a legacy one resolves — a one-time, idempotent hand-off: once re-keyed, later logins hit the
    /// subject key directly and never consult the name again.
    /// </returns>
    internal static (Guid? LinkedUserId, bool MigrateLegacy) ResolveCanonicalLink(
        Guid? subjectKeyedUserId,
        Guid? legacyNameKeyedUserId)
    {
        if (subjectKeyedUserId.HasValue)
        {
            return (subjectKeyedUserId.Value, false);
        }

        if (legacyNameKeyedUserId.HasValue)
        {
            return (legacyNameKeyedUserId.Value, true);
        }

        return (null, false);
    }

    /// <summary>
    /// Decides the outcome of the atomic "link this identity unless it is already linked" step (#133):
    /// if a live link already exists (a concurrent first-login won the race), that winner is used and
    /// nothing is written; otherwise the candidate is linked. The caller performs this inside a single
    /// read-modify-write so the check and the write cannot interleave, and audits an adoption only when
    /// <c>WroteLink</c> is true. Pure so the no-overwrite / wrote-flag contract is unit-testable.
    /// </summary>
    /// <param name="existingLiveLinkUserId">The user already linked to this identity (with a still-existing account), or null.</param>
    /// <param name="candidateUserId">The user to link when no live link exists (the adopted or newly created account).</param>
    /// <returns>The effective user id, and whether this call should write the link.</returns>
    internal static (Guid EffectiveUserId, bool WroteLink) ResolveLinkWrite(Guid? existingLiveLinkUserId, Guid candidateUserId)
    {
        return existingLiveLinkUserId.HasValue
            ? (existingLiveLinkUserId.Value, false)
            : (candidateUserId, true);
    }
}

/// <summary>
/// Thrown when an SSO login must not create, adopt, or link an account — a pre-existing, unlinked
/// Jellyfin account whose adoption the provider forbids, or a login without a resolvable identity.
/// The controller maps this to an HTTP 403. Messages are deliberately generic — the
/// identity-provider-supplied name is not embedded, since exception messages may be logged or
/// reported elsewhere; the caller logs the sanitized name and context.
/// </summary>
internal sealed class AccountLinkForbiddenException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AccountLinkForbiddenException"/> class.
    /// </summary>
    internal AccountLinkForbiddenException()
        : base("An unlinked Jellyfin account already exists for this SSO identity, and adopting it is disabled for the provider (AllowExistingAccountLink).")
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AccountLinkForbiddenException"/> class with a
    /// specific message.
    /// </summary>
    /// <param name="message">The message; must not embed the provider-supplied name.</param>
    internal AccountLinkForbiddenException(string message)
        : base(message)
    {
    }
}
