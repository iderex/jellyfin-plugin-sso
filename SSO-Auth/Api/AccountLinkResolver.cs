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
}

/// <summary>
/// Thrown when an SSO login resolves to a pre-existing, unlinked Jellyfin account and adopting such
/// accounts is not permitted for the provider. The controller maps this to an HTTP 403. The message
/// is deliberately generic — the identity-provider-supplied name is not embedded, since exception
/// messages may be logged or reported elsewhere; the caller logs the sanitized name and context.
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
}
