using System;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The two <c>User.AuthenticationProviderId</c> values the SSO-only login feature (#165) moves accounts
/// between, named once so the enforcement sweep, the break-glass guard, and the login-path re-assertion
/// all agree on them.
/// </summary>
/// <remarks>
/// Jellyfin has no server-wide "disable password login" switch (see SSO-ONLY-LOGIN-DESIGN.md §2); the only
/// lever is the per-user provider id. Setting it to <see cref="SsoProviderId"/> — the plugin controller's
/// full type name, which is NOT a registered <c>IAuthenticationProvider</c> — makes Jellyfin route that
/// account's password attempts to its <c>InvalidAuthenticationProvider</c>, which rejects every password.
/// This is the exact lever <see cref="CanonicalLinkService"/> already uses for the accounts it
/// creates (<c>user.AuthenticationProviderId = typeof(SSOController).FullName</c>). Restoring
/// <see cref="DefaultPasswordProviderId"/> re-opens native password login, exactly as the Unregister revoke
/// path does. Neither value is a secret; both are stable, documented Jellyfin identifiers.
/// </remarks>
internal static class SsoAuthenticationProviders
{
    /// <summary>
    /// Jellyfin's built-in password provider — the account routing that native (username + password) login
    /// uses. Restoring it is the reversible off-switch (SSO-ONLY-LOGIN-DESIGN.md §3 option B); it never
    /// touches the stored password hash. This is the same full type name the config page documents as the
    /// common "Set default Provider" value.
    /// </summary>
    internal const string DefaultPasswordProviderId = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

    /// <summary>
    /// Gets the provider id that disables native password login for an account: the SSO controller's full
    /// type name, which resolves to no registered password provider (so core substitutes its
    /// <c>InvalidAuthenticationProvider</c>). Computed from <see cref="SSOController"/> so a namespace/rename
    /// tracks automatically rather than drifting from the value <see cref="CanonicalLinkService"/>
    /// stamps on created accounts.
    /// </summary>
    internal static string SsoProviderId { get; } = typeof(SSOController).FullName!;

    /// <summary>Whether the given provider id is the plugin's SSO (password-disabling) provider.</summary>
    /// <param name="authenticationProviderId">The account's <c>AuthenticationProviderId</c>.</param>
    /// <returns>True when the id routes to no password provider (SSO-only for that account).</returns>
    internal static bool IsSsoProvider(string authenticationProviderId)
        => string.Equals(authenticationProviderId, SsoProviderId, StringComparison.Ordinal);

    /// <summary>Whether the given provider id is Jellyfin's built-in password provider.</summary>
    /// <param name="authenticationProviderId">The account's <c>AuthenticationProviderId</c>.</param>
    /// <returns>True when native password login is routed through core's default provider.</returns>
    internal static bool IsDefaultPasswordProvider(string authenticationProviderId)
        => string.Equals(authenticationProviderId, DefaultPasswordProviderId, StringComparison.Ordinal);
}
