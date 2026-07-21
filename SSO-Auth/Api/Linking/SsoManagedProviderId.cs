// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>
/// The single <c>User.AuthenticationProviderId</c> value the plugin stamps on the accounts it manages
/// (#133) and that the SSO-only feature (#165) uses to detect them. It is a Jellyfin identifier that
/// resolves to no registered <c>IAuthenticationProvider</c>, so core substitutes its
/// <c>InvalidAuthenticationProvider</c> and every password attempt on such an account is rejected.
/// </summary>
internal static class SsoManagedProviderId
{
    /// <summary>
    /// Gets the pinned provider-id string.
    /// </summary>
    /// <remarks>
    /// SECURITY / PERSISTENCE: this exact string is written to <c>User.AuthenticationProviderId</c> and
    /// persisted in Jellyfin's user database. It MUST NEVER change — every account provisioned by an
    /// earlier version carries this literal, and both the stamp (<c>CanonicalLinkService</c>) and the
    /// SSO-only detector (<c>SsoAuthenticationProviders.IsSsoProvider</c>) compare against it. It is
    /// deliberately a fixed literal and NOT <c>typeof(SSOController).FullName</c>: coupling a persisted
    /// value to the controller's namespace meant any future move of that type (e.g. into an Api.Http
    /// module, #807) would silently stop recognizing every existing SSO-managed account. The value
    /// happens to equal the controller's historical full type name; a conformance test pins it.
    /// </remarks>
    internal const string Value = "Jellyfin.Plugin.SSO_Auth.Api.SSOController";
}
