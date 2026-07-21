// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Audit;

/// <summary>
/// Emits consistent, structured audit-log entries for security-relevant SSO events that exist today:
/// successful logins, adoption of a pre-existing account, and provider configuration changes. Every
/// entry shares the "[SSO Audit]" prefix so operators can filter the trail, and only non-sensitive
/// fields are logged (never secrets or certificates). Identity-provider- and admin-supplied values
/// are stripped of line endings inline before logging so they cannot forge or split an entry.
/// Each call is guarded by <see cref="ILogger.IsEnabled(LogLevel)"/> so the inline line-ending
/// sanitizer is not evaluated when the level is disabled (net10 CA1873, #566); the sanitizer stays
/// at the logging call so CodeQL's log-forging taint tracking still sees it inline.
/// </summary>
internal static class SsoAudit
{
    /// <summary>Records a successful login (a session was issued).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="username">The Jellyfin username the session was issued for.</param>
    /// <param name="isAdmin">Whether the session was granted administrator rights.</param>
    internal static void LoginSucceeded(ILogger logger, string protocol, string provider, string username, bool isAdmin)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Login succeeded: {Username} via {Protocol} provider '{Provider}' (admin={IsAdmin}).",
            username?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty),
            isAdmin);
    }

    /// <summary>
    /// Records a new SSO identity being provisioned as a disabled account pending administrator approval
    /// (#737, ProvisionNewUsersDisabled). No session was issued; an administrator must enable the account.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="username">The Jellyfin username the disabled account was created under.</param>
    internal static void ProvisionedPendingApproval(ILogger logger, string protocol, string provider, string username)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] New account provisioned pending approval: '{Username}' via {Protocol} provider '{Provider}' was created disabled (ProvisionNewUsersDisabled); no session issued. Enable it in the Jellyfin dashboard to approve.",
            username?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records an SSO identity being linked to a pre-existing account (the opt-in adoption path).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="displayName">The adopted account's name.</param>
    internal static void AccountAdopted(ILogger logger, string protocol, string provider, string displayName)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SSO identity linked to existing account '{DisplayName}' via {Protocol} provider '{Provider}' (AllowExistingAccountLink).",
            displayName?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records a provider being added or updated.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    internal static void ProviderConfigured(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Provider configured: {Protocol} '{Provider}'.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records a provider being removed.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    internal static void ProviderRemoved(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Provider removed: {Protocol} '{Provider}'.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records that a provider's authorization server does not advertise PKCE S256 support (#141).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The provider name.</param>
    internal static void PkceNotAdvertised(ILogger logger, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] OpenID provider '{Provider}' does not advertise PKCE (S256) in its discovery document (code_challenge_methods_supported). PKCE is still sent, but a server that ignores it leaves cross-session authorization-code injection undetectable (RFC 9700 §2.1.1). Set RequirePkce to fail closed once the provider supports it.",
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records an administrator importing a configuration document (#161).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="oidProviders">How many OpenID providers the import merged.</param>
    /// <param name="samlProviders">How many SAML providers the import merged.</param>
    internal static void ConfigImported(ILogger logger, int oidProviders, int samlProviders)
        => logger.LogWarning(
            "[SSO Audit] Configuration imported by an administrator: {OidProviders} OpenID and {SamlProviders} SAML provider(s) merged. Server-managed secrets and links were preserved; redacted secrets must be re-entered on this instance.",
            oidProviders,
            samlProviders);

    /// <summary>Records SSO-only login being turned on (#165), with the guaranteed break-glass survivor.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who enabled the mode.</param>
    /// <param name="breakGlassAdmin">The designated break-glass admin whose password door survives.</param>
    /// <param name="repointedCount">How many accounts were repointed off the password provider.</param>
    internal static void SsoOnlyLoginEnabled(ILogger logger, string actor, string? breakGlassAdmin, int repointedCount)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SSO-only login ENABLED by {Actor}: break-glass admin '{BreakGlassAdmin}' keeps password login; {RepointedCount} account(s) repointed to SSO-only.",
            actor?.ReplaceLineEndings(string.Empty),
            breakGlassAdmin?.ReplaceLineEndings(string.Empty),
            repointedCount);
    }

    /// <summary>Records SSO-only login being turned off (#165), the reversible no-SSO off-switch.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who disabled the mode.</param>
    /// <param name="restoredCount">How many accounts had native password routing restored.</param>
    internal static void SsoOnlyLoginDisabled(ILogger logger, string actor, int restoredCount)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SSO-only login DISABLED by {Actor}: native password routing restored for {RestoredCount} account(s); no password hash was reset.",
            actor?.ReplaceLineEndings(string.Empty),
            restoredCount);
    }

    /// <summary>
    /// Records an SSO-only activation (or designation) being REFUSED by the fail-closed guard (#165), so a
    /// blocked lockout attempt leaves a trail (T-R1). The reason is a fixed verdict CODE, never a username or
    /// roster (T-I1).
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator whose activation was refused.</param>
    /// <param name="reasonCode">The guard verdict name (a fixed enum member, not user input).</param>
    internal static void SsoOnlyLoginActivationRefused(ILogger logger, string actor, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SSO-only login activation REFUSED for {Actor}: no surviving admin login path ({ReasonCode}). No change was made.",
            actor?.ReplaceLineEndings(string.Empty),
            reasonCode);
    }

    /// <summary>Records the break-glass admin designation being set or changed (#165), an elevated operation.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who changed the designation.</param>
    /// <param name="breakGlassAdmin">The newly designated break-glass admin.</param>
    internal static void BreakGlassAdminDesignated(ILogger logger, string actor, string? breakGlassAdmin)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Break-glass admin designated by {Actor}: '{BreakGlassAdmin}' is now the account SSO-only login never repoints.",
            actor?.ReplaceLineEndings(string.Empty),
            breakGlassAdmin?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records a validated inbound SAML <c>LogoutRequest</c> that terminated sessions (#727, SLO-3b). Only
    /// non-sensitive fields are logged: the provider name and the count of Jellyfin users whose tokens were
    /// revoked — never the raw NameID or SessionIndex, which are subject identifiers (T-I1). The provider is
    /// route input, so its line endings are stripped inline before logging (log-forging defense).
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The SAML provider the request arrived for.</param>
    /// <param name="usersRevoked">How many distinct Jellyfin users had their tokens revoked.</param>
    internal static void LogoutRequested(ILogger logger, string provider, int usersRevoked)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] SAML logout requested: a validated LogoutRequest for provider '{Provider}' revoked tokens for {UsersRevoked} user(s).",
            provider?.ReplaceLineEndings(string.Empty),
            usersRevoked);
    }

    /// <summary>
    /// Records an inbound SAML <c>LogoutRequest</c> being rejected fail-closed (#727, SLO-3b). The reason is a
    /// FIXED code (unsigned/malformed/replay/no-matching-session, a constant, never request-derived text), so
    /// a blocked forged logout leaves a trail (T-R1) without disclosing subject identifiers or which branch
    /// rejected it to the caller (the caller sees only a uniform 400). The provider is route input, stripped
    /// of line endings inline before logging.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The SAML provider the request arrived for.</param>
    /// <param name="reasonCode">The fixed rejection reason code (not request-derived).</param>
    internal static void LogoutRejected(ILogger logger, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SAML logout request REJECTED for provider '{Provider}' ({ReasonCode}). No session was terminated.",
            provider?.ReplaceLineEndings(string.Empty),
            reasonCode);
    }

    /// <summary>Records a provider being saved with one or more default-on security checks disabled (#140, #672).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="options">The enabled insecure option names (configuration keys, not user input).</param>
    internal static void InsecureOptionsEnabled(ILogger logger, string protocol, string provider, IReadOnlyList<string> options)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        // Shared by OpenID (#140) and SAML (#672), so the wording stays protocol-neutral: each named option
        // switches off a protection that is on by default (OpenID transport/issuer/endpoint binding, SAML
        // audience binding). Naming the exact options is what the audit trail needs; the per-option detail
        // lives in each toggle's config doc.
        logger.LogWarning(
            "[SSO Audit] {Protocol} provider '{Provider}' saved with security checks disabled: {Options}. Each switches off a default-on protection on the login path (such as transport, issuer/audience, or endpoint binding); keep them only if the provider genuinely requires it.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty),
            string.Join(", ", options));
    }
}
