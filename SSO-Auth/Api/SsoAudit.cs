using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Emits consistent, structured audit-log entries for security-relevant SSO events that exist today:
/// successful logins, adoption of a pre-existing account, and provider configuration changes. Every
/// entry shares the "[SSO Audit]" prefix so operators can filter the trail, and only non-sensitive
/// fields are logged (never secrets or certificates). Identity-provider- and admin-supplied values
/// are stripped of line endings inline before logging so they cannot forge or split an entry.
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
        => logger.LogInformation(
            "[SSO Audit] Login succeeded: {Username} via {Protocol} provider '{Provider}' (admin={IsAdmin}).",
            username?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty),
            isAdmin);

    /// <summary>Records an SSO identity being linked to a pre-existing account (the opt-in adoption path).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="displayName">The adopted account's name.</param>
    internal static void AccountAdopted(ILogger logger, string protocol, string provider, string displayName)
        => logger.LogWarning(
            "[SSO Audit] SSO identity linked to existing account '{DisplayName}' via {Protocol} provider '{Provider}' (AllowExistingAccountLink).",
            displayName?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty));

    /// <summary>Records a provider being added or updated.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    internal static void ProviderConfigured(ILogger logger, string protocol, string provider)
        => logger.LogInformation(
            "[SSO Audit] Provider configured: {Protocol} '{Provider}'.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty));

    /// <summary>Records a provider being removed.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    internal static void ProviderRemoved(ILogger logger, string protocol, string provider)
        => logger.LogInformation(
            "[SSO Audit] Provider removed: {Protocol} '{Provider}'.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty));
}
