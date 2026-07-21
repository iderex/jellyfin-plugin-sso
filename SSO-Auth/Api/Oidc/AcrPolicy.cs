using System;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The step-up / forced-MFA acr allow-list check (#757). When a provider sets <c>RequireAcr</c>, the
/// signature-verified id_token's returned <c>acr</c> claim must be one of the space-separated values the
/// admin configured in <c>AcrValues</c> (the same list requested on the authorization request). Fail-closed:
/// an absent/blank returned <c>acr</c>, or an empty allow-list, satisfies nothing — so a login lacking the
/// required authentication context is refused. Matching is ordinal (acr values are case-sensitive URIs /
/// tokens per OIDC Core §2).
/// </summary>
internal static class AcrPolicy
{
    /// <summary>
    /// Whether the returned <c>acr</c> claim satisfies the configured <c>acr_values</c> allow-list.
    /// </summary>
    /// <param name="returnedAcr">The <c>acr</c> claim value from the verified id_token (may be null/blank).</param>
    /// <param name="configuredAcrValues">The provider's space-separated <c>AcrValues</c> allow-list.</param>
    /// <returns><see langword="true"/> only when a non-blank returned <c>acr</c> exactly matches one configured value.</returns>
    internal static bool IsSatisfied(string? returnedAcr, string? configuredAcrValues)
    {
        if (string.IsNullOrWhiteSpace(returnedAcr) || string.IsNullOrWhiteSpace(configuredAcrValues))
        {
            return false;
        }

        var acr = returnedAcr.Trim();
        foreach (var acceptable in configuredAcrValues.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            if (string.Equals(acceptable, acr, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
