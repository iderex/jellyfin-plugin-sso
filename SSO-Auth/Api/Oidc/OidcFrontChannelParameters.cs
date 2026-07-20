#nullable enable

using System.Collections.Generic;
using System.Globalization;
using Duende.IdentityModel.Client;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Builds the optional step-up front-channel parameters added to the OpenID authorization request (#757,
/// OIDC Core §3.1.2.1): <c>acr_values</c>, <c>prompt</c>, and <c>max_age</c>. Each is included ONLY when the
/// provider set it, so an unconfigured provider produces no parameters and its authorization request is
/// byte-identical to before this feature — upgrade-safe. Returns <see langword="null"/> when none are set so
/// the caller can hand nothing to <c>PrepareLoginAsync</c>.
/// </summary>
internal static class OidcFrontChannelParameters
{
    /// <summary>
    /// Builds the extra authorize parameters from the provider configuration, or <see langword="null"/> when
    /// none of <c>AcrValues</c>/<c>Prompt</c>/<c>MaxAge</c> is set.
    /// </summary>
    /// <param name="config">The OpenID provider configuration.</param>
    /// <returns>The front-channel parameters to add, or <see langword="null"/> when there are none.</returns>
    internal static Parameters? FromConfig(OidConfig config)
    {
        var pairs = new List<KeyValuePair<string, string>>();

        var acrValues = config.AcrValues?.Trim();
        if (!string.IsNullOrEmpty(acrValues))
        {
            pairs.Add(new KeyValuePair<string, string>("acr_values", acrValues));
        }

        var prompt = config.Prompt?.Trim();
        if (!string.IsNullOrEmpty(prompt))
        {
            pairs.Add(new KeyValuePair<string, string>("prompt", prompt));
        }

        // max_age is a non-negative number of seconds (0 forces re-authentication); a negative value is
        // treated as unset rather than sent as an invalid parameter.
        if (config.MaxAge is int maxAge && maxAge >= 0)
        {
            pairs.Add(new KeyValuePair<string, string>("max_age", maxAge.ToString(CultureInfo.InvariantCulture)));
        }

        return pairs.Count > 0 ? new Parameters(pairs) : null;
    }
}
