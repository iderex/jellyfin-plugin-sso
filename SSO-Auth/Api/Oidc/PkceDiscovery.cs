using System;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Decides whether an OpenID provider's discovery document advertises PKCE with SHA-256 (<c>S256</c>).
/// RFC 9700 §2.1.1 requires a client to confirm the authorization server supports PKCE before relying
/// on it. The OidcClient library sends <c>code_challenge</c> (S256) unconditionally but never checks
/// the discovery document's <c>code_challenge_methods_supported</c>, so a server that ignores PKCE would
/// silently downgrade authorization-code-injection protection (#141). Pure: the caller fetches the raw
/// discovery JSON; this only interprets it, and fails closed (<c>false</c>) on anything unexpected.
/// </summary>
internal static class PkceDiscovery
{
    /// <summary>
    /// Returns whether the discovery document lists <c>S256</c> in <c>code_challenge_methods_supported</c>.
    /// </summary>
    /// <param name="discoveryJson">The raw OpenID discovery document JSON.</param>
    /// <returns>
    /// <c>true</c> only when <c>S256</c> is advertised; <c>false</c> on absence, an empty/other-only set,
    /// a non-array value, non-string elements, or malformed/blank JSON.
    /// </returns>
    internal static bool SupportsS256(string discoveryJson)
    {
        if (string.IsNullOrWhiteSpace(discoveryJson))
        {
            return false;
        }

        try
        {
            var methods = JObject.Parse(discoveryJson)["code_challenge_methods_supported"] as JArray;
            return methods is not null
                && methods.Any(method =>
                    method.Type == JTokenType.String
                    && string.Equals(method.Value<string>(), "S256", StringComparison.Ordinal));
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
