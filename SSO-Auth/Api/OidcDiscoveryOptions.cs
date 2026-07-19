using System;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Builds the <see cref="OidcClientOptions"/> Authority and discovery policy — <c>RequireHttps</c>,
/// <c>ValidateIssuerName</c>, <c>ValidateEndpoints</c>, and the additional base address for providers whose
/// endpoints sit off the authority — from a provider config, in ONE place. Both the login path
/// (<see cref="Flows.OidcLoginService"/>, which layers the client credentials, redirect URI, scope and the
/// id_token validator on top) and the admin Test-connection probe (<see cref="ProviderConnectionTester"/>,
/// which reads discovery only) build their options here, so the test fetch runs under the EXACT same
/// SSRF/TLS posture as the real login discovery (#163) — a later change to the login's discovery policy
/// cannot silently leave the probe on a weaker one. The client secret is deliberately NOT set here:
/// discovery and JWKS need no credential, so the probe never even reveals the at-rest secret.
/// </summary>
internal static class OidcDiscoveryOptions
{
    /// <summary>
    /// Builds options carrying only the provider's Authority and discovery policy. Throws
    /// <see cref="UriFormatException"/> / <see cref="ArgumentNullException"/> when the configured endpoint is
    /// null or not an absolute URL — the caller decides whether that is a fail-closed login error (the login
    /// wraps this in its secret-reveal guard) or an actionable Test-connection result.
    /// </summary>
    /// <param name="config">The OpenID provider configuration.</param>
    /// <returns>Options with Authority and Policy.Discovery set from the config.</returns>
    internal static OidcClientOptions Build(OidConfig config)
    {
        var authority = config.OidEndpoint?.Trim();
        var options = new OidcClientOptions { Authority = authority };
        var oidEndpointUri = new Uri(authority);
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(oidEndpointUri.GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.ValidateEndpoints = !config.DoNotValidateEndpoints; // For Google and other providers with different endpoints
        options.Policy.Discovery.RequireHttps = !config.DisableHttps;
        options.Policy.Discovery.ValidateIssuerName = !config.DoNotValidateIssuerName;
        return options;
    }
}
