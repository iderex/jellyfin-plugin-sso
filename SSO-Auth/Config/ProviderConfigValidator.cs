using System;
using Jellyfin.Plugin.SSO_Auth.Api;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Rejects invalid provider configuration fail-closed before anything is persisted. The whole-config
/// <see cref="Validate"/> gates the admin config-page save inside <see cref="ProviderConfigStore.Save"/>;
/// the per-provider methods apply the same predicates to a single incoming provider, so every admin
/// write path can share one validation rule (#318). Delegates to the existing
/// <see cref="CanonicalBaseUrl.IsInvalidOverride"/> and <see cref="SamlCertificate.IsInvalid"/> predicates.
/// </summary>
internal static class ProviderConfigValidator
{
    // Throws if any provider's canonical base-URL override (#139) is set but not a valid absolute
    // http/https base URL, or any SAML provider's signing certificate (#206) is set but not a loadable
    // X.509 certificate — rejecting the save fail-closed before anything is persisted. A blank value is
    // valid in both cases (the override feature is off; a half-configured provider). Only the admin
    // config-page save path validates the whole config; the Add endpoints validate their own incoming
    // provider at the controller, and login-path writes reuse the live object and are never revalidated.
    internal static void Validate(PluginConfiguration incoming)
    {
        if (incoming.OidConfigs != null)
        {
            foreach (var kvp in incoming.OidConfigs)
            {
                ValidateBaseUrlOverride("OpenID", kvp.Key, kvp.Value?.BaseUrlOverride);
            }
        }

        if (incoming.SamlConfigs != null)
        {
            foreach (var kvp in incoming.SamlConfigs)
            {
                ValidateBaseUrlOverride("SAML", kvp.Key, kvp.Value?.BaseUrlOverride);
            }

            foreach (var kvp in incoming.SamlConfigs)
            {
                ValidateSamlCertificate(kvp.Key, kvp.Value?.SamlCertificate);
            }
        }
    }

    // A malformed override would be persisted and then silently fall back to the request Host at
    // login (#139). The provider name is line-ending-stripped inline in case it reaches a log through
    // the thrown exception.
    internal static void ValidateBaseUrlOverride(string protocol, string provider, string baseUrlOverride)
    {
        if (CanonicalBaseUrl.IsInvalidOverride(baseUrlOverride))
        {
            throw new ArgumentException(
                $"{protocol} provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid Base URL override; it must be an absolute http(s) URL such as https://jellyfin.example.com.");
        }
    }

    // A garbage certificate would be persisted and then throw a CryptographicException on every
    // callback — an unhandled 500 (#206). Same inline line-ending strip as above.
    internal static void ValidateSamlCertificate(string provider, string certificate)
    {
        if (SamlCertificate.IsInvalid(certificate))
        {
            throw new ArgumentException(
                $"SAML provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid signing certificate; it must be a Base64-encoded (DER) X.509 certificate.");
        }
    }
}
