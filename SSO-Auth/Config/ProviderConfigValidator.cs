using System;
using Jellyfin.Plugin.SSO_Auth.Api;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Rejects invalid provider configuration fail-closed before anything is persisted. The whole-config
/// <see cref="Validate"/> gates the admin config-page save inside <see cref="ProviderConfigStore.Save"/>;
/// the per-provider methods apply the same predicates to a single incoming provider, so every admin
/// write path can share one validation rule (#318). Delegates to the existing
/// <see cref="CanonicalBaseUrl.IsInvalidOverride"/>, <see cref="SamlCertificate.IsInvalid"/>, and
/// <see cref="ProviderNameValidator.IsInvalid"/> predicates.
/// </summary>
internal static class ProviderConfigValidator
{
    // Throws if any provider's canonical base-URL override (#139) is set but not a valid absolute
    // http/https base URL, any SAML provider's signing certificate (#206) is set but not a loadable
    // X.509 certificate, or any NEWLY registered provider name (#336) contains URI-reserved
    // characters — rejecting the save fail-closed before anything is persisted. A blank override or
    // certificate is valid (the override feature is off; a half-configured provider), and a name
    // already present in the live configuration is exempt from the name rule (see
    // ValidateProviderName). Only the admin config-page save path validates the whole config; the Add
    // endpoints validate their own incoming provider at the controller, and login-path writes reuse
    // the live object and are never revalidated.
    internal static void Validate(PluginConfiguration incoming, PluginConfiguration live)
    {
        if (incoming.OidConfigs != null)
        {
            foreach (var kvp in incoming.OidConfigs)
            {
                ValidateProviderName("OpenID", kvp.Key, isNew: live?.OidConfigs?.ContainsKey(kvp.Key) != true);
                ValidateBaseUrlOverride("OpenID", kvp.Key, kvp.Value?.BaseUrlOverride);
            }
        }

        if (incoming.SamlConfigs != null)
        {
            foreach (var kvp in incoming.SamlConfigs)
            {
                ValidateProviderName("SAML", kvp.Key, isNew: live?.SamlConfigs?.ContainsKey(kvp.Key) != true);
                ValidateBaseUrlOverride("SAML", kvp.Key, kvp.Value?.BaseUrlOverride);
            }

            foreach (var kvp in incoming.SamlConfigs)
            {
                ValidateSamlCertificate(kvp.Key, kvp.Value?.SamlCertificate);
            }
        }
    }

    // A NEW provider name containing URI-reserved characters would be persisted and then break the
    // callback round-trip at login (#336): the name is appended raw to the redirect_uri/ACS URL
    // (SsoUrlBuilder) and matched back by route. Only a name absent from the live configuration is
    // rejected — an existing name, whose URL bytes the identity provider already has registered, must
    // keep saving unchanged or the deployment would be stranded behind a rename. Same inline
    // line-ending strip as below.
    internal static void ValidateProviderName(string protocol, string provider, bool isNew)
    {
        if (isNew && ProviderNameValidator.IsInvalid(provider))
        {
            throw new ArgumentException(
                $"{protocol} provider '{provider?.ReplaceLineEndings(string.Empty)}' has a name with URI-reserved characters; the name becomes part of the callback URL registered with the identity provider, so a new name must not contain any of % : / ? # [ ] @ ! $ & ' ( ) * + , ; =.");
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
