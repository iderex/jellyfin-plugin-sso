using System;
using System.Linq;
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
    // X.509 certificate, or any NEWLY registered provider name (#336/#360) contains control characters,
    // URI-reserved characters, or a backslash — rejecting the save fail-closed before anything is
    // persisted. A blank override or
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
            // One pass runs all three checks per provider, so with several invalid providers the first
            // error reported follows map order rather than check kind; every invalid save is still
            // rejected fail-closed before anything is persisted.
            foreach (var kvp in incoming.SamlConfigs)
            {
                ValidateProviderName("SAML", kvp.Key, isNew: live?.SamlConfigs?.ContainsKey(kvp.Key) != true);
                ValidateBaseUrlOverride("SAML", kvp.Key, kvp.Value?.BaseUrlOverride);
                ValidateSamlCertificate(kvp.Key, kvp.Value?.SamlCertificate);
                ValidateSamlSecondaryCertificate(kvp.Key, kvp.Value?.SamlSecondaryCertificate);
                ValidateSamlSigningKey(kvp.Key, kvp.Value?.SamlSigningKeyPfx);
                ValidateSamlSigningKey(kvp.Key, kvp.Value?.SamlRolloverSigningKeyPfx);
            }
        }
    }

    // A NEW provider name containing URI-reserved or control characters would be persisted and then break
    // the callback round-trip at login (#336, #360): the name is appended raw to the redirect_uri/ACS URL
    // (SsoUrlBuilder) and matched back by route. Only a name absent from the live configuration is
    // rejected — an existing name, whose URL bytes the identity provider already has registered, must
    // keep saving unchanged or the deployment would be stranded behind a rename. The echoed name gets a
    // full control strip (stronger than the line-ending strip below — see the inline comment).
    internal static void ValidateProviderName(string protocol, string provider, bool isNew)
    {
        if (isNew && ProviderNameValidator.IsInvalid(provider))
        {
            // Rejected names can now carry arbitrary control characters (#360), so line-ending stripping
            // alone would let e.g. ESC survive into the exception text and any log that captures it —
            // strip ALL controls inline here, then the two non-control line separators (U+2028/U+2029)
            // that ReplaceLineEndings covers and char.IsControl does not.
            var echoName = string.Concat((provider ?? string.Empty).Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);
            throw new ArgumentException(
                $"{protocol} provider '{echoName}' has a name with control characters, URI-reserved characters, or a backslash; the name becomes part of the callback URL registered with the identity provider, so a new name must not contain control characters, a backslash, or any of % : / ? # [ ] @ ! $ & ' ( ) * + , ; =.",
                nameof(provider));
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
                $"{protocol} provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid Base URL override; it must be an absolute http(s) URL such as https://jellyfin.example.com.",
                nameof(baseUrlOverride));
        }
    }

    // A garbage certificate would be persisted and then throw a CryptographicException on every
    // callback — an unhandled 500 (#206). Same inline line-ending strip as above.
    internal static void ValidateSamlCertificate(string provider, string certificate)
    {
        if (SamlCertificate.IsInvalid(certificate))
        {
            throw new ArgumentException(
                $"SAML provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid signing certificate; it must be a Base64-encoded (DER) X.509 certificate.",
                nameof(certificate));
        }
    }

    // The optional inbound secondary verification certificate (#491) is the identity provider's PUBLIC
    // certificate — the exact same kind of value as the primary, and rejected the exact same way: a
    // set-but-unloadable value would be persisted and then throw a CryptographicException on every callback
    // (an unhandled 500, #206). Blank is valid (no overlap window configured). Same inline line-ending
    // strip as above.
    internal static void ValidateSamlSecondaryCertificate(string provider, string certificate)
    {
        if (SamlCertificate.IsInvalid(certificate))
        {
            throw new ArgumentException(
                $"SAML provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid secondary signing certificate; it must be a Base64-encoded (DER) X.509 certificate.",
                nameof(certificate));
        }
    }

    // A garbage service-provider signing key (#167) would be persisted and then fail every signed
    // challenge. On the config-page save the key is withheld from JSON so it arrives blank (valid) and the
    // stored one is re-injected afterwards; this rejects the case where a non-blank, unloadable key is
    // posted. Same inline line-ending strip as above.
    internal static void ValidateSamlSigningKey(string provider, string signingKeyPfx)
    {
        if (SamlSigningKey.IsInvalid(signingKeyPfx))
        {
            throw new ArgumentException(
                $"SAML provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid request signing key; it must be a Base64-encoded, unencrypted PKCS#12 (PFX) blob containing an RSA or ECDSA private key.",
                nameof(signingKeyPfx));
        }
    }
}
