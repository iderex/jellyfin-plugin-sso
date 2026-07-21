using System;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Rejects invalid provider configuration fail-closed before anything is persisted. The whole-config
/// <see cref="Validate"/> gates the admin config-page save inside <see cref="ProviderConfigStore.Save"/>
/// by composing the per-provider checks below; those per-provider methods are also exercised directly,
/// one predicate at a time, by the unit tests (hence internal, not private). The single source of truth
/// is the underlying <see cref="CanonicalBaseUrl.IsInvalidOverride"/>,
/// <see cref="SamlCertificate.IsInvalid"/>, <see cref="SamlSigningKey.IsInvalid"/>, and
/// <see cref="ProviderNameValidator.IsInvalid"/> predicates — the SAME ones the Add endpoints' own
/// guards (<c>SSOController.RejectInvalid*</c>) delegate to. The two admin write paths keep separate
/// throwing wrappers on purpose (#671): the config-page messages here embed the provider name and
/// protocol for the admin UI, whereas the Add-endpoint messages stay generic and input-independent (they
/// never echo the caller's provider name back), and <c>RejectInvalidNewProviderName</c> resolves
/// existence under the config lock. So a new provider-config rule is one shared base predicate plus the
/// two context-appropriate wrappers — the validation logic is not duplicated, only the messaging is
/// deliberately parallel.
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

    /// <summary>
    /// Validates an entire incoming provider configuration fail-closed before the config-page save
    /// persists it, throwing on the first invalid provider found. Composes the per-provider name,
    /// base-URL-override, certificate, signing-key, ACR, permission-role and parental-rating checks
    /// over every OpenID and SAML provider; a valid config returns without effect.
    /// </summary>
    /// <param name="incoming">The configuration about to be persisted.</param>
    /// <param name="live">The current live configuration, used to tell a newly added provider from an existing one.</param>
    /// <exception cref="ArgumentException">A provider fails any per-provider rule.</exception>
    internal static void Validate(PluginConfiguration incoming, PluginConfiguration live)
    {
        if (incoming.OidConfigs != null)
        {
            foreach (var kvp in incoming.OidConfigs)
            {
                ValidateProviderName("OpenID", kvp.Key, isNew: live?.OidConfigs?.ContainsKey(kvp.Key) != true);
                ValidateBaseUrlOverride("OpenID", kvp.Key, kvp.Value?.BaseUrlOverride);
                ValidatePermissionRoleMappings("OpenID", kvp.Key, kvp.Value?.PermissionRoleMappings);
                ValidateParentalRatingMappings("OpenID", kvp.Key, kvp.Value?.ParentalRatingRoleMappings);
                ValidateAcrRequirement(kvp.Key, kvp.Value);
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
                ValidatePermissionRoleMappings("SAML", kvp.Key, kvp.Value?.PermissionRoleMappings);
                ValidateParentalRatingMappings("SAML", kvp.Key, kvp.Value?.ParentalRatingRoleMappings);
            }
        }
    }

    // A NEW provider name containing URI-reserved or control characters would be persisted and then break
    // the callback round-trip at login (#336, #360): the name is appended raw to the redirect_uri/ACS URL
    // (the OIDC/SAML URL builders) and matched back by route. Only a name absent from the live configuration is
    // rejected — an existing name, whose URL bytes the identity provider already has registered, must
    // keep saving unchanged or the deployment would be stranded behind a rename. The echoed name gets a
    // full control strip (stronger than the line-ending strip below — see the inline comment).

    /// <summary>
    /// Rejects a NEW provider whose name would corrupt the login callback URL it becomes part of: a name
    /// that is new to the live configuration and contains control characters, a backslash, or a
    /// URI-reserved character is refused. An already-registered name is exempt so a deployment is never
    /// stranded behind a rename.
    /// </summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name to check.</param>
    /// <param name="isNew">Whether this name is absent from the live configuration; only new names are validated.</param>
    /// <exception cref="ArgumentException">The name is new and contains a forbidden character.</exception>
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

    // RequireAcr with no acr_values would be persisted and then refuse EVERY login for the provider (the
    // allow-list is empty, so no returned acr can satisfy it) — a silent lockout (#757). Reject it at save so
    // the mis-set is caught before it takes effect, rather than failing open (a no-op) or locking out. The
    // provider name is line-ending-stripped inline in case it reaches a log through the thrown exception.

    /// <summary>
    /// Rejects an OpenID provider that requires an ACR but supplies no acr_values, which would otherwise
    /// persist and then silently lock out every login for that provider (the allow-list is empty, so no
    /// returned acr can satisfy it). Caught at save rather than failing open or locking out (#757).
    /// </summary>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="config">The OpenID provider configuration to check; a null config is tolerated.</param>
    /// <exception cref="ArgumentException">RequireAcr is set with blank AcrValues.</exception>
    internal static void ValidateAcrRequirement(string provider, OidConfig? config)
    {
        if (config?.RequireAcr == true && string.IsNullOrWhiteSpace(config.AcrValues))
        {
            throw new ArgumentException(
                $"OpenID provider '{provider?.ReplaceLineEndings(string.Empty)}' sets RequireAcr but no Acr Values; set the required acr_values (space-separated) the returned acr must match, or turn RequireAcr off.",
                nameof(config));
        }
    }

    // A malformed override would be persisted and then silently fall back to the request Host at
    // login (#139). The provider name is line-ending-stripped inline in case it reaches a log through
    // the thrown exception.

    /// <summary>
    /// Rejects a canonical base-URL override that is set but is not a valid absolute http(s) base URL,
    /// which would otherwise persist and then silently fall back to the request Host at login (#139). A
    /// blank override is valid (the feature is off).
    /// </summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="baseUrlOverride">The override value to check.</param>
    /// <exception cref="ArgumentException">The override is non-blank and not a valid absolute http(s) URL.</exception>
    internal static void ValidateBaseUrlOverride(string protocol, string provider, string? baseUrlOverride)
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

    /// <summary>
    /// Rejects a SAML provider whose signing certificate is set but is not a loadable X.509 certificate,
    /// which would otherwise persist and then throw on every callback (an unhandled 500, #206). A blank
    /// certificate is valid (a half-configured provider).
    /// </summary>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="certificate">The Base64-encoded (DER) X.509 certificate to check.</param>
    /// <exception cref="ArgumentException">The certificate is non-blank and not loadable.</exception>
    internal static void ValidateSamlCertificate(string provider, string? certificate)
    {
        if (SamlCertificate.IsInvalid(certificate ?? string.Empty))
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

    /// <summary>
    /// Rejects a SAML provider whose OPTIONAL secondary verification certificate (#491) is set but not
    /// loadable — the identity provider's public certificate for a key-overlap window, validated exactly
    /// like the primary. A blank value is valid (no overlap window configured).
    /// </summary>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="certificate">The Base64-encoded (DER) X.509 certificate to check.</param>
    /// <exception cref="ArgumentException">The certificate is non-blank and not loadable.</exception>
    internal static void ValidateSamlSecondaryCertificate(string provider, string? certificate)
    {
        if (SamlCertificate.IsInvalid(certificate ?? string.Empty))
        {
            throw new ArgumentException(
                $"SAML provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid secondary signing certificate; it must be a Base64-encoded (DER) X.509 certificate.",
                nameof(certificate));
        }
    }

    // A malformed generic permission-role mapping (#164) would be persisted and then silently grant
    // nothing for the offending entry at login (fail-closed at runtime), leaving the admin's intended
    // permission un-applied with no feedback. Reject it at the door instead: every entry's Permission must
    // name a known Jellyfin PermissionKind that is not one of the dedicated permissions managed by their
    // own fields (administrator, all-folders, Live TV access/management) — those have exactly one
    // authoritative source and may not be double-mapped here. A null entry maps nothing and is tolerated
    // (it grants nothing at runtime). Both the config-page save and the Add endpoints run this. The
    // provider name and the echoed permission are control-stripped in case they reach a log through the
    // thrown exception.

    /// <summary>
    /// Rejects a permission-role mapping (#164) whose Permission is empty, is not a known Jellyfin
    /// PermissionKind, or names one of the dedicated permissions owned by their own fields (administrator,
    /// all-folders, Live TV, account-disable). Such an entry would otherwise persist and silently grant
    /// nothing at login. A null mappings collection or a null entry maps nothing and is tolerated.
    /// </summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (control-stripped) in the rejection message.</param>
    /// <param name="mappings">The permission-role mappings to check.</param>
    /// <exception cref="ArgumentException">An entry names an invalid or dedicated permission.</exception>
    internal static void ValidatePermissionRoleMappings(string protocol, string provider, System.Collections.Generic.IEnumerable<PermissionRoleMap>? mappings)
    {
        if (mappings == null)
        {
            return;
        }

        foreach (var mapping in mappings)
        {
            if (mapping == null)
            {
                continue;
            }

            var status = PermissionRolePolicy.Classify(mapping.Permission);
            if (status == PermissionRolePolicy.PermissionNameStatus.Valid)
            {
                continue;
            }

            var echoName = (provider ?? string.Empty).ReplaceLineEndings(string.Empty);
            var echoPerm = string.Concat((mapping.Permission ?? string.Empty).Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);
            var reason = status switch
            {
                PermissionRolePolicy.PermissionNameStatus.Empty => "has an empty permission name",
                PermissionRolePolicy.PermissionNameStatus.Dedicated => $"names '{echoPerm}', which is managed by its own dedicated setting (administrator, all-folders, or Live TV) or is barred from role mapping (account-disable) and may not be mapped here",
                _ => $"names '{echoPerm}', which is not a known Jellyfin permission",
            };
            throw new ArgumentException(
                $"{protocol} provider '{echoName}' has an invalid permission-role mapping: it {reason}. Each mapping's Permission must be the exact name of a Jellyfin PermissionKind (for example EnableContentDownloading) other than IsAdministrator, EnableAllFolders, EnableLiveTvAccess, EnableLiveTvManagement, or IsDisabled.",
                nameof(mappings));
        }
    }

    // A parental-rating mapping (#736) with a negative score or no roles would be persisted and then either
    // never apply (no roles) or be a nonsensical ceiling — reject both fail-closed at save so a mis-set is
    // caught before it takes effect. A null entry maps nothing and is tolerated (it contributes nothing at
    // runtime). Both the config-page save and the Add endpoints run this. The provider name is control-
    // stripped in case it reaches a log through the thrown exception.

    /// <summary>
    /// Rejects a parental-rating mapping (#736) with a negative score or with no roles — the former is a
    /// nonsensical ceiling, the latter would never apply. Both are caught at save so a mis-set is found
    /// before it takes effect. A null mappings collection or a null entry maps nothing and is tolerated.
    /// </summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="mappings">The parental-rating mappings to check.</param>
    /// <exception cref="ArgumentException">An entry has a negative score or lists no roles.</exception>
    internal static void ValidateParentalRatingMappings(string protocol, string provider, System.Collections.Generic.IEnumerable<ParentalRatingRoleMap>? mappings)
    {
        if (mappings == null)
        {
            return;
        }

        foreach (var mapping in mappings)
        {
            if (mapping == null)
            {
                continue;
            }

            var echoName = (provider ?? string.Empty).ReplaceLineEndings(string.Empty);
            if (mapping.Score < 0)
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has an invalid parental-rating mapping: the score must be zero or greater (a smaller value is more restrictive; null/unmapped leaves the ceiling untouched).",
                    nameof(mappings));
            }

            if (mapping.Roles == null || mapping.Roles.Length == 0)
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has a parental-rating mapping with no roles: each mapping must list at least one role the ceiling applies to.",
                    nameof(mappings));
            }
        }
    }

    // A garbage service-provider signing key (#167) would be persisted and then fail every signed
    // challenge. On the config-page save the key is withheld from JSON so it arrives blank (valid) and the
    // stored one is re-injected afterwards; this rejects the case where a non-blank, unloadable key is
    // posted. Same inline line-ending strip as above.

    /// <summary>
    /// Rejects a service-provider request signing key (#167/#491) that is non-blank but not a loadable
    /// unencrypted PKCS#12 blob, which would otherwise persist and fail every signed challenge. A blank
    /// key is valid — a config-page save withholds the key from JSON, so it arrives blank and the stored
    /// one is re-injected afterwards.
    /// </summary>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="signingKeyPfx">The Base64-encoded PKCS#12 (PFX) signing key to check.</param>
    /// <exception cref="ArgumentException">The key is non-blank and not a loadable PFX with an RSA or ECDSA private key.</exception>
    internal static void ValidateSamlSigningKey(string provider, string? signingKeyPfx)
    {
        if (SamlSigningKey.IsInvalid(signingKeyPfx ?? string.Empty))
        {
            throw new ArgumentException(
                $"SAML provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid request signing key; it must be a Base64-encoded, unencrypted PKCS#12 (PFX) blob containing an RSA or ECDSA private key.",
                nameof(signingKeyPfx));
        }
    }
}
