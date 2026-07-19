using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Names the per-provider SAML options that switch off a default-on protection (#672, the SAML parity of
/// the OpenID <see cref="Jellyfin.Plugin.SSO_Auth.Api.Oidc.OidcInsecureToggles"/> under #140), so enabling one leaves a visible, auditable
/// trace instead of silently weakening the login path. Kept strictly to default-on-DISABLE toggles: the
/// opt-in SAML hardening flags (<c>ValidateRecipient</c>, <c>ValidateInResponseTo</c>, request signing)
/// are additive protections, not downgrades, and are deliberately NOT reported here.
/// </summary>
internal static class SamlInsecureToggles
{
    /// <summary>
    /// Lists the insecure options currently enabled on a SAML provider, by their configuration-key names
    /// (stable and greppable). Empty when the provider keeps every default-on protection.
    /// </summary>
    /// <param name="config">The SAML provider configuration.</param>
    /// <returns>The enabled insecure option names.</returns>
    internal static IReadOnlyList<string> Enabled(SamlConfig config)
    {
        var enabled = new List<string>();
        if (config == null)
        {
            return enabled;
        }

        // DoNotValidateAudience drops the AudienceRestriction binding: with it on, an assertion minted for
        // a DIFFERENT service provider that shares this IdP is accepted, so it is a genuine audience/SP
        // confusion downgrade of a default-on check — exactly the class #140 audits for OpenID.
        if (config.DoNotValidateAudience)
        {
            enabled.Add(nameof(SamlConfig.DoNotValidateAudience));
        }

        return enabled;
    }
}
