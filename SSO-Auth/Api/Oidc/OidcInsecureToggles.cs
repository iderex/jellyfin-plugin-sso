// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Names the per-provider OpenID options that switch off an RFC 9700-mandated protection (#140), so
/// enabling one leaves a visible, auditable trace instead of silently weakening the login path. These
/// are legitimate escape hatches (e.g. Google's cross-host endpoints need <c>DoNotValidateEndpoints</c>),
/// so they are kept — but their cost is surfaced, not hidden.
/// </summary>
internal static class OidcInsecureToggles
{
    /// <summary>
    /// Lists the insecure options currently enabled on a provider, by their configuration-key names
    /// (stable and greppable), most-severe first. Empty when the provider is fully validated.
    /// </summary>
    /// <param name="config">The OpenID provider configuration.</param>
    /// <returns>The enabled insecure option names.</returns>
    internal static IReadOnlyList<string> Enabled(OidConfig? config)
    {
        var enabled = new List<string>();
        if (config == null)
        {
            return enabled;
        }

        // DisableHttps first: it drops TLS on discovery/JWKS/token, so the id_token's signing keys
        // are fetched over a MITM-able channel — the most damaging of the three.
        if (config.DisableHttps)
        {
            enabled.Add(nameof(OidConfig.DisableHttps));
        }

        if (config.DoNotValidateIssuerName)
        {
            enabled.Add(nameof(OidConfig.DoNotValidateIssuerName));
        }

        if (config.DoNotValidateEndpoints)
        {
            enabled.Add(nameof(OidConfig.DoNotValidateEndpoints));
        }

        // RFC 9207 response-iss check (#125): last because it is defence-in-depth on top of the
        // per-provider callback binding, which already resists the classic mix-up on its own.
        if (config.DoNotValidateResponseIssuer)
        {
            enabled.Add(nameof(OidConfig.DoNotValidateResponseIssuer));
        }

        return enabled;
    }
}
