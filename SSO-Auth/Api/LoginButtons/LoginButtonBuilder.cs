// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;

/// <summary>
/// Turns the plugin configuration into the ordered list of login-page buttons (#722): one button per ENABLED
/// provider that does not set <see cref="ProviderConfigBase.HideLoginButton"/>, OpenID providers first then
/// SAML, each in the provider dictionaries' order. Pure — no I/O — so the selection rule is unit-testable.
/// Disabled providers are omitted (a disabled provider's start route rejects the login anyway), matching the
/// enabled-only rule the anonymous <c>GetNames</c> endpoints already use (#344).
/// </summary>
internal static class LoginButtonBuilder
{
    /// <summary>
    /// Builds the button list for the given configuration. Returns an empty list when button management is
    /// off, so the caller renders (and merges) an empty managed block that removes any prior region.
    /// </summary>
    /// <param name="configuration">The plugin configuration.</param>
    /// <returns>The ordered buttons; empty when management is off or no provider qualifies.</returns>
    public static IReadOnlyList<LoginButton> Build(PluginConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var buttons = new List<LoginButton>();
        if (!configuration.ManageLoginPageButtons)
        {
            return buttons;
        }

        foreach (var (name, config) in configuration.OidConfigs)
        {
            AddIfVisible(buttons, LoginButtonProtocol.Oidc, name, config);
        }

        foreach (var (name, config) in configuration.SamlConfigs)
        {
            AddIfVisible(buttons, LoginButtonProtocol.Saml, name, config);
        }

        return buttons;
    }

    private static void AddIfVisible(List<LoginButton> buttons, LoginButtonProtocol protocol, string name, ProviderConfigBase config)
    {
        if (!config.Enabled || config.HideLoginButton)
        {
            return;
        }

        var text = string.IsNullOrWhiteSpace(config.LoginButtonText) ? name : config.LoginButtonText;
        buttons.Add(new LoginButton(protocol, name, text));
    }
}
