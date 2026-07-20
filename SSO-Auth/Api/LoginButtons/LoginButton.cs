namespace Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;

/// <summary>
/// The SSO protocol a <see cref="LoginButton"/> starts, choosing the anonymous start route it links to.
/// </summary>
public enum LoginButtonProtocol
{
    /// <summary>OpenID Connect — links to <c>/sso/OID/start/{name}</c>.</summary>
    Oidc,

    /// <summary>SAML 2.0 — links to <c>/sso/SAML/start/{name}</c>.</summary>
    Saml,
}

/// <summary>
/// A single "Sign in with …" button to render on the Jellyfin login page (#722). Immutable value type: the
/// display <see cref="Text"/> and the provider <see cref="Name"/> are admin/provider-controlled strings that
/// are HTML/URL-encoded at render time by <see cref="LoginButtonInjector"/>, never trusted as markup.
/// </summary>
/// <param name="Protocol">The provider protocol, selecting the start route segment (OID or SAML).</param>
/// <param name="Name">The provider name (its config-dictionary key), used to build the start URL.</param>
/// <param name="Text">The button label shown to the visitor.</param>
public readonly record struct LoginButton(LoginButtonProtocol Protocol, string Name, string Text);
