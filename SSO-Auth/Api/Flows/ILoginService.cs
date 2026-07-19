using System;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.SSO_Auth.Api.Flows;

/// <summary>
/// The shared contract every SSO login protocol implements (#790). Each protocol module has exactly one
/// implementation — <see cref="OidcLoginService"/> for OpenID Connect and <see cref="SamlLoginService"/> for
/// SAML — so the session-minting authenticate leg is a single, protocol-agnostic shape rather than two
/// parallel code paths, and a future protocol slots in by implementing this interface instead of forking a
/// third path. This is a composition-first abstraction: protocols are polymorphic implementations of one
/// contract, not a deep inheritance hierarchy. Protocol-specific operations that do not generalise (SAML SP
/// metadata, the OIDC state summaries) stay off the interface, on the concrete service.
/// </summary>
internal interface ILoginService
{
    /// <summary>
    /// Redeems the browser-bound authorize state once and mints the session for the already-verified
    /// identity, delegating to the shared completion tail. The controller keeps the flow tier HttpContext-free
    /// (#177) by resolving the presented binding cookie and the remote endpoint and passing them in; the
    /// binding-cookie NAME is protocol-specific and chosen by the controller, so this contract takes the
    /// resolved cookie value.
    /// </summary>
    /// <param name="provider">The configured provider name.</param>
    /// <param name="response">The client-presented one-time exchange payload.</param>
    /// <param name="bindingCookie">The presented browser-binding cookie value (or null when absent).</param>
    /// <param name="remoteEndPointResolver">Resolves the caller's normalized remote IP, lazily.</param>
    /// <returns>The session result, or a fail-closed rejection.</returns>
    Task<ActionResult> AuthenticateAsync(string provider, AuthResponse response, string bindingCookie, Func<string> remoteEndPointResolver);
}
