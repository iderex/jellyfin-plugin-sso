#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Composes the SSO URLs this service provider hands to identity providers: the OIDC redirect_uri
/// and the SAML AssertionConsumerServiceURL, plus the expected-ACS set the Recipient/Destination
/// binding (#156) compares against. These strings are validated byte-for-byte on the other side
/// (RFC 6749 section 4.1.3 redirect_uri equality; the SAML Recipient echo is compared Ordinal), so
/// every method concatenates exactly what the previously scattered call sites produced: lowercase
/// "/sso/", the protocol segment, the route-spelling variant, and the route-decoded provider name
/// appended raw — never re-encoded, since encoding would change the bytes identity providers
/// already have registered.
/// </summary>
internal static class SsoUrlBuilder
{
    /// <summary>Builds the challenge-time OIDC redirect_uri; the spelling follows the route the login started on.</summary>
    /// <param name="baseUrl">The canonical base URL, trailing-slash free (from <see cref="Net.CanonicalBaseUrl.Resolve"/>).</param>
    /// <param name="newPath">Whether the login started on the new-path route, choosing "redirect" over "r".</param>
    /// <param name="provider">The route-decoded provider name, appended raw.</param>
    /// <returns>The absolute redirect_uri to register the authorization request under.</returns>
    internal static string OidRedirectUri(string baseUrl, bool newPath, string provider) =>
        Build(baseUrl, "OID", newPath ? "redirect" : "r", provider);

    /// <summary>Builds the token-exchange redirect_uri, echoing the spelling of the callback's own path (#98).</summary>
    /// <param name="baseUrl">The canonical base URL, trailing-slash free.</param>
    /// <param name="callbackPath">The callback request's path, whose OID segment decides the spelling.</param>
    /// <param name="provider">The route-decoded provider name, appended raw.</param>
    /// <returns>The redirect_uri the token request must repeat byte-for-byte.</returns>
    internal static string OidCallbackRedirectUri(string baseUrl, string? callbackPath, string provider) =>
        Build(baseUrl, "OID", OidcCallbackPath.RedirectSegment(callbackPath), provider);

    /// <summary>Builds the SAML AssertionConsumerServiceURL advertised in the AuthnRequest.</summary>
    /// <param name="baseUrl">The canonical base URL, trailing-slash free.</param>
    /// <param name="newPath">Whether the login started on the new-path route, choosing "post" over "p".</param>
    /// <param name="provider">The route-decoded provider name, appended raw.</param>
    /// <returns>The absolute URL the identity provider must POST the assertion to.</returns>
    internal static string SamlAcsUrl(string baseUrl, bool newPath, string provider) =>
        Build(baseUrl, "SAML", newPath ? "post" : "p", provider);

    /// <summary>
    /// Builds both ACS spellings this provider could have advertised. NewPath is process-wide mutable
    /// configuration a concurrent challenge can flip between challenge and callback, so the Recipient
    /// binding accepts either spelling; deriving both from <see cref="SamlAcsUrl"/> makes it structural
    /// that the validator cannot drift from the challenge-time string.
    /// </summary>
    /// <param name="baseUrl">The canonical base URL, trailing-slash free.</param>
    /// <param name="provider">The route-decoded provider name, appended raw.</param>
    /// <returns>The new-path spelling first, then the legacy spelling.</returns>
    internal static string[] SamlExpectedAcsUrls(string baseUrl, string provider) =>
        new[] { SamlAcsUrl(baseUrl, newPath: true, provider), SamlAcsUrl(baseUrl, newPath: false, provider) };

    private static string Build(string baseUrl, string protocol, string segment, string provider) =>
        baseUrl + "/sso/" + protocol + "/" + segment + "/" + provider;
}
