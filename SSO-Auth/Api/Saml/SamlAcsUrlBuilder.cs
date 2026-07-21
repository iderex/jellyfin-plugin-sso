// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Composes the SAML AssertionConsumerServiceURL this service provider hands to identity providers, plus
/// the expected-ACS set the Recipient/Destination binding (#156) compares against. The SAML Recipient echo
/// is compared Ordinal — byte-for-byte — so every method concatenates exactly what the previously scattered
/// call sites produced: lowercase "/sso/", the "SAML" segment, the route-spelling variant, and the
/// route-decoded provider name appended raw — never re-encoded, since encoding would change the bytes
/// identity providers already have registered.
/// (Split out of the kernel SsoUrlBuilder in #790 so the SAML half lives in the Saml module.)
/// </summary>
internal static class SamlAcsUrlBuilder
{
    /// <summary>Builds the AssertionConsumerServiceURL advertised in the AuthnRequest.</summary>
    /// <param name="baseUrl">The canonical base URL, trailing-slash free (from <see cref="Net.CanonicalBaseUrl.Resolve"/>).</param>
    /// <param name="newPath">Whether the login started on the new-path route, choosing "post" over "p".</param>
    /// <param name="provider">The route-decoded provider name, appended raw.</param>
    /// <returns>The absolute URL the identity provider must POST the assertion to.</returns>
    internal static string AcsUrl(string baseUrl, bool newPath, string provider) =>
        Build(baseUrl, newPath ? "post" : "p", provider);

    /// <summary>
    /// Builds both ACS spellings this provider could have advertised. NewPath is process-wide mutable
    /// configuration a concurrent challenge can flip between challenge and callback, so the Recipient
    /// binding accepts either spelling; deriving both from <see cref="AcsUrl"/> makes it structural
    /// that the validator cannot drift from the challenge-time string.
    /// </summary>
    /// <param name="baseUrl">The canonical base URL, trailing-slash free.</param>
    /// <param name="provider">The route-decoded provider name, appended raw.</param>
    /// <returns>The new-path spelling first, then the legacy spelling.</returns>
    internal static string[] ExpectedAcsUrls(string baseUrl, string provider) =>
        new[] { AcsUrl(baseUrl, newPath: true, provider), AcsUrl(baseUrl, newPath: false, provider) };

    private static string Build(string baseUrl, string segment, string provider) =>
        baseUrl + "/sso/SAML/" + segment + "/" + provider;
}
