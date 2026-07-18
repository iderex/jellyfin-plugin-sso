namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The two discovery-document facts the OpenID challenge reads from a single discovery response: whether
/// the authorization server advertises PKCE with SHA-256 (#141) and whether it advertises the RFC 9207
/// response-<c>iss</c> parameter (#210). Both are definite booleans because they are produced only from a
/// document that was actually read (<see cref="OidcDiscoveryReader"/>); a document that could not be read
/// yields <see cref="OidcDiscoveryResult.Unavailable"/> instead, so the caller fails the login closed
/// rather than defaulting to a weaker enforcement.
/// </summary>
/// <param name="PkceS256">Whether the AS advertises PKCE S256 (<c>false</c> when the read document does not list it).</param>
/// <param name="ResponseIssuerAdvertised">Whether the AS advertises the RFC 9207 response-<c>iss</c> parameter.</param>
internal readonly record struct DiscoveryFacts(bool PkceS256, bool ResponseIssuerAdvertised);
