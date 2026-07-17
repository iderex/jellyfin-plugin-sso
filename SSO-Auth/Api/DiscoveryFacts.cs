namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The two discovery-document facts the OpenID challenge reads in one fetch: PKCE-S256 support (#141) —
/// true when advertised, false when the document was read but does not advertise it, null when it could
/// not be fetched/read — and whether the authorization server advertises the RFC 9207 response-<c>iss</c>
/// parameter (#210), which is tolerant (false) whenever the document could not be read so an unreadable
/// flag never locks out a provider that omits <c>iss</c>. Produced by <see cref="OidcDiscoveryCache"/>.
/// </summary>
/// <param name="PkceS256">Whether the AS advertises PKCE S256; null when discovery could not be read.</param>
/// <param name="ResponseIssuerAdvertised">Whether the AS advertises the RFC 9207 response-<c>iss</c> parameter.</param>
internal readonly record struct DiscoveryFacts(bool? PkceS256, bool ResponseIssuerAdvertised);
