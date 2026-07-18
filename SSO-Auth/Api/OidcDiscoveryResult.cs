using Duende.IdentityModel.OidcClient;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The outcome of the OpenID challenge's single discovery read (<see cref="OidcDiscoveryReader"/>, #450):
/// the two security-relevant facts and the <see cref="Duende.IdentityModel.OidcClient.ProviderInformation"/>
/// the login itself is fed — both derived from the SAME discovery response, so the enforcement facts and
/// the login can never diverge, and neither can be silently weakened by a failed second probe.
/// <see cref="Available"/> is <see langword="false"/> only when the document could not be read at all; the
/// caller then fails the login closed rather than proceeding on unverified facts.
/// </summary>
/// <param name="Facts">The PKCE-S256 (#141) and RFC 9207 response-<c>iss</c> (#210) facts read from the document.</param>
/// <param name="ProviderInformation">The provider metadata built from the same document, or null when the read failed.</param>
internal readonly record struct OidcDiscoveryResult(DiscoveryFacts Facts, ProviderInformation ProviderInformation)
{
    /// <summary>Gets a value indicating whether the discovery document was read (the facts and metadata are usable).</summary>
    internal bool Available => ProviderInformation is not null;

    /// <summary>Gets the failed-read result — no facts, no metadata — on which the caller fails the login closed.</summary>
    internal static OidcDiscoveryResult Unavailable => default;

    /// <summary>A successful read: the facts and the provider metadata, both from the one discovery response.</summary>
    /// <param name="facts">The facts parsed from the discovery document.</param>
    /// <param name="providerInformation">The provider metadata built from the same document (never null on success).</param>
    /// <returns>An available result carrying both.</returns>
    internal static OidcDiscoveryResult From(DiscoveryFacts facts, ProviderInformation providerInformation) =>
        new(facts, providerInformation);
}
