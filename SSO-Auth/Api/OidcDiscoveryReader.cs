using System;
using System.Net.Http;
using System.Threading.Tasks;
using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Reads a provider's OpenID discovery document ONCE at the challenge and returns both the two
/// security-relevant facts — PKCE-S256 support (#141, RFC 9700 §2.1.1) and whether the authorization
/// server advertises the RFC 9207 response-<c>iss</c> parameter (#210) — AND the
/// <see cref="Duende.IdentityModel.OidcClient.ProviderInformation"/> the OidcClient login is fed. Before
/// #450 the facts came from a SEPARATE best-effort probe, distinct from the discovery
/// <see cref="OidcClient.PrepareLoginAsync"/> performs internally: the two could disagree, and a failed or
/// omitted probe silently downgraded the RFC 9207 requirement. Sourcing both from one response removes that
/// split — the facts and the login can no longer diverge, and there is no second fetch to fail.
///
/// The fetch is IdentityModel's own <see cref="HttpClientDiscoveryExtensions.GetDiscoveryDocumentAsync(System.Net.Http.HttpMessageInvoker, DiscoveryDocumentRequest, System.Threading.CancellationToken)"/>
/// under the caller's <see cref="DiscoveryPolicy"/> (<c>RequireHttps</c> / <c>ValidateIssuerName</c> /
/// <c>ValidateEndpoints</c> / the additional base addresses) — the exact call and policy OidcClient uses,
/// so the plugin-owned read honours the same channel and endpoint validation rather than a bespoke,
/// unvalidated GET (closing the earlier probe's <c>RequireHttps</c> gap). The resulting metadata is fed to
/// PrepareLoginAsync via <see cref="OidcClientOptions.ProviderInformation"/>, which suppresses the library's
/// own second discovery.
///
/// Stateless — a fresh read per challenge, exactly the per-challenge discovery the library performed before
/// this change. Nothing is cached: least of all the JWKS the callback validates the id_token against, whose
/// reuse stays bounded by a single authorize state's lifetime (#247), never widened by a process-wide cache.
/// </summary>
internal static class OidcDiscoveryReader
{
    // The discovery/JWKS fetch is bounded so a slow or hanging authorization server cannot stall the
    // anonymous challenge endpoint. This is now the login-critical discovery (its result is fed to
    // PrepareLoginAsync), so the bound is tighter than the platform-default ~100s the library's own
    // in-PrepareLoginAsync discovery ran under before #450 — a deliberate anonymous-endpoint DoS-hardening
    // trade-off: a pathologically slow IdP (a 10s+ cold start) is refused fail-closed and self-heals on the
    // next challenge, rather than tying up the endpoint. It keeps the 10s the pre-#450 probe already applied.
    private static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Reads the discovery document named by <paramref name="options"/> (its <c>Authority</c> and
    /// <c>Policy.Discovery</c>) and returns the facts plus the provider metadata built from it, or
    /// <see cref="OidcDiscoveryResult.Unavailable"/> when the document could not be read. Never throws — a
    /// transient failure, a policy rejection (e.g. non-HTTPS under <c>RequireHttps</c>), or a malformed
    /// document all return <c>Unavailable</c> so the caller fails the login closed rather than proceeding on
    /// unverified facts.
    /// </summary>
    /// <param name="options">The OidcClient options whose <c>Authority</c> and discovery policy the read uses — the same the login is built with.</param>
    /// <param name="provider">The provider name, for the failure warning only.</param>
    /// <param name="httpClientFactory">The shared HTTP client factory the outbound fetch is built over.</param>
    /// <param name="logger">The logger for the fail-closed read-failure warning.</param>
    /// <returns>The facts and provider metadata from the one discovery response, or <see cref="OidcDiscoveryResult.Unavailable"/>.</returns>
    internal static async Task<OidcDiscoveryResult> ReadAsync(OidcClientOptions options, string provider, IHttpClientFactory httpClientFactory, ILogger logger)
    {
        try
        {
            using var client = SsoHttp.CreateClient(httpClientFactory);
            client.Timeout = FetchTimeout;

            var discovery = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = options.Authority,
                Policy = options.Policy.Discovery,
            }).ConfigureAwait(false);

            if (discovery.IsError)
            {
                // The provider name and the library error are stripped of line endings inline at the log
                // call so an admin-supplied value or a reflected server string cannot forge or split the
                // entry (the log-forging sanitizer never crosses a helper boundary).
                logger.LogWarning(
                    "Could not read the OpenID discovery document for provider {Provider}: {Error}. The login fails closed rather than proceeding on unverified discovery facts.",
                    provider?.ReplaceLineEndings(string.Empty),
                    discovery.Error?.ReplaceLineEndings(string.Empty));
                return OidcDiscoveryResult.Unavailable;
            }

            // Both facts come from the raw body of THIS response (the same bytes the metadata below is
            // parsed from), read through the two fail-closed/tolerant pure parsers: PKCE-S256 fails closed
            // (#141, caller rejects only under RequirePkce), response-iss stays tolerant (#210, absence
            // never locks out a provider that omits `iss`).
            var facts = new DiscoveryFacts(
                PkceDiscovery.SupportsS256(discovery.Raw),
                OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(discovery.Raw));

            // The exact discovery -> ProviderInformation mapping OidcClient performs internally, so feeding
            // this back into PrepareLoginAsync reproduces the library's own login setup from the very
            // response the facts were read from (#450). Populated only from this policy-validated fetch, so
            // the DiscoveryPolicy is not bypassed.
            var providerInformation = new ProviderInformation
            {
                IssuerName = discovery.Issuer,
                KeySet = discovery.KeySet,
                AuthorizeEndpoint = discovery.AuthorizeEndpoint,
                PushedAuthorizationRequestEndpoint = discovery.PushedAuthorizationRequestEndpoint,
                TokenEndpoint = discovery.TokenEndpoint,
                EndSessionEndpoint = discovery.EndSessionEndpoint,
                UserInfoEndpoint = discovery.UserInfoEndpoint,
                TokenEndPointAuthenticationMethods = discovery.TokenEndpointAuthenticationMethodsSupported,
            };

            return OidcDiscoveryResult.From(facts, providerInformation);
        }
        catch (Exception e)
        {
            logger.LogWarning(
                e,
                "Could not read the OpenID discovery document for provider {Provider}; the login fails closed rather than proceeding on unverified discovery facts.",
                provider?.ReplaceLineEndings(string.Empty));
            return OidcDiscoveryResult.Unavailable;
        }
    }
}
