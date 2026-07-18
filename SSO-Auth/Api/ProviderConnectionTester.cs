using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Runs an admin-triggered Test-connection probe against a STORED provider configuration (#163) so an
/// administrator can confirm connectivity and basic config before a user hits the failure at first login.
/// The endpoints that call this are elevation-gated (see <see cref="SSOController"/>), and the probe fetches
/// only the already-stored provider URL — the exact URL the (rate-limited) anonymous login challenge already
/// fetches — so it adds no outbound-fetch surface beyond the login path.
///
/// OpenID: reads the discovery document through the SAME hardened reader the login uses
/// (<see cref="OidcDiscoveryReader"/> under the provider's <see cref="OidcDiscoveryOptions"/> discovery
/// policy — RequireHttps / ValidateIssuerName / ValidateEndpoints), and reports the issuer, endpoints and
/// JWKS reachability from that one response. It never reveals the client secret (discovery needs no
/// credential). SAML: parses the configured PUBLIC signing certificate and reports its non-secret facts;
/// there is no SAML metadata-URL field, so the SAML probe makes no network call. Neither path ever puts a
/// secret, signing key, or DEK into the <see cref="ProviderTestResult"/> or the log.
/// </summary>
internal static class ProviderConnectionTester
{
    /// <summary>
    /// Probes a stored OpenID provider: reads its discovery document under the login's hardened discovery
    /// policy and reports the issuer, endpoints, JWKS reachability and the two discovery facts. Fail-closed
    /// and actionable — an unreadable document or an invalid endpoint returns a non-Ok result with a
    /// generic, secret-free message rather than throwing.
    /// </summary>
    /// <param name="config">The stored OpenID provider configuration.</param>
    /// <param name="provider">The provider name, for the reader's fail-closed warning only.</param>
    /// <param name="httpClientFactory">The shared HTTP client factory the hardened discovery fetch is built over.</param>
    /// <param name="logger">The logger the reader logs its fail-closed warning to (never a secret).</param>
    /// <returns>The probe result, safe to return to an administrator.</returns>
    internal static async Task<ProviderTestResult> TestOidcAsync(OidConfig config, string provider, IHttpClientFactory httpClientFactory, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(config.OidEndpoint))
        {
            return ProviderTestResult.Failure("No OpenID endpoint is configured. Set the OpenID Endpoint, save the provider, then test again.");
        }

        OidcClientOptions options;
        try
        {
            // Same discovery policy the login builds (#163), so the probe's TLS/endpoint posture matches.
            options = OidcDiscoveryOptions.Build(config);
        }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException)
        {
            return ProviderTestResult.Failure("The configured OpenID Endpoint is not a valid absolute URL (for example https://idp.example.com).");
        }

        var discovery = await OidcDiscoveryReader.ReadAsync(options, provider, httpClientFactory, logger).ConfigureAwait(false);
        if (!discovery.Available)
        {
            // The reader already logged the fail-closed warning (with the library error, never a secret).
            // The admin-facing message stays generic: it names what to check, not any sensitive value.
            return ProviderTestResult.Failure(
                "Could not read the OpenID discovery document. Check that the endpoint is reachable, serves /.well-known/openid-configuration, and — unless HTTPS discovery is disabled — is served over HTTPS.");
        }

        var info = discovery.ProviderInformation;
        var jwksKeyCount = info.KeySet?.Keys?.Count ?? 0;
        var jwksReachable = info.KeySet is not null;

        var details = new List<string>
        {
            "Issuer: " + Describe(info.IssuerName),
            "Authorization endpoint: " + Describe(info.AuthorizeEndpoint),
            "Token endpoint: " + Describe(info.TokenEndpoint),
            "UserInfo endpoint: " + Describe(info.UserInfoEndpoint),
            jwksReachable
                ? $"JWKS: reachable ({jwksKeyCount} key(s))"
                : "JWKS: the discovery document advertised no jwks_uri",
            "PKCE (S256) advertised: " + YesNo(discovery.Facts.PkceS256),
            "RFC 9207 response-iss advertised: " + YesNo(discovery.Facts.ResponseIssuerAdvertised),
        };

        return ProviderTestResult.Success("The OpenID discovery document was read successfully.", details);
    }

    /// <summary>
    /// Probes a stored SAML provider: parses the configured PUBLIC signing certificate and reports its
    /// non-secret facts (subject, issuer, validity window, SHA-256 thumbprint). No network call — there is
    /// no metadata-URL field — and never the service-provider signing key. A non-parsing certificate returns
    /// a non-Ok result with an actionable, secret-free message.
    /// </summary>
    /// <param name="config">The stored SAML provider configuration.</param>
    /// <returns>The probe result, safe to return to an administrator.</returns>
    internal static ProviderTestResult TestSaml(SamlConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.SamlCertificate))
        {
            return ProviderTestResult.Failure("No SAML signing certificate is configured. Paste the identity provider's Base64 (DER) X.509 signing certificate, save the provider, then test again.");
        }

        X509Certificate2 certificate;
        try
        {
            // The same parse SamlCertificate.IsInvalid performs (#206): Base64 (DER) X.509. The IdP signing
            // certificate carries only the PUBLIC key, so nothing secret is loaded or reported.
            certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(config.SamlCertificate));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            return ProviderTestResult.Failure("The configured SAML signing certificate could not be parsed. It must be the identity provider's Base64-encoded (DER) X.509 PUBLIC signing certificate — not a PEM wrapper and not a private key.");
        }

        using (certificate)
        {
            var notBefore = certificate.NotBefore.ToUniversalTime();
            var notAfter = certificate.NotAfter.ToUniversalTime();
            var now = DateTime.UtcNow;

            var details = new List<string>
            {
                "Subject: " + Describe(certificate.Subject),
                "Issuer: " + Describe(certificate.Issuer),
                $"Valid from (UTC): {notBefore:u}",
                $"Valid to (UTC): {notAfter:u}",
                "SHA-256 thumbprint: " + certificate.GetCertHashString(HashAlgorithmName.SHA256),
            };

            if (now < notBefore || now > notAfter)
            {
                details.Add("Note: the certificate is outside its validity period — logins may fail until it is renewed.");
            }

            return ProviderTestResult.Success("The SAML signing certificate parsed successfully.", details);
        }
    }

    // A discovery value the admin can eyeball, or an explicit marker when the document did not advertise it,
    // so a blank field reads as "not advertised" rather than an empty line.
    private static string Describe(string value) =>
        string.IsNullOrWhiteSpace(value) ? "(not advertised)" : value;

    private static string YesNo(bool value) => value ? "yes" : "no";
}
