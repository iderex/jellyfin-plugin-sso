#nullable enable
using System;
using System.Security.Cryptography;
using System.Text;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Signs an outgoing SAML message for the HTTP-Redirect binding (SAML Bindings 3.4.4.1, #167). The plugin
/// sends its AuthnRequest as a DEFLATE-compressed, Base64-encoded query parameter, so the signature is NOT
/// an enveloped XML <c>ds:Signature</c> (identity providers ignore one on a redirect-binding message) but a
/// detached signature over the URL-encoded query string, computed in the mandated parameter order
/// (SAMLRequest, then RelayState when present, then SigAlg) and appended as the Signature parameter. The
/// algorithm is RSA-SHA256, verified against the shared allowlist so this path can never sign with a weaker
/// algorithm than the inbound path demands (no SHA-1).
/// </summary>
internal static class SamlRedirectSigner
{
    private const string RsaSha256SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /// <summary>
    /// Builds the signed redirect URL for a DEFLATE/Base64-encoded SAML message.
    /// </summary>
    /// <param name="endpoint">The identity provider's endpoint URL.</param>
    /// <param name="parameterName">"SAMLRequest" or "SAMLResponse".</param>
    /// <param name="encodedMessage">The DEFLATE-compressed, Base64-encoded message.</param>
    /// <param name="relayState">The relay state, omitted when null or empty.</param>
    /// <param name="signingKey">The service-provider RSA private key.</param>
    /// <returns>The full redirect URL including SigAlg and Signature.</returns>
    /// <exception cref="ArgumentException">Thrown when the endpoint or message is null or empty.</exception>
    internal static string BuildSignedRedirectUrl(string endpoint, string parameterName, string encodedMessage, string? relayState, RSA signingKey)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            throw new ArgumentException("Endpoint must not be empty.", nameof(endpoint));
        }

        if (string.IsNullOrEmpty(encodedMessage))
        {
            throw new ArgumentException("Message must not be empty.", nameof(encodedMessage));
        }

        ArgumentNullException.ThrowIfNull(signingKey);

        // Defense in depth: the algorithm this signer emits must be one the inbound path would also accept,
        // so a future edit cannot quietly introduce SHA-1 here while the response validator still rejects it.
        if (!SamlSignatureAlgorithms.IsSignatureMethodAllowed(RsaSha256SignatureAlgorithm))
        {
            throw new InvalidOperationException("The outgoing SAML signing algorithm is not on the signature allowlist.");
        }

        // The signature covers these parameters URL-encoded, in exactly this order, as they will appear in
        // the query string. Uri.EscapeDataString is used both to compute the signed octets and to emit the
        // URL, so the identity provider verifies over the exact bytes transmitted.
        var signedQuery = parameterName + "=" + Uri.EscapeDataString(encodedMessage);
        if (!string.IsNullOrEmpty(relayState))
        {
            signedQuery += "&RelayState=" + Uri.EscapeDataString(relayState);
        }

        signedQuery += "&SigAlg=" + Uri.EscapeDataString(RsaSha256SignatureAlgorithm);

        var signature = signingKey.SignData(Encoding.UTF8.GetBytes(signedQuery), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var query = signedQuery + "&Signature=" + Uri.EscapeDataString(Convert.ToBase64String(signature));

        var separator = endpoint.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        return endpoint + separator + query;
    }
}
