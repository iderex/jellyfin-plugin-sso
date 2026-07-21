// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Security.Cryptography;
using System.Text;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Signs an outgoing SAML message for the HTTP-Redirect binding (SAML Bindings 3.4.4.1, #167). The plugin
/// sends its AuthnRequest as a DEFLATE-compressed, Base64-encoded query parameter, so the signature is NOT
/// an enveloped XML <c>ds:Signature</c> (identity providers ignore one on a redirect-binding message) but a
/// detached signature over the URL-encoded query string, computed in the mandated parameter order
/// (SAMLRequest, then RelayState when present, then SigAlg) and appended as the Signature parameter. The
/// SigAlg is chosen from the service-provider key's own type — an RSA key signs rsa-sha256, an ECDSA key
/// signs ecdsa-sha256 (#493) — and every choice is verified against the shared allowlist so this path can
/// never sign with a weaker algorithm than the inbound path demands (no SHA-1). A key that is neither RSA
/// nor ECDSA is rejected, never silently left unsigned.
/// </summary>
internal static class SamlRedirectSigner
{
    private const string RsaSha256SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private const string EcdsaSha256SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    /// <summary>
    /// Builds the signed redirect URL for a DEFLATE/Base64-encoded SAML message.
    /// </summary>
    /// <param name="endpoint">The identity provider's endpoint URL.</param>
    /// <param name="parameterName">"SAMLRequest" or "SAMLResponse".</param>
    /// <param name="encodedMessage">The DEFLATE-compressed, Base64-encoded message.</param>
    /// <param name="relayState">The relay state, omitted when null or empty.</param>
    /// <param name="signingKey">The service-provider private key — RSA or ECDSA.</param>
    /// <returns>The full redirect URL including SigAlg and Signature.</returns>
    /// <exception cref="ArgumentException">Thrown when the endpoint or message is null or empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the key is neither RSA nor ECDSA, or its algorithm is not on the allowlist.</exception>
    internal static string BuildSignedRedirectUrl(string endpoint, string parameterName, string encodedMessage, string? relayState, AsymmetricAlgorithm signingKey)
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

        // The SigAlg is derived from the key's own type: an RSA key can only sign rsa-sha256, an ECDSA key
        // only ecdsa-sha256. Any other key type is rejected here rather than silently left unsigned.
        var signatureAlgorithm = ResolveSignatureAlgorithm(signingKey);

        // Defense in depth: the algorithm this signer emits must be one the inbound path would also accept,
        // so a future edit cannot quietly introduce SHA-1 here while the response validator still rejects it.
        if (!SamlSignatureAlgorithms.IsSignatureMethodAllowed(signatureAlgorithm))
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

        signedQuery += "&SigAlg=" + Uri.EscapeDataString(signatureAlgorithm);

        var signature = Sign(signingKey, Encoding.UTF8.GetBytes(signedQuery));
        var query = signedQuery + "&Signature=" + Uri.EscapeDataString(Convert.ToBase64String(signature));

        var separator = endpoint.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        return endpoint + separator + query;
    }

    private static string ResolveSignatureAlgorithm(AsymmetricAlgorithm signingKey) => signingKey switch
    {
        RSA => RsaSha256SignatureAlgorithm,
        ECDsa => EcdsaSha256SignatureAlgorithm,
        _ => throw Unsupported(signingKey),
    };

    private static byte[] Sign(AsymmetricAlgorithm signingKey, byte[] data) => signingKey switch
    {
        RSA rsa => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),

        // XML-DSig ecdsa-sha256 signature values are the raw IEEE P1363 r||s concatenation, not the ASN.1/DER
        // sequence .NET emits by default, so the identity provider verifies the exact fixed-size octets.
        ECDsa ecdsa => ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
        _ => throw Unsupported(signingKey),
    };

    private static InvalidOperationException Unsupported(AsymmetricAlgorithm signingKey)
        => new InvalidOperationException($"Unsupported SAML signing key type '{signingKey.GetType().Name}'; only RSA and ECDSA are supported.");
}
