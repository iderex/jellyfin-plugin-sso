#nullable enable

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Safely constructs a <see cref="SamlResponse"/> from an untrusted SAML response string (#199). The
/// <see cref="SamlResponse"/> constructor throws on malformed input — <see cref="FormatException"/> for a
/// non-base64 body and <see cref="XmlException"/> for malformed XML or a prohibited DOCTYPE (the P2#9
/// XXE guard). Left unhandled, those surface to an unauthenticated caller as an HTTP 500 with a stack
/// trace; this maps them to a fail-closed <see langword="false"/> so the callback endpoints reject a
/// malformed response the same way they reject an invalid one — a clean 4xx.
/// </summary>
internal static class SamlResponseLoader
{
    // Maximum accepted length of the Base64 SAMLResponse. Real responses are single-digit KB; 256 KB is
    // generous headroom for role-heavy assertions and bounds the base64 decode + whitespace-preserving DOM
    // parse on the unauthenticated callback path (#249), where a multi-MB body would otherwise cost ~100 MB
    // of transient allocations before any signature is checked. The DTD prohibition stops entity expansion
    // but not raw bulk, and the rate limiter is opt-in — this is the always-on cap.

    /// <summary>The always-on ceiling (256 KB) on the Base64 SAMLResponse length, bounding the decode and DOM parse on the unauthenticated callback path before any signature is checked (#249).</summary>
    internal const int MaxEncodedResponseLength = 256 * 1024;

    /// <summary>
    /// Tries to parse a SAML response against a single signing certificate, returning
    /// <see langword="false"/> (rather than throwing) on the malformed-input exceptions the
    /// <see cref="SamlResponse"/> constructor raises.
    /// </summary>
    /// <param name="certificateStr">The identity provider's signing certificate as a Base64 string.</param>
    /// <param name="responseString">The untrusted SAML response (Base64).</param>
    /// <param name="response">The parsed response on success; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if the response parsed; otherwise <see langword="false"/>.</returns>
    internal static bool TryParse(string certificateStr, string? responseString, [NotNullWhen(true)] out SamlResponse? response)
        => TryParse(certificateStr, null, responseString, out response);

    /// <summary>
    /// Tries to parse a SAML response against the primary signing certificate OR an optional secondary
    /// certificate — the identity-provider verification-key overlap window (#491) — returning
    /// <see langword="false"/> (rather than throwing) on the malformed-input exceptions the
    /// <see cref="SamlResponse"/> constructor raises.
    /// </summary>
    /// <param name="certificateStr">The identity provider's primary signing certificate as a Base64 string.</param>
    /// <param name="secondaryCertificateStr">The optional secondary certificate (Base64), or blank for none.</param>
    /// <param name="responseString">The untrusted SAML response (Base64).</param>
    /// <param name="response">The parsed response on success; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if the response parsed; otherwise <see langword="false"/>.</returns>
    internal static bool TryParse(string certificateStr, string? secondaryCertificateStr, string? responseString, [NotNullWhen(true)] out SamlResponse? response)
    {
        // A null or empty body is the most common malformed callback (an absent SAMLResponse form field
        // yields a null string on the unauthenticated ACS endpoint); reject it here rather than let
        // Convert.FromBase64String(null) raise ArgumentNullException and escape as an unhandled 500.
        if (string.IsNullOrEmpty(responseString))
        {
            response = null;
            return false;
        }

        // Reject an oversized body before decoding/parsing it (#249) — fail closed, same clean rejection
        // as any other malformed response, with no crypto or allocation spent on the untrusted bulk.
        if (responseString.Length > MaxEncodedResponseLength)
        {
            response = null;
            return false;
        }

        try
        {
            response = new SamlResponse(certificateStr, secondaryCertificateStr, responseString);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or XmlException or CryptographicException or ArgumentException)
        {
            // FormatException/XmlException: a malformed response body (#199). CryptographicException/
            // ArgumentException: a null/garbage configured SamlCertificate (#206) — the save-time
            // validation blocks that, but a legacy or hand-edited config could still carry one, so fail
            // closed to a clean rejection here rather than an unhandled 500.
            response = null;
            return false;
        }
    }
}
