using System;
using System.Security.Cryptography;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Safely constructs a <see cref="Response"/> from an untrusted SAML response string (#199). The
/// <see cref="Response"/> constructor throws on malformed input — <see cref="FormatException"/> for a
/// non-base64 body and <see cref="XmlException"/> for malformed XML or a prohibited DOCTYPE (the P2#9
/// XXE guard). Left unhandled, those surface to an unauthenticated caller as an HTTP 500 with a stack
/// trace; this maps them to a fail-closed <see langword="false"/> so the callback endpoints reject a
/// malformed response the same way they reject an invalid one — a clean 4xx.
/// </summary>
internal static class SamlResponseLoader
{
    /// <summary>
    /// Tries to parse a SAML response, returning <see langword="false"/> (rather than throwing) on the
    /// malformed-input exceptions the <see cref="Response"/> constructor raises.
    /// </summary>
    /// <param name="certificateStr">The identity provider's signing certificate as a Base64 string.</param>
    /// <param name="responseString">The untrusted SAML response (Base64).</param>
    /// <param name="response">The parsed response on success; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if the response parsed; otherwise <see langword="false"/>.</returns>
    internal static bool TryParse(string certificateStr, string responseString, out Response response)
    {
        // A null or empty body is the most common malformed callback (an absent SAMLResponse form field
        // yields a null string on the unauthenticated ACS endpoint); reject it here rather than let
        // Convert.FromBase64String(null) raise ArgumentNullException and escape as an unhandled 500.
        if (string.IsNullOrEmpty(responseString))
        {
            response = null;
            return false;
        }

        try
        {
            response = new Response(certificateStr, responseString);
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
