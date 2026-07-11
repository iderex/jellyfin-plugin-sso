using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth;

/// <summary>
/// Allowlist of acceptable XML-DSig signature and digest algorithms for a SAML response. .NET's
/// <c>SignedXml.CheckSignature</c> still accepts SHA-1 (rsa-sha1 / xmldsig#sha1), a collision-weak
/// primitive, so a misconfigured or downgraded identity provider would otherwise be trusted. This
/// enforces RSA/ECDSA-SHA-256-or-stronger signatures and SHA-256-or-stronger digests, fail-closed.
/// </summary>
internal static class SamlSignatureAlgorithms
{
    private static readonly HashSet<string> AllowedSignatureMethods = new HashSet<string>(StringComparer.Ordinal)
    {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
    };

    private static readonly HashSet<string> AllowedDigestMethods = new HashSet<string>(StringComparer.Ordinal)
    {
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384",
        "http://www.w3.org/2001/04/xmlenc#sha512",
    };

    /// <summary>
    /// Whether the signature method and every reference digest method are on the allowlist.
    /// </summary>
    /// <param name="signatureMethod">The SignedInfo signature-method URI.</param>
    /// <param name="digestMethods">The digest-method URI of every reference.</param>
    /// <returns>True only if the signature method is allowed and there is at least one reference, all of whose digests are allowed.</returns>
    internal static bool IsAllowed(string signatureMethod, IEnumerable<string> digestMethods)
    {
        if (!AllowedSignatureMethods.Contains(signatureMethod ?? string.Empty))
        {
            return false;
        }

        if (digestMethods == null)
        {
            return false;
        }

        var any = false;
        foreach (var digest in digestMethods)
        {
            any = true;
            if (!AllowedDigestMethods.Contains(digest ?? string.Empty))
            {
                return false;
            }
        }

        return any;
    }
}
