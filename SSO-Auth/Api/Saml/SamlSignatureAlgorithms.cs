using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

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

    // Only comment-free canonicalization is accepted, exclusive or inclusive. The "#WithComments"
    // variants are deliberately excluded: they preserve XML comments through canonicalization, which
    // breaks "sign what is seen" (content can differ from what was digested) — Microsoft flags them
    // for exactly this reason. These serve both as the SignedInfo CanonicalizationMethod and as the
    // canonicalization step allowed inside a reference's transform chain.
    private static readonly HashSet<string> AllowedCanonicalizationMethods = new HashSet<string>(StringComparer.Ordinal)
    {
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    };

    // A reference transform chain may contain only the enveloped-signature transform and comment-free
    // canonicalization. Anything else — XPath/XSLT filters, decryption, or comment-preserving c14n —
    // is rejected: those are the levers XML-signature-wrapping uses to make the digested bytes differ
    // from the element that is actually read.
    private static readonly HashSet<string> AllowedTransforms = new HashSet<string>(StringComparer.Ordinal)
    {
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    };

    /// <summary>
    /// Whether the SignedInfo canonicalization method is a comment-free exclusive/inclusive C14N.
    /// </summary>
    /// <param name="canonicalizationMethod">The SignedInfo canonicalization-method URI.</param>
    /// <returns>True only if the method is on the allowlist.</returns>
    internal static bool IsCanonicalizationAllowed(string canonicalizationMethod)
        => AllowedCanonicalizationMethods.Contains(canonicalizationMethod ?? string.Empty);

    /// <summary>
    /// Whether every transform in a reference's chain is on the allowlist (enveloped-signature or
    /// comment-free C14N), and there is at least one.
    /// </summary>
    /// <param name="transforms">The transform-algorithm URIs of one reference, in order.</param>
    /// <returns>True only if there is at least one transform and all are allowed.</returns>
    internal static bool AreTransformsAllowed(IEnumerable<string> transforms)
        => AllOnList(AllowedTransforms, transforms);

    /// <summary>
    /// Whether a signature-method URI is on the allowlist (RSA/ECDSA SHA-256 or stronger; no SHA-1).
    /// Shared by the inbound-response check below and the outgoing-request signer, so the SP never signs
    /// with an algorithm weaker than the one it demands of the identity provider.
    /// </summary>
    /// <param name="signatureMethod">The signature-method URI.</param>
    /// <returns>True only if the method is on the allowlist.</returns>
    internal static bool IsSignatureMethodAllowed(string signatureMethod)
        => AllowedSignatureMethods.Contains(signatureMethod ?? string.Empty);

    /// <summary>
    /// Whether the signature method and every reference digest method are on the allowlist.
    /// </summary>
    /// <param name="signatureMethod">The SignedInfo signature-method URI.</param>
    /// <param name="digestMethods">The digest-method URI of every reference.</param>
    /// <returns>True only if the signature method is allowed and there is at least one reference, all of whose digests are allowed.</returns>
    internal static bool IsAllowed(string signatureMethod, IEnumerable<string> digestMethods)
        => IsSignatureMethodAllowed(signatureMethod)
           && AllOnList(AllowedDigestMethods, digestMethods);

    // The fail-closed shape both the transform chain and the reference digests require: a non-null
    // enumerable with at least one element, every element on the allowlist. A null enumerable is
    // rejected, an empty chain is rejected (nothing was actually signed/canonicalized), and a null
    // element normalizes to string.Empty — never on any allowlist — so it is rejected too. Short-circuits
    // on the first off-list element. Defined once so the two call sites cannot drift apart (#395).
    private static bool AllOnList(HashSet<string> allow, IEnumerable<string> values)
    {
        if (values == null)
        {
            return false;
        }

        var any = false;
        foreach (var value in values)
        {
            any = true;
            if (!allow.Contains(value ?? string.Empty))
            {
                return false;
            }
        }

        return any;
    }
}
