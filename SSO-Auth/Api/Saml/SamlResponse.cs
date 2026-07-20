/*
 Was Jitbit's simple SAML 2.0 component for ASP.NET
 https://github.com/jitbit/AspNetSaml/
 (c) Jitbit LP, 2016
 Use this freely under the Apache license (see https://choosealicense.com/licenses/apache-2.0/)
 version 1.2.3
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Represents a SAML response.
/// </summary>
internal sealed class SamlResponse : IDisposable
{
    // The only positions an enveloped SAML signature may occupy: a direct child of the Response or
    // of the Assertion. Encodes the security-critical "no relocated signature" invariant, so it is a
    // single constant shared by the validator and the diagnostic getter (they must never diverge).
    private const string SignatureXPath =
        "/samlp:Response/ds:Signature | /samlp:Response/saml:Assertion/ds:Signature";

    // The bearer SubjectConfirmationData required by the SAML 2.0 Web Browser SSO profile: the data
    // element under a SubjectConfirmation whose Method is the bearer URN. Every SubjectConfirmationData
    // read is scoped to it so a non-bearer confirmation (e.g. holder-of-key, which the profile pairs with
    // a key-possession proof this SP does not verify) is never consumed as if it were the bearer token
    // (#238). Kept as one constant shared by IsValid's presence check and every reader so they cannot
    // diverge.
    private const string BearerSubjectConfirmationDataXPath =
        "/samlp:Response/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation[@Method='urn:oasis:names:tc:SAML:2.0:cm:bearer']/saml:SubjectConfirmationData";

    private readonly List<X509Certificate2> _certificates;
    private readonly XmlDocument _xmlDoc;
    private readonly XmlNamespaceManager _xmlNameSpaceManager; // we need this one to run our XPath queries on the SAML XML

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlResponse"/> class, verifying against a single
    /// identity-provider signing certificate.
    /// </summary>
    /// <param name="certificateStr">The certificate formatted as a Base64 string.</param>
    /// <param name="responseString">The SAML response formatted as a string.</param>
    public SamlResponse(string certificateStr, string responseString)
        : this(certificateStr, null, responseString)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlResponse"/> class, verifying against the primary
    /// signing certificate OR an optional secondary certificate — the identity-provider verification-key
    /// overlap window (#491). The response is accepted when its signature verifies against EITHER
    /// certificate under the same fail-closed checks; a blank secondary is byte-for-byte the primary-only
    /// behavior.
    /// </summary>
    /// <param name="certificateStr">The primary certificate formatted as a Base64 string.</param>
    /// <param name="secondaryCertificateStr">The optional secondary certificate (Base64), or blank for none.</param>
    /// <param name="responseString">The SAML response formatted as a string.</param>
    public SamlResponse(string certificateStr, string secondaryCertificateStr, string responseString)
    {
        // Decode and load the certificate(s), then parse the response — in that exact order, so the
        // exception sequence SamlResponseLoader.TryParse catches is unchanged: FormatException (bad
        // certificate base64), CryptographicException (bad certificate), then FormatException/XmlException
        // (bad body). The XML is loaded here, at construction, and the fields are readonly: a validated
        // response object can never have different XML swapped into it afterwards (#396).
        _certificates = LoadCandidateCertificates(certificateStr, secondaryCertificateStr);
        _xmlDoc = ParseResponseXml(responseString);
        _xmlNameSpaceManager = GetNamespaceManager(); // lets construct a "manager" for XPath queries
    }

    /// <summary>
    /// Gets the SAML response's XML data.
    /// </summary>
    public string Xml => _xmlDoc.OuterXml;

    /// <summary>
    /// Disposes the loaded identity-provider signing certificate(s) (#674). Each
    /// <see cref="X509Certificate2"/> wraps an unmanaged key handle, and one <see cref="SamlResponse"/> is
    /// constructed per inbound assertion-consumer callback, so without this every request leaked a handle.
    /// The certificates are the only unmanaged resource this type owns: <see cref="XmlDocument"/> holds only
    /// managed state (it is not itself IDisposable) and the parse-time <see cref="System.Xml.XmlReader"/> /
    /// <see cref="StringReader"/> are already disposed inside <see cref="ParseResponseXml"/>. Disposal must
    /// therefore happen only AFTER the response is fully consumed (signature validation and every claim
    /// read), because <see cref="VerifiesAgainstCandidateCertificate"/> uses these certificates — the owning
    /// callers scope it to the point where the assertion has been read in full.
    /// </summary>
    public void Dispose()
    {
        foreach (var certificate in _certificates)
        {
            certificate.Dispose();
        }
    }

    // Loads the candidate identity-provider signing certificates: the primary always, and the optional
    // secondary only when configured (#491). The primary is loaded FIRST so the constructor's exception
    // ordering — and therefore the fail-closed mapping in SamlResponseLoader.TryParse — is unchanged. Both
    // are the identity provider's PUBLIC signing certificate; a configured-but-unloadable secondary throws
    // the same load exceptions as the primary and is rejected the same fail-closed way (the admin write
    // paths reject it up front via SamlCertificate.IsInvalid).
    private static List<X509Certificate2> LoadCandidateCertificates(string certificateStr, string secondaryCertificateStr)
    {
        var certificates = new List<X509Certificate2>
        {
            X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificateStr)),
        };

        if (!string.IsNullOrWhiteSpace(secondaryCertificateStr))
        {
            certificates.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(secondaryCertificateStr)));
        }

        return certificates;
    }

    // Parses the untrusted, Base64-encoded SAML response into a hardened XmlDocument. The body base64
    // decode runs after the certificate load (preserving the constructor's exception ordering), and the
    // DTD-prohibit / PreserveWhitespace / null-resolver hardening is applied here.
    private static XmlDocument ParseResponseXml(string base64Response)
    {
        var xml = Encoding.UTF8.GetString(Convert.FromBase64String(base64Response));

        // PreserveWhitespace is load-bearing for XML signature validation (canonicalization depends
        // on the exact whitespace), so it must stay true.
        var xmlDoc = new XmlDocument
        {
            PreserveWhitespace = true,
            XmlResolver = null,
        };

        // The SAML response is untrusted input. Reject any DTD/DOCTYPE outright: XmlResolver=null
        // alone blocks only EXTERNAL entities (XXE/SSRF), while an internal DTD still expands
        // entities (a billion-laughs style denial of service). DtdProcessing.Prohibit makes the
        // reader throw on a DOCTYPE, which is the fail-closed posture; a well-formed SAML assertion
        // never carries one.
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,

            // Bound the DOM the reader materializes (#754). The untrusted body is already length-capped
            // before decoding by SamlResponseLoader.MaxEncodedResponseLength (256 KB of base64), so this
            // parser-layer cap normally never bites — a legitimate SAML response is single-digit KB, and
            // the pre-decode cap keeps any accepted body well under this. It is the belt to the loader's
            // suspenders: if that pre-decode cap were ever raised or bypassed, the reader still refuses to
            // build a multi-megabyte document on the unauthenticated, pre-signature path (a cheap CPU/
            // memory amplifier the DTD prohibition above does not stop, since it bounds entities, not bulk).
            MaxCharactersInDocument = 256 * 1024,
        };
        using (var stringReader = new StringReader(xml))
        using (var reader = XmlReader.Create(stringReader, settings))
        {
            xmlDoc.Load(reader);
        }

        return xmlDoc;
    }

    /// <summary>
    /// Checks whether the XML response is valid by verifying the signature.
    /// </summary>
    /// <returns>Whether the XML response is valid.</returns>
    public bool IsValid()
    {
        // Exactly one assertion must be present (fail closed). Every claim reader consumes the
        // Response's direct-child Assertion[1], so a response carrying a second such assertion — the
        // SAML assertion-injection / XML-signature-wrapping class — is rejected before any reader can
        // be pointed at attacker-controlled content. The count is scoped to direct children (the
        // nodes the readers can actually select): a spec-legal supporting assertion nested in
        // saml:Advice is not miscounted, and wrapping is independently blocked by the position-bound
        // signature selection, the enveloped-within check, and the reference-covers-{root|assertion}
        // check below.
        if (_xmlDoc.SelectNodes("/samlp:Response/saml:Assertion", _xmlNameSpaceManager)?.Count != 1)
        {
            return false;
        }

        // Select the signature only at a legal, position-bound location: an enveloped SAML signature
        // is a direct child of the Response or of the Assertion. A relative //ds:Signature would also
        // match a signature relocated into a wrapper or a Signature/Object, so the XPath is anchored.
        var signatureNodes = _xmlDoc.SelectNodes(SignatureXPath, _xmlNameSpaceManager);
        if (signatureNodes == null || signatureNodes.Count == 0)
        {
            return false;
        }

        try
        {
            // EVERY position-bound signature must independently validate — its reference must cover the
            // Response root or the single Assertion, its algorithms must be allowed, and it must verify
            // against a pinned certificate (#238). The Web Browser SSO profile permits signing the
            // Response, the Assertion, or BOTH; validating all of them (rather than only the first in
            // document order) removes the "which signature is authoritative" ambiguity without rejecting
            // a conformant IdP that signs both — a second, non-verifying signature rejects the whole
            // response, so an attacker cannot slip a decoy alongside a valid one.
            foreach (XmlElement signatureElement in signatureNodes)
            {
                var signedXml = new SignedXml(_xmlDoc);
                signedXml.LoadXml(signatureElement);

                if (!ValidateSignatureReference(signedXml, signatureElement)
                    || !IsSignatureAlgorithmAllowed(signedXml)
                    || !VerifiesAgainstCandidateCertificate(signedXml))
                {
                    return false;
                }
            }

            return IsWithinTimeBounds() && HasBearerSubjectConfirmation();
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException or XmlException)
        {
            // A malformed signature on this untrusted-input path is rejected as invalid rather than
            // surfacing as an unhandled 500 (fail closed). SignedXml.LoadXml / CheckSignature throw
            // these on, e.g., a duplicate reference ID (CryptographicException) or a "#"-only /
            // non-NCName reference fragment (ArgumentException); catching them here keeps the whole
            // signature path fail-closed without swallowing unrelated errors.
            return false;
        }
    }

    // Reject weak/legacy signature and digest algorithms (e.g. RSA-SHA1, SHA-1 digest) and any
    // canonicalization/transform outside the comment-free-C14N + enveloped-signature allowlist,
    // before the cryptographic check, so a misconfigured or downgraded identity provider — or a
    // wrapping attack leaning on a comment-preserving or filtering transform — is not trusted.
    // Runs after ValidateSignatureReference, which guarantees exactly one reference exists.
    private static bool IsSignatureAlgorithmAllowed(SignedXml signedXml)
    {
        if (!SamlSignatureAlgorithms.IsCanonicalizationAllowed(signedXml.SignedInfo.CanonicalizationMethod))
        {
            return false;
        }

        var digestMethods = new List<string>();
        foreach (Reference reference in signedXml.SignedInfo.References)
        {
            var transforms = new List<string>();
            foreach (Transform transform in reference.TransformChain)
            {
                transforms.Add(transform.Algorithm);
            }

            if (!SamlSignatureAlgorithms.AreTransformsAllowed(transforms))
            {
                return false;
            }

            digestMethods.Add(reference.DigestMethod);
        }

        return SamlSignatureAlgorithms.IsAllowed(signedXml.SignedInfo.SignatureMethod, digestMethods);
    }

    // The signature must verify against at least one candidate certificate that is CURRENTLY within its
    // validity window (#491). Only the cryptographic key trial spans the primary and the optional
    // secondary certificate; the position-bound signature selection, the single-reference /
    // reference-covers-{root|assertion} / enveloped-within binding, and the algorithm allowlist all run
    // once per signature ABOVE this, cert-independently — so trying a second certificate cannot relax any
    // of them or open a wrapping/downgrade path, it only decides which key's signature is accepted. An
    // expired (or not-yet-valid) candidate is skipped rather than trusted, so a signing key the identity
    // provider has rolled away from can no longer authenticate even while it is still configured for the
    // overlap window.
    private bool VerifiesAgainstCandidateCertificate(SignedXml signedXml)
    {
        var utcNow = DateTime.UtcNow;
        foreach (var certificate in _certificates)
        {
            if (IsWithinValidityPeriod(certificate, utcNow) && signedXml.CheckSignature(certificate, true))
            {
                return true;
            }
        }

        return false;
    }

    // Whether the certificate is within its own [NotBefore, NotAfter] validity window at verification
    // time. SignedXml.CheckSignature(cert, verifySignatureOnly: true) validates only the cryptography and
    // does NOT itself check the certificate dates, so this is the single place the window is enforced — an
    // expired or not-yet-valid certificate is fail-closed rejected (#491). NotBefore/NotAfter are exposed
    // as local time, so both sides are compared in UTC. The same clock-skew tolerance every other time
    // bound on this path uses (SamlAssertionTime.ClockSkew) is applied to both edges, so a small IdP/SP
    // clock difference at a cutover — the moment a freshly staged certificate's NotBefore is a few minutes
    // ahead of this server — does not spuriously reject an otherwise-valid signature.
    private static bool IsWithinValidityPeriod(X509Certificate2 certificate, DateTime utcNow)
    {
        return utcNow >= certificate.NotBefore.ToUniversalTime() - SamlAssertionTime.ClockSkew
            && utcNow <= certificate.NotAfter.ToUniversalTime() + SamlAssertionTime.ClockSkew;
    }

    /// <summary>
    /// Checks whether the response is valid AND asserts it was issued for this service provider by
    /// requiring the signed assertion's AudienceRestriction to name <paramref name="expectedAudience"/>.
    /// Fail-closed: with no expected audience configured, or no matching Audience present, it is invalid.
    /// </summary>
    /// <param name="expectedAudience">The audience (SP entity id) this response must be addressed to.</param>
    /// <returns>Whether the response is valid and bound to this audience.</returns>
    public bool IsValid(string expectedAudience)
    {
        if (!IsValid())
        {
            return false;
        }

        // Trim and fail closed on an empty expected audience, so a caller passing a padded value
        // (e.g. " https://sp ") still matches the trimmed audiences read from the assertion.
        expectedAudience = expectedAudience?.Trim();
        if (string.IsNullOrEmpty(expectedAudience))
        {
            return false;
        }

        return IsAddressedTo(expectedAudience);
    }

    /// <summary>
    /// Gets the signature-method algorithm URI declared in the response's XML signature, or null when
    /// the response carries no signature. Diagnostic only (e.g. to explain a rejected weak algorithm in
    /// a log); it is never a substitute for <see cref="IsValid()"/>.
    /// </summary>
    /// <returns>The SignedInfo signature-method URI, or null if unsigned.</returns>
    public string GetSignatureAlgorithm()
    {
        // Same position-bound selection as IsValid, so the diagnostic reflects the signature that
        // would actually be validated rather than any signature found anywhere in the document.
        var nodeList = _xmlDoc.SelectNodes(SignatureXPath, _xmlNameSpaceManager);
        if (nodeList == null || nodeList.Count == 0)
        {
            return null;
        }

        // This is a diagnostic used only in the failure-log path, so it must never throw: a malformed
        // signature element makes SignedXml.LoadXml raise CryptographicException, which would turn the
        // clean rejection its caller is about to return into an unhandled HTTP 500 (#199). Return null
        // (unknown algorithm) on any malformed-signature exception instead.
        try
        {
            var signedXml = new SignedXml(_xmlDoc);
            signedXml.LoadXml((XmlElement)nodeList[0]);
            return signedXml.SignedInfo.SignatureMethod;
        }
        catch (Exception ex) when (ex is CryptographicException or XmlException or ArgumentException or FormatException)
        {
            return null;
        }
    }

    // Whether the assertion is addressed to us: SAML 2.0 requires the SP to appear in EVERY
    // <AudienceRestriction> (AND across restrictions, OR within one). Accepting on a match in ANY single
    // restriction (the old .Any over the flattened union) would honor an assertion whose first restriction
    // names a different SP and whose second names us — one not strictly addressed to this service provider
    // (#238). Fail closed on no restriction at all: an assertion carrying no AudienceRestriction is not
    // addressed to anyone in particular and must not pass the audience check.
    private bool IsAddressedTo(string expectedAudience)
    {
        var restrictions = _xmlDoc.SelectNodes("/samlp:Response/saml:Assertion[1]/saml:Conditions/saml:AudienceRestriction", _xmlNameSpaceManager);
        if (restrictions == null || restrictions.Count == 0)
        {
            return false;
        }

        foreach (XmlNode restriction in restrictions)
        {
            var audiences = restriction.SelectNodes("saml:Audience", _xmlNameSpaceManager);
            // Trim so a pretty-printed assertion (indentation/newlines around the value) still compares
            // equal; the assertion is signed, so trimming does not weaken the check.
            var present = audiences != null && audiences.Cast<XmlNode>()
                .Any(node => string.Equals(node?.InnerText?.Trim(), expectedAudience, StringComparison.Ordinal));
            if (!present)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Gets the ID attribute of the assertion, used to enforce one-time use (replay protection).
    /// </summary>
    /// <returns>The assertion ID, or null when absent.</returns>
    public string GetAssertionId()
    {
        var assertion = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]", _xmlNameSpaceManager) as XmlElement;
        var id = assertion?.GetAttribute("ID");
        return string.IsNullOrEmpty(id) ? null : id;
    }

    /// <summary>
    /// Gets the latest NotOnOrAfter across the assertion's Conditions and bearer SubjectConfirmationData,
    /// in UTC. Callers use it to retain a consumed assertion for replay protection for the whole time it
    /// would still be accepted.
    /// </summary>
    /// <returns>The latest NotOnOrAfter, or null when neither window carries one.</returns>
    public DateTime? GetNotOnOrAfter()
    {
        DateTime? latest = null;
        var xpaths = new[]
        {
            "/samlp:Response/saml:Assertion[1]/saml:Conditions",
            BearerSubjectConfirmationDataXPath,
        };

        foreach (var xpath in xpaths)
        {
            var value = (_xmlDoc.SelectSingleNode(xpath, _xmlNameSpaceManager) as XmlElement)?.GetAttribute("NotOnOrAfter");
            if (!string.IsNullOrEmpty(value) && SamlAssertionTime.TryParseUtc(value, out var parsed) && (latest == null || parsed > latest.Value))
            {
                latest = parsed;
            }
        }

        return latest;
    }

    // A single same-document reference is required, and it must cover the element whose content is
    // actually read: the Response root or the (single) Assertion. .NET's CheckSignature validates the
    // digest but not WHAT is signed, so without this a signature over an unrelated node would pass.
    // The signature must additionally be enveloped inside the element its reference covers — a
    // signature relocated outside it (a wrapping/relocation attack) is rejected even if its digest
    // still matches the copied element elsewhere in the tree.
    private bool ValidateSignatureReference(SignedXml signedXml, XmlElement signatureElement)
    {
        if (signedXml.SignedInfo.References.Count != 1) // exactly one reference, no more, no less
        {
            return false;
        }

        var reference = (Reference)signedXml.SignedInfo.References[0];

        // A same-document ID reference only ("#id"); an empty (whole-document "") or external URI is
        // rejected. A "#"-only or non-NCName fragment never reaches here — SignedXml.LoadXml resolves
        // the reference eagerly and throws on it, which IsValid catches and turns into a rejection.
        if (string.IsNullOrEmpty(reference.Uri) || reference.Uri[0] != '#')
        {
            return false;
        }

        var idElement = signedXml.GetIdElement(_xmlDoc, reference.Uri.Substring(1));
        if (idElement == null)
        {
            return false;
        }

        var assertionNode = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion", _xmlNameSpaceManager) as XmlElement;
        if (idElement != _xmlDoc.DocumentElement && idElement != assertionNode)
        {
            return false;
        }

        return IsEnvelopedWithin(signatureElement, idElement);
    }

    // Whether the signature element is a descendant of the element its reference covers (an enveloped
    // signature sits inside the element it signs). Rejects a signature moved outside that element.
    private static bool IsEnvelopedWithin(XmlElement signatureElement, XmlElement signedElement)
    {
        for (var parent = signatureElement.ParentNode; parent != null; parent = parent.ParentNode)
        {
            if (parent == signedElement)
            {
                return true;
            }
        }

        return false;
    }

    // Fail-closed time-bound validation: an assertion is accepted only if it carries at least one
    // parseable upper bound (NotOnOrAfter) and every present bound holds, within a small clock skew.
    // A missing or unparseable upper bound is a rejection, not an accept-forever (the old behavior).
    private bool IsWithinTimeBounds()
    {
        var subjectConfirmationData = _xmlDoc.SelectSingleNode(BearerSubjectConfirmationDataXPath, _xmlNameSpaceManager);
        var conditions = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:Conditions", _xmlNameSpaceManager);

        return SamlAssertionTime.IsWithinValidity(
            subjectConfirmationData?.Attributes?["NotOnOrAfter"]?.Value,
            conditions?.Attributes?["NotBefore"]?.Value,
            conditions?.Attributes?["NotOnOrAfter"]?.Value,
            DateTime.UtcNow,
            SamlAssertionTime.ClockSkew);
    }

    // The Web Browser SSO profile is a bearer profile: the (signed) assertion must carry a bearer
    // SubjectConfirmation with its confirmation data. Asserting its presence — after the signature is
    // verified — rejects an assertion that offers only a non-bearer confirmation (e.g. holder-of-key),
    // which would otherwise be consumed with no key-possession proof (#238).
    private bool HasBearerSubjectConfirmation()
    {
        return _xmlDoc.SelectSingleNode(BearerSubjectConfirmationDataXPath, _xmlNameSpaceManager) != null;
    }

    /// <summary>
    /// Gets the name ID attribute from the XML response.
    /// </summary>
    /// <returns>The name ID attribute, or null when the assertion carries no NameID (the caller
    /// rejects such a login; previously this threw and surfaced as a 500).</returns>
    public string GetNameID()
    {
        var node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:Subject/saml:NameID", _xmlNameSpaceManager);
        return node?.InnerText;
    }

    /// <summary>
    /// Gets the bearer SubjectConfirmationData's Recipient — the assertion-consumer URL the identity
    /// provider minted this assertion for. It lives inside the assertion, so it is covered by the
    /// signature regardless of whether the whole Response or only the Assertion is signed. The caller
    /// binds it to this service provider's own ACS URL (#156).
    /// </summary>
    /// <returns>The Recipient attribute, or null when absent.</returns>
    public string GetRecipient()
    {
        var node = _xmlDoc.SelectSingleNode(BearerSubjectConfirmationDataXPath, _xmlNameSpaceManager) as XmlElement;
        var recipient = node?.GetAttribute("Recipient");
        return string.IsNullOrEmpty(recipient) ? null : recipient;
    }

    /// <summary>
    /// Gets the bearer SubjectConfirmationData's InResponseTo — the ID of the AuthnRequest this
    /// assertion answers. Signed (inside the assertion), so the caller can trust it to correlate the
    /// response against a request this service provider actually issued (#156). Absent on an
    /// IdP-initiated (unsolicited) response.
    /// </summary>
    /// <returns>The InResponseTo attribute, or null when absent.</returns>
    public string GetInResponseTo()
    {
        var node = _xmlDoc.SelectSingleNode(BearerSubjectConfirmationDataXPath, _xmlNameSpaceManager) as XmlElement;
        var inResponseTo = node?.GetAttribute("InResponseTo");
        return string.IsNullOrEmpty(inResponseTo) ? null : inResponseTo;
    }

    /// <summary>
    /// Gets the Response element's Destination — the endpoint the identity provider sent this response
    /// to. Response-level, so it is only signature-covered when the whole Response (not merely the
    /// Assertion) is signed; the caller therefore treats it as a defense-in-depth check on top of the
    /// always-signed <see cref="GetRecipient"/> (#156).
    /// </summary>
    /// <returns>The Destination attribute, or null when absent.</returns>
    public string GetDestination()
    {
        var node = _xmlDoc.SelectSingleNode("/samlp:Response", _xmlNameSpaceManager) as XmlElement;
        var destination = node?.GetAttribute("Destination");
        return string.IsNullOrEmpty(destination) ? null : destination;
    }

    /// <summary>
    /// Gets the values for a custom attribute from the XML response.
    /// </summary>
    /// <param name="attr">The custom attribute to query.</param>
    /// <returns>The custom attributes.</returns>
    public List<string> GetCustomAttributes(string attr)
    {
        // Select the Attribute nodes with a CONSTANT XPath and compare @Name in C# (exact ordinal), rather
        // than interpolating attr into a quoted XPath literal (#678). An attr carrying an apostrophe or a
        // "'] | //*['"-style payload would otherwise break out of the '...' predicate and select arbitrary
        // nodes — classic XPath injection. Every production caller passes the constant "Role", so the result
        // set for that case is byte-for-byte the previous behavior (same nodes, same document order); the
        // rewrite only removes the injection surface the public signature exposes for any other input.
        var output = new List<string>();
        var attributes = _xmlDoc.SelectNodes("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute", _xmlNameSpaceManager);
        if (attributes == null)
        {
            return output;
        }

        foreach (XmlNode attribute in attributes)
        {
            if (!string.Equals((attribute as XmlElement)?.GetAttribute("Name"), attr, StringComparison.Ordinal))
            {
                continue;
            }

            var values = attribute.SelectNodes("saml:AttributeValue", _xmlNameSpaceManager);
            if (values == null)
            {
                continue;
            }

            foreach (XmlNode value in values)
            {
                output.Add(value?.InnerText);
            }
        }

        return output;
    }

    // returns namespace manager, we need one b/c MS says so... Otherwise XPath doesnt work in an XML doc with namespaces
    // see https://stackoverflow.com/questions/7178111/why-is-xmlnamespacemanager-necessary
    private XmlNamespaceManager GetNamespaceManager()
    {
        var manager = new XmlNamespaceManager(_xmlDoc.NameTable);
        manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
        manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

        return manager;
    }
}
