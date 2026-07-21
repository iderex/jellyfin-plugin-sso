// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Parses and validates an inbound IdP-initiated SAML 2.0 <c>LogoutRequest</c> (#727, SLO-3b) — the
/// unauthenticated, session-destructive surface. It deliberately MIRRORS the signed-XML hardening of
/// <see cref="SamlResponse"/> (DTD-prohibited size-bounded parse, exactly-one enveloped signature whose
/// single reference covers the signed root, the RSA/ECDSA-SHA-256-or-stronger algorithm allowlist, the
/// candidate-certificate trial across the validity window) but against a different document: the signed
/// element is the <c>samlp:LogoutRequest</c> root itself (there is no assertion, no bearer confirmation,
/// no audience). It is a FOCUSED validator that reuses the shared primitives
/// (<see cref="SamlSignatureAlgorithms"/>, <see cref="SamlCertificate"/>, <see cref="SamlAssertionTime"/>)
/// rather than re-implementing the algorithm lists or certificate strength policy — a separate type from
/// <see cref="SamlResponse"/> so hardening the logout path cannot regress the heavily-tested login path.
/// </summary>
/// <remarks>
/// Fail-closed throughout: an unsigned, wrong-key, wrapped, weak-algorithm, malformed or DTD-bearing
/// request fails <see cref="IsValid"/> (or never parses). One-time-use (replay) and the feature gate live
/// in the orchestrating <see cref="SamlLogoutValidator"/> and the controller endpoint; this type is the
/// pure parse-plus-signature step and exposes only the validated NameID, the SessionIndex list, and the
/// request ID once <see cref="IsValid"/> has returned true.
/// </remarks>
internal sealed class SamlLogoutRequest : IDisposable
{
    // The only position an enveloped LogoutRequest signature may occupy: a direct child of the
    // LogoutRequest root. A relative //ds:Signature would also match a signature relocated into a wrapper,
    // so the XPath is anchored to the root — the LogoutRequest analogue of SamlResponse.SignatureXPath.
    private const string SignatureXPath = "/samlp:LogoutRequest/ds:Signature";

    /// <summary>The always-on ceiling (256 KB) on the Base64 SAMLRequest length, bounding the decode and DOM parse on the unauthenticated logout path before any signature is checked (mirrors <see cref="SamlResponseLoader.MaxEncodedResponseLength"/>).</summary>
    internal const int MaxEncodedRequestLength = 256 * 1024;

    private readonly List<X509Certificate2> _certificates;
    private readonly XmlDocument _xmlDoc;
    private readonly XmlNamespaceManager _xmlNameSpaceManager;

    private SamlLogoutRequest(List<X509Certificate2> certificates, XmlDocument xmlDoc)
    {
        _certificates = certificates;
        _xmlDoc = xmlDoc;
        _xmlNameSpaceManager = GetNamespaceManager();
    }

    /// <summary>
    /// Tries to parse an untrusted, Base64-encoded <c>LogoutRequest</c> against the provider's primary
    /// signing certificate OR an optional secondary certificate (the verification-key overlap window, #491),
    /// returning <see langword="false"/> (rather than throwing) on the malformed-input the parse raises —
    /// a non-base64 body, malformed XML, a prohibited DOCTYPE, or an unloadable configured certificate. The
    /// caller rejects a false the same fail-closed way it rejects a failed signature (a uniform 400).
    /// </summary>
    /// <param name="certificateStr">The identity provider's primary signing certificate as a Base64 string.</param>
    /// <param name="secondaryCertificateStr">The optional secondary certificate (Base64), or blank for none.</param>
    /// <param name="requestString">The untrusted <c>SAMLRequest</c> (Base64).</param>
    /// <param name="logoutRequest">The parsed request on success; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if the request parsed; otherwise <see langword="false"/>.</returns>
    internal static bool TryParse(string certificateStr, string? secondaryCertificateStr, string? requestString, [NotNullWhen(true)] out SamlLogoutRequest? logoutRequest)
    {
        logoutRequest = null;

        // A null/empty body is the most common malformed request (an absent SAMLRequest form field binds to
        // null); reject it here rather than let Convert.FromBase64String(null) throw and escape as a 500.
        if (string.IsNullOrEmpty(requestString))
        {
            return false;
        }

        // Reject an oversized body before decoding/parsing it — fail closed, no crypto or allocation spent on
        // untrusted bulk (mirrors SamlResponseLoader.MaxEncodedResponseLength on the unauthenticated path).
        if (requestString.Length > MaxEncodedRequestLength)
        {
            return false;
        }

        List<X509Certificate2>? certificates = null;
        try
        {
            certificates = LoadCandidateCertificates(certificateStr, secondaryCertificateStr);
            var xmlDoc = ParseRequestXml(requestString);
            logoutRequest = new SamlLogoutRequest(certificates, xmlDoc);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or XmlException or CryptographicException or ArgumentException)
        {
            // A malformed request body (FormatException/XmlException, incl. a prohibited DOCTYPE) or a
            // null/garbage configured certificate (CryptographicException/ArgumentException) fails closed to a
            // clean rejection here rather than an unhandled 500 — the same mapping SamlResponseLoader uses.
            if (certificates != null)
            {
                foreach (var certificate in certificates)
                {
                    certificate.Dispose();
                }
            }

            return false;
        }
    }

    /// <summary>
    /// Disposes the loaded identity-provider signing certificate(s): each <see cref="X509Certificate2"/>
    /// wraps an unmanaged key handle, and one instance is constructed per inbound logout request. Disposal
    /// must happen only AFTER the request is fully consumed (signature validation and every getter read),
    /// because the candidate-certificate trial uses these certificates.
    /// </summary>
    public void Dispose()
    {
        foreach (var certificate in _certificates)
        {
            certificate.Dispose();
        }
    }

    /// <summary>
    /// Checks whether the request is valid: a single enveloped signature, at the position-bound root
    /// location, whose one reference covers the LogoutRequest document root, whose algorithms are on the
    /// allowlist, that verifies against a candidate certificate — AND, when the request carries a
    /// <c>NotOnOrAfter</c>, that it has not expired (honoured when present, per SAML core §3.7). Fail-closed
    /// on any missing/malformed piece.
    /// </summary>
    /// <returns>Whether the LogoutRequest is signature- and time-valid.</returns>
    internal bool IsValid()
    {
        // Exactly one enveloped signature, at the position-bound root location only. Zero signatures (an
        // unsigned request) or a signature relocated anywhere else is rejected before any cryptographic work.
        var signatureNodes = _xmlDoc.SelectNodes(SignatureXPath, _xmlNameSpaceManager);
        if (signatureNodes == null || signatureNodes.Count != 1)
        {
            return false;
        }

        try
        {
            var signatureElement = (XmlElement)signatureNodes[0]!;
            var signedXml = new SignedXml(_xmlDoc);
            signedXml.LoadXml(signatureElement);

            if (!ValidateSignatureReference(signedXml, signatureElement)
                || !IsSignatureAlgorithmAllowed(signedXml)
                || !VerifiesAgainstCandidateCertificate(signedXml))
            {
                return false;
            }

            return IsWithinTimeBounds();
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException or XmlException)
        {
            // A malformed signature on this untrusted-input path is rejected as invalid rather than surfacing
            // as an unhandled 500 (fail closed) — the same exception set SamlResponse.IsValid catches.
            return false;
        }
    }

    /// <summary>Gets the request's <c>ID</c> attribute, used for one-time-use (replay) enforcement.</summary>
    /// <returns>The ID, or null when absent.</returns>
    internal string? GetRequestId()
    {
        var id = (_xmlDoc.SelectSingleNode("/samlp:LogoutRequest", _xmlNameSpaceManager) as XmlElement)?.GetAttribute("ID");
        return string.IsNullOrEmpty(id) ? null : id;
    }

    /// <summary>Gets the request's <c>saml:Issuer</c> value, or null when absent.</summary>
    /// <returns>The Issuer, or null when absent.</returns>
    internal string? GetIssuer()
    {
        var node = _xmlDoc.SelectSingleNode("/samlp:LogoutRequest/saml:Issuer", _xmlNameSpaceManager);
        var issuer = node?.InnerText;
        return string.IsNullOrEmpty(issuer) ? null : issuer;
    }

    /// <summary>
    /// Gets the subject <c>saml:NameID</c> the request names — the value matched (exact ordinal) against the
    /// captured login-time NameID to resolve which sessions to revoke. Direct child of the LogoutRequest root.
    /// </summary>
    /// <returns>The NameID, or null when absent.</returns>
    internal string? GetNameId()
    {
        var node = _xmlDoc.SelectSingleNode("/samlp:LogoutRequest/saml:NameID", _xmlNameSpaceManager);
        return node?.InnerText;
    }

    /// <summary>
    /// Gets the zero-or-more <c>samlp:SessionIndex</c> values the request carries. An empty list means the
    /// request names no specific session, so it targets every session of the subject (SAML core §3.7).
    /// </summary>
    /// <returns>The SessionIndex values in document order (possibly empty, never null).</returns>
    internal IReadOnlyList<string> GetSessionIndexes()
    {
        var output = new List<string>();
        var nodes = _xmlDoc.SelectNodes("/samlp:LogoutRequest/samlp:SessionIndex", _xmlNameSpaceManager);
        if (nodes == null)
        {
            return output;
        }

        foreach (XmlNode node in nodes)
        {
            var value = node?.InnerText;
            if (!string.IsNullOrEmpty(value))
            {
                output.Add(value);
            }
        }

        return output;
    }

    /// <summary>Gets the request's <c>NotOnOrAfter</c> as UTC, or null when the request declares none.</summary>
    /// <returns>The parsed UTC upper bound, or null when absent or unparseable.</returns>
    internal DateTime? GetNotOnOrAfter()
    {
        var raw = (_xmlDoc.SelectSingleNode("/samlp:LogoutRequest", _xmlNameSpaceManager) as XmlElement)?.GetAttribute("NotOnOrAfter");
        return !string.IsNullOrEmpty(raw) && SamlAssertionTime.TryParseUtc(raw, out var parsed) ? parsed : null;
    }

    // Loads the candidate identity-provider signing certificates: the primary always, the optional secondary
    // only when configured (#491). Identical policy to SamlResponse.LoadCandidateCertificates — both are the
    // IdP's PUBLIC signing certificate, and an unloadable value throws the same load exceptions TryParse maps.
    private static List<X509Certificate2> LoadCandidateCertificates(string certificateStr, string? secondaryCertificateStr)
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

    // Parses the untrusted, Base64-encoded LogoutRequest into a hardened XmlDocument. The DTD-prohibit /
    // PreserveWhitespace / null-resolver / size-cap hardening is IDENTICAL to SamlResponse.ParseResponseXml —
    // PreserveWhitespace is load-bearing for signature canonicalization, DtdProcessing.Prohibit blocks the
    // billion-laughs/XXE class, and MaxCharactersInDocument bounds the DOM on the pre-signature path.
    private static XmlDocument ParseRequestXml(string base64Request)
    {
        var xml = Encoding.UTF8.GetString(Convert.FromBase64String(base64Request));

        var xmlDoc = new XmlDocument
        {
            PreserveWhitespace = true,
            XmlResolver = null,
        };

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 256 * 1024,
        };
        using (var stringReader = new StringReader(xml))
        using (var reader = XmlReader.Create(stringReader, settings))
        {
            xmlDoc.Load(reader);
        }

        return xmlDoc;
    }

    // A single same-document reference is required, and it must cover the LogoutRequest document root — the
    // element whose NameID/SessionIndex/ID are actually read. .NET's CheckSignature validates the digest but
    // not WHAT is signed, so without this a signature over a smuggled sibling would pass (signature-wrapping).
    // The signature must additionally be enveloped inside the root it covers. Mirrors
    // SamlResponse.ValidateSignatureReference, narrowed to the single permitted covered element (the root).
    private bool ValidateSignatureReference(SignedXml signedXml, XmlElement signatureElement)
    {
        var signedInfo = signedXml.SignedInfo;
        if (signedInfo is null || signedInfo.References.Count != 1)
        {
            return false;
        }

        var reference = (Reference)signedInfo.References[0]!;

        // A same-document ID reference only ("#id"); an empty (whole-document "") or external URI is rejected.
        var referenceUri = reference.Uri;
        if (string.IsNullOrEmpty(referenceUri) || referenceUri[0] != '#')
        {
            return false;
        }

        var idElement = signedXml.GetIdElement(_xmlDoc, referenceUri.Substring(1));
        if (idElement == null || idElement != _xmlDoc.DocumentElement)
        {
            return false;
        }

        return IsEnvelopedWithin(signatureElement, idElement);
    }

    // Whether the signature element is a descendant of the element its reference covers (an enveloped
    // signature sits inside the element it signs). Identical to SamlResponse.IsEnvelopedWithin.
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

    // Rejects weak/legacy signature and digest algorithms (RSA-SHA1, SHA-1 digest) and any
    // canonicalization/transform outside the comment-free-C14N + enveloped-signature allowlist, by delegating
    // to the SHARED SamlSignatureAlgorithms allowlist — the SAME lists the login path enforces, never a copy.
    private static bool IsSignatureAlgorithmAllowed(SignedXml signedXml)
    {
        var signedInfo = signedXml.SignedInfo;
        if (signedInfo is null)
        {
            return false;
        }

        if (!SamlSignatureAlgorithms.IsCanonicalizationAllowed(signedInfo.CanonicalizationMethod ?? string.Empty))
        {
            return false;
        }

        var digestMethods = new List<string>();
        foreach (Reference reference in signedInfo.References)
        {
            var transforms = new List<string>();
            foreach (Transform transform in reference.TransformChain)
            {
                transforms.Add(transform.Algorithm ?? string.Empty);
            }

            if (!SamlSignatureAlgorithms.AreTransformsAllowed(transforms))
            {
                return false;
            }

            digestMethods.Add(reference.DigestMethod ?? string.Empty);
        }

        return SamlSignatureAlgorithms.IsAllowed(signedInfo.SignatureMethod ?? string.Empty, digestMethods);
    }

    // The signature must verify against at least one candidate certificate that is CURRENTLY within its
    // validity window and meets the shared signing-key strength floor. Only the cryptographic key trial spans
    // the primary and optional secondary; the reference/algorithm binding above runs cert-independently.
    // Delegates the strength floor to the SHARED SamlCertificate.HasAcceptableSigningKey — never a copy.
    private bool VerifiesAgainstCandidateCertificate(SignedXml signedXml)
    {
        var utcNow = DateTime.UtcNow;
        foreach (var certificate in _certificates)
        {
            if (SamlCertificate.HasAcceptableSigningKey(certificate)
                && IsWithinValidityPeriod(certificate, utcNow)
                && signedXml.CheckSignature(certificate, true))
            {
                return true;
            }
        }

        return false;
    }

    // Whether the certificate is within its own [NotBefore, NotAfter] window at verification time, with the
    // shared clock-skew tolerance on both edges. Identical to SamlResponse.IsWithinValidityPeriod.
    private static bool IsWithinValidityPeriod(X509Certificate2 certificate, DateTime utcNow)
    {
        return utcNow >= certificate.NotBefore.ToUniversalTime() - SamlAssertionTime.ClockSkew
            && utcNow <= certificate.NotAfter.ToUniversalTime() + SamlAssertionTime.ClockSkew;
    }

    // Time-bounding for a LogoutRequest: NotOnOrAfter is OPTIONAL (unlike an assertion, which must carry an
    // upper bound). When absent, the request is time-unbounded and accepted (replay one-time-use is the DoS
    // backstop). When present, it is honoured with the shared clock skew — a stale request is rejected.
    private bool IsWithinTimeBounds()
    {
        var raw = (_xmlDoc.SelectSingleNode("/samlp:LogoutRequest", _xmlNameSpaceManager) as XmlElement)?.GetAttribute("NotOnOrAfter");
        if (string.IsNullOrEmpty(raw))
        {
            return true;
        }

        if (!SamlAssertionTime.TryParseUtc(raw, out var notOnOrAfter))
        {
            // Present but unparseable -> fail closed, exactly as SamlAssertionTime treats a bad upper bound.
            return false;
        }

        // NotOnOrAfter is an exclusive upper bound; apply the skew to "now" so a small IdP/SP clock difference
        // does not spuriously reject an otherwise-valid request.
        return DateTime.UtcNow - SamlAssertionTime.ClockSkew < notOnOrAfter;
    }

    private XmlNamespaceManager GetNamespaceManager()
    {
        var manager = new XmlNamespaceManager(_xmlDoc.NameTable);
        manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
        manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

        return manager;
    }
}
