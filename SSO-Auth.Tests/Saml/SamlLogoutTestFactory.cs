// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Builds real, cryptographically-signed SAML 2.0 <c>LogoutRequest</c> documents (and deliberately broken
/// variants) against a throw-away self-signed certificate, so the SLO-3b tests exercise the actual
/// signature-validation path in <c>SamlLogoutRequest</c> rather than mocks — the LogoutRequest analogue of
/// <see cref="SamlTestFactory"/>.
/// </summary>
internal static class SamlLogoutTestFactory
{
    private const string TimeFormat = "yyyy-MM-ddTHH:mm:ssZ";

    /// <summary>
    /// Produces a self-signed certificate plus a signed LogoutRequest for the given subject/session indexes.
    /// </summary>
    /// <param name="nameId">The value placed in saml:NameID.</param>
    /// <param name="includeNameId">When false, the saml:NameID element is omitted entirely.</param>
    /// <param name="sessionIndexes">Zero or more samlp:SessionIndex values; null emits none.</param>
    /// <param name="notOnOrAfter">When set, emits the request's NotOnOrAfter attribute.</param>
    /// <param name="issuer">The saml:Issuer value.</param>
    /// <param name="requestId">The request ID attribute (defaults to a fresh one); reuse a fixed value for the replay test.</param>
    /// <param name="sign">When false, the request is left unsigned.</param>
    /// <param name="signWithSha1">When true, sign with RSA-SHA1/SHA1 digest (the weak-algorithm case).</param>
    /// <param name="wrapSignature">When true, sign a smuggled sibling element and move the (valid) signature to the root — the XML-signature-wrapping case.</param>
    /// <param name="signingKeyBits">RSA signing-key size in bits; defaults to 2048.</param>
    /// <returns>A fixture exposing the certificate and the signed document.</returns>
    internal static SamlLogoutFixture Create(
        string nameId = "alice",
        bool includeNameId = true,
        string[]? sessionIndexes = null,
        DateTime? notOnOrAfter = null,
        string issuer = "https://idp.example.com",
        string? requestId = null,
        bool sign = true,
        bool signWithSha1 = false,
        bool wrapSignature = false,
        int signingKeyBits = 2048)
    {
        var rootId = requestId ?? ("_" + Guid.NewGuid().ToString("N"));
        var issueInstant = DateTime.UtcNow.ToString(TimeFormat, CultureInfo.InvariantCulture);
        var notOnOrAfterAttr = notOnOrAfter == null
            ? string.Empty
            : " NotOnOrAfter=\"" + notOnOrAfter.Value.ToUniversalTime().ToString(TimeFormat, CultureInfo.InvariantCulture) + "\"";

        // The smuggled, separately-signed sibling used by the wrapping case: it carries its own ID so a
        // signature can reference it instead of the document root.
        const string EvilId = "_evil";
        var evil = wrapSignature
            ? "<samlp:Extensions ID=\"" + EvilId + "\"><saml:NameID>attacker</saml:NameID></samlp:Extensions>"
            : string.Empty;

        var sessionIndexElements = new StringBuilder();
        if (sessionIndexes != null)
        {
            foreach (var index in sessionIndexes)
            {
                sessionIndexElements.Append("<samlp:SessionIndex>" + SecurityElement.Escape(index) + "</samlp:SessionIndex>");
            }
        }

        var xml =
            "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + rootId + "\" Version=\"2.0\" IssueInstant=\"" + issueInstant + "\"" + notOnOrAfterAttr + ">" +
                "<saml:Issuer>" + SecurityElement.Escape(issuer) + "</saml:Issuer>" +
                evil +
                (includeNameId ? "<saml:NameID>" + SecurityElement.Escape(nameId) + "</saml:NameID>" : string.Empty) +
                sessionIndexElements +
            "</samlp:LogoutRequest>";

        using var rsa = RSA.Create(signingKeyBits);
        var request = new CertificateRequest("CN=Test SAML IdP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(xml);

        if (sign)
        {
            // Wrapping: sign the smuggled sibling (a cryptographically VALID signature), then move it to the
            // root so it sits at the position-bound location but its reference covers the sibling, not the
            // root — exactly the shape the reference-covers-root defense must reject.
            var referenceId = wrapSignature ? EvilId : rootId;
            SignElement(document, referenceId, rsa, certificate, signWithSha1, moveSignatureToRoot: wrapSignature);
        }

        return new SamlLogoutFixture(certificate, document, rootId);
    }

    /// <summary>Encodes an arbitrary XML string as a Base64 SAMLRequest (used for the DTD/malformed cases).</summary>
    /// <param name="xml">The raw XML.</param>
    /// <returns>The Base64 SAMLRequest.</returns>
    internal static string Encode(string xml) => Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));

    private static void SignElement(XmlDocument document, string referenceId, RSA signingKey, X509Certificate2 certificate, bool useSha1, bool moveSignatureToRoot)
    {
        var signedXml = new SignedXml(document) { SigningKey = signingKey };

        var reference = new Reference("#" + referenceId) { DigestMethod = useSha1 ? SignedXml.XmlDsigSHA1Url : SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = useSha1 ? SignedXml.XmlDsigRSASHA1Url : SignedXml.XmlDsigRSASHA256Url;

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();

        var signatureElement = signedXml.GetXml();
        // Normally the enveloped signature is appended inside the element it covers. For the wrapping case the
        // signature is instead appended to the document root, so it sits at the validator's position-bound
        // location while its reference points at the smuggled sibling.
        var target = moveSignatureToRoot
            ? document.DocumentElement!
            : (XmlElement)signedXml.GetIdElement(document, referenceId)!;
        target.AppendChild(document.ImportNode(signatureElement, true));
    }
}

/// <summary>A signed SAML LogoutRequest together with the certificate that signed it.</summary>
internal sealed class SamlLogoutFixture
{
    private readonly X509Certificate2 _certificate;

    internal SamlLogoutFixture(X509Certificate2 certificate, XmlDocument document, string requestId)
    {
        _certificate = certificate;
        Document = document;
        RequestId = requestId;
    }

    /// <summary>Gets the signed document (mutable, so tests can inject attacks).</summary>
    internal XmlDocument Document { get; }

    /// <summary>Gets the ID attribute of the root LogoutRequest element.</summary>
    internal string RequestId { get; }

    /// <summary>Gets the signing certificate exported as a Base64 DER string (the public part only).</summary>
    internal string CertificateBase64 => Convert.ToBase64String(_certificate.Export(X509ContentType.Cert));

    /// <summary>Encodes the current document as the Base64 SAMLRequest string the endpoint expects.</summary>
    internal string EncodeRequest() => SamlLogoutTestFactory.Encode(Document.OuterXml);
}
