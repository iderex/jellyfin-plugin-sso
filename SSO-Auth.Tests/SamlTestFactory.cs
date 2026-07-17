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
/// Builds real, cryptographically-signed SAML 2.0 responses (and deliberately broken variants)
/// against a throw-away self-signed certificate, so tests exercise the actual signature-validation
/// path in <see cref="Jellyfin.Plugin.SSO_Auth.SamlResponse"/> rather than mocks.
///
/// Scoped to what the current <see cref="Jellyfin.Plugin.SSO_Auth.SamlResponse"/> validates
/// (signature, signature scope, SubjectConfirmationData/@NotOnOrAfter). It grows as the
/// validation surface is hardened (audience, recipient, InResponseTo, ... — see docs/ROADMAP.md).
/// </summary>
internal static class SamlTestFactory
{
    /// <summary>Which element the enveloped signature covers.</summary>
    internal enum SignatureScope
    {
        /// <summary>Sign the root samlp:Response element.</summary>
        Response,

        /// <summary>Sign only the saml:Assertion element.</summary>
        Assertion,
    }

    /// <summary>
    /// Produces a self-signed certificate plus a signed SAML response for the given subject/role.
    /// </summary>
    /// <param name="nameId">The value placed in saml:NameID.</param>
    /// <param name="includeNameId">When false, the saml:NameID element is omitted entirely.</param>
    /// <param name="role">The value of the "Role" attribute.</param>
    /// <param name="notOnOrAfter">SubjectConfirmationData/@NotOnOrAfter; defaults to five minutes in the future.</param>
    /// <param name="includeNotOnOrAfter">When false, the NotOnOrAfter attribute is omitted entirely.</param>
    /// <param name="conditionsNotBefore">When set, emits a Conditions element carrying this NotBefore.</param>
    /// <param name="conditionsNotOnOrAfter">When set, emits a Conditions element carrying this NotOnOrAfter.</param>
    /// <param name="audience">When set, emits a Conditions/AudienceRestriction with this single Audience.</param>
    /// <param name="audiences">When set, emits a Conditions/AudienceRestriction with these Audiences (overrides audience).</param>
    /// <param name="scope">Which element to sign.</param>
    /// <param name="signWithSha1">When true, sign with RSA-SHA1/SHA1 digest (for weak-algorithm tests).</param>
    /// <returns>A fixture exposing the certificate and the signed document.</returns>
    internal static SamlFixture Create(
        string nameId = "alice",
        bool includeNameId = true,
        string role = "jellyfin-users",
        DateTime? notOnOrAfter = null,
        bool includeNotOnOrAfter = true,
        DateTime? conditionsNotBefore = null,
        DateTime? conditionsNotOnOrAfter = null,
        string? audience = null,
        string[]? audiences = null,
        SignatureScope scope = SignatureScope.Response,
        bool signWithSha1 = false,
        bool signWithCommentsC14n = false,
        bool signWithInclusiveC14n = false,
        bool includeAdviceAssertion = false,
        string? recipient = null,
        string? inResponseTo = null,
        string? destination = null,
        string? subjectConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer",
        string[][]? audienceRestrictions = null)
    {
        var audienceList = audiences ?? (audience == null ? null : new[] { audience });
        const string TimeFormat = "yyyy-MM-ddTHH:mm:ssZ";
        var effectiveNotOnOrAfter = notOnOrAfter ?? DateTime.UtcNow.AddMinutes(5);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test SAML IdP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        var responseId = "_" + Guid.NewGuid().ToString("N");
        var assertionId = "_" + Guid.NewGuid().ToString("N");

        var subjectConfirmationAttributes = new StringBuilder();
        if (includeNotOnOrAfter)
        {
            subjectConfirmationAttributes.Append(" NotOnOrAfter=\"" + effectiveNotOnOrAfter.ToUniversalTime().ToString(TimeFormat, CultureInfo.InvariantCulture) + "\"");
        }

        if (recipient != null)
        {
            subjectConfirmationAttributes.Append(" Recipient=\"" + SecurityElement.Escape(recipient) + "\"");
        }

        if (inResponseTo != null)
        {
            subjectConfirmationAttributes.Append(" InResponseTo=\"" + SecurityElement.Escape(inResponseTo) + "\"");
        }

        var subjectConfirmationData = "<saml:SubjectConfirmationData" + subjectConfirmationAttributes + " />";

        // One <AudienceRestriction> per inner array when audienceRestrictions is set (for the multi-block
        // AND tests), else a single restriction from audienceList as before.
        var restrictionBlocks = new StringBuilder();
        var effectiveRestrictions = audienceRestrictions ?? (audienceList == null ? null : new[] { audienceList });
        if (effectiveRestrictions != null)
        {
            foreach (var block in effectiveRestrictions)
            {
                var audienceElements = new StringBuilder();
                foreach (var a in block)
                {
                    audienceElements.Append("<saml:Audience>" + a + "</saml:Audience>");
                }

                restrictionBlocks.Append("<saml:AudienceRestriction>" + audienceElements + "</saml:AudienceRestriction>");
            }
        }

        var conditions = string.Empty;
        if (conditionsNotBefore.HasValue || conditionsNotOnOrAfter.HasValue || restrictionBlocks.Length > 0)
        {
            var attributes = new StringBuilder();
            if (conditionsNotBefore.HasValue)
            {
                attributes.Append(" NotBefore=\"" + conditionsNotBefore.Value.ToUniversalTime().ToString(TimeFormat, CultureInfo.InvariantCulture) + "\"");
            }

            if (conditionsNotOnOrAfter.HasValue)
            {
                attributes.Append(" NotOnOrAfter=\"" + conditionsNotOnOrAfter.Value.ToUniversalTime().ToString(TimeFormat, CultureInfo.InvariantCulture) + "\"");
            }

            conditions = restrictionBlocks.Length == 0
                ? "<saml:Conditions" + attributes + " />"
                : "<saml:Conditions" + attributes + ">" + restrictionBlocks + "</saml:Conditions>";
        }

        var destinationAttribute = destination == null ? string.Empty : " Destination=\"" + SecurityElement.Escape(destination) + "\"";

        // A spec-legal supporting assertion nested inside saml:Advice, part of the signed content.
        // It must NOT be miscounted as a second top-level assertion by the single-assertion check.
        var advice = includeAdviceAssertion
            ? "<saml:Advice><saml:Assertion ID=\"_advice\" Version=\"2.0\"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion></saml:Advice>"
            : string.Empty;

        var xml =
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + responseId + "\" Version=\"2.0\"" + destinationAttribute + ">" +
                "<saml:Assertion ID=\"" + assertionId + "\" Version=\"2.0\">" +
                    "<saml:Issuer>https://idp.example.com</saml:Issuer>" +
                    conditions +
                    advice +
                    "<saml:Subject>" +
                        (includeNameId ? "<saml:NameID>" + SecurityElement.Escape(nameId) + "</saml:NameID>" : string.Empty) +
                        "<saml:SubjectConfirmation" + (subjectConfirmationMethod == null ? string.Empty : " Method=\"" + SecurityElement.Escape(subjectConfirmationMethod) + "\"") + ">" +
                            subjectConfirmationData +
                        "</saml:SubjectConfirmation>" +
                    "</saml:Subject>" +
                    "<saml:AttributeStatement>" +
                        "<saml:Attribute Name=\"Role\"><saml:AttributeValue>" + SecurityElement.Escape(role) + "</saml:AttributeValue></saml:Attribute>" +
                    "</saml:AttributeStatement>" +
                "</saml:Assertion>" +
            "</samlp:Response>";

        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(xml);

        var referenceId = scope == SignatureScope.Response ? responseId : assertionId;
        SignElement(document, referenceId, rsa, certificate, signWithSha1, signWithCommentsC14n, signWithInclusiveC14n);

        return new SamlFixture(certificate, document, responseId, assertionId);
    }

    /// <summary>
    /// Produces a Response-scope-signed fixture whose XML carries REAL inter-element line breaks and
    /// indentation — the pretty-printed shape a conformant IdP serializes and signs over — instead of
    /// the compact single line <see cref="Create"/> emits. The template uses LF line endings, so the
    /// signed digest is computed over the EOL-normalized form the service provider reconstructs; the
    /// interop test (#120) rewrites those line breaks to raw CRLF on the wire to exercise the reader's
    /// XML 1.0 EOL normalization. Whitespace between elements is signature-covered (PreserveWhitespace),
    /// so this shape is what actually pins the normalization property.
    /// </summary>
    /// <param name="notOnOrAfter">SubjectConfirmationData/@NotOnOrAfter; defaults to five minutes in the future.</param>
    /// <returns>A fixture whose <see cref="SamlFixture.Document"/> serializes to the LF baseline.</returns>
    internal static SamlFixture CreateIndented(DateTime? notOnOrAfter = null)
    {
        const string TimeFormat = "yyyy-MM-ddTHH:mm:ssZ";
        var notOnOrAfterValue = (notOnOrAfter ?? DateTime.UtcNow.AddMinutes(5))
            .ToUniversalTime().ToString(TimeFormat, CultureInfo.InvariantCulture);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test SAML IdP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        var responseId = "_" + Guid.NewGuid().ToString("N");
        var assertionId = "_" + Guid.NewGuid().ToString("N");

        // LF line breaks and indentation between elements, exactly as a conformant IdP serializes before
        // signing. Kept as LF here (the interop test converts them to raw CRLF for the on-the-wire bytes).
        var xml =
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + responseId + "\" Version=\"2.0\">\n" +
            "  <saml:Assertion ID=\"" + assertionId + "\" Version=\"2.0\">\n" +
            "    <saml:Issuer>https://idp.example.com</saml:Issuer>\n" +
            "    <saml:Subject>\n" +
            "      <saml:NameID>alice</saml:NameID>\n" +
            "      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
            "        <saml:SubjectConfirmationData NotOnOrAfter=\"" + notOnOrAfterValue + "\" />\n" +
            "      </saml:SubjectConfirmation>\n" +
            "    </saml:Subject>\n" +
            "    <saml:AttributeStatement>\n" +
            "      <saml:Attribute Name=\"Role\"><saml:AttributeValue>jellyfin-users</saml:AttributeValue></saml:Attribute>\n" +
            "    </saml:AttributeStatement>\n" +
            "  </saml:Assertion>\n" +
            "</samlp:Response>";

        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(xml);

        SignElement(document, responseId, rsa, certificate, useSha1: false, useWithCommentsC14n: false, useInclusiveC14n: false);

        return new SamlFixture(certificate, document, responseId, assertionId);
    }

    /// <summary>
    /// Produces a response signed on BOTH the Response element AND the Assertion element (with the same
    /// key/cert), the ambiguous "two signatures" shape the single-signature invariant (#238) rejects.
    /// The assertion is signed first, then the response, so the response signature covers the already-signed
    /// assertion and both verify individually.
    /// </summary>
    /// <returns>A fixture whose document carries a Response-level and an Assertion-level signature.</returns>
    internal static SamlFixture CreateDoublySigned()
    {
        const string TimeFormat = "yyyy-MM-ddTHH:mm:ssZ";
        var notOnOrAfter = DateTime.UtcNow.AddMinutes(5).ToString(TimeFormat, CultureInfo.InvariantCulture);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test SAML IdP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        var responseId = "_" + Guid.NewGuid().ToString("N");
        var assertionId = "_" + Guid.NewGuid().ToString("N");

        var xml =
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + responseId + "\" Version=\"2.0\">" +
                "<saml:Assertion ID=\"" + assertionId + "\" Version=\"2.0\">" +
                    "<saml:Issuer>https://idp.example.com</saml:Issuer>" +
                    "<saml:Subject>" +
                        "<saml:NameID>alice</saml:NameID>" +
                        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" +
                            "<saml:SubjectConfirmationData NotOnOrAfter=\"" + notOnOrAfter + "\" />" +
                        "</saml:SubjectConfirmation>" +
                    "</saml:Subject>" +
                    "<saml:AttributeStatement>" +
                        "<saml:Attribute Name=\"Role\"><saml:AttributeValue>jellyfin-users</saml:AttributeValue></saml:Attribute>" +
                    "</saml:AttributeStatement>" +
                "</saml:Assertion>" +
            "</samlp:Response>";

        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(xml);

        SignElement(document, assertionId, rsa, certificate, useSha1: false, useWithCommentsC14n: false, useInclusiveC14n: false);
        SignElement(document, responseId, rsa, certificate, useSha1: false, useWithCommentsC14n: false, useInclusiveC14n: false);

        return new SamlFixture(certificate, document, responseId, assertionId);
    }

    private static void SignElement(XmlDocument document, string referenceId, RSA signingKey, X509Certificate2 certificate, bool useSha1, bool useWithCommentsC14n, bool useInclusiveC14n)
    {
        var signedXml = new SignedXml(document) { SigningKey = signingKey };

        var reference = new Reference("#" + referenceId) { DigestMethod = useSha1 ? SignedXml.XmlDsigSHA1Url : SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        if (useWithCommentsC14n)
        {
            reference.AddTransform(new XmlDsigExcC14NWithCommentsTransform());
        }
        else if (useInclusiveC14n)
        {
            reference.AddTransform(new XmlDsigC14NTransform());
        }
        else
        {
            reference.AddTransform(new XmlDsigExcC14NTransform());
        }

        signedXml.AddReference(reference);

        signedXml.SignedInfo!.CanonicalizationMethod =
            useWithCommentsC14n ? SignedXml.XmlDsigExcC14NWithCommentsTransformUrl
            : useInclusiveC14n ? SignedXml.XmlDsigC14NTransformUrl
            : SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = useSha1 ? SignedXml.XmlDsigRSASHA1Url : SignedXml.XmlDsigRSASHA256Url;

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();

        var signatureElement = signedXml.GetXml();
        var target = (XmlElement)signedXml.GetIdElement(document, referenceId)!;
        target.AppendChild(document.ImportNode(signatureElement, true));
    }
}

/// <summary>
/// A signed SAML response together with the certificate that signed it.
/// </summary>
internal sealed class SamlFixture
{
    private readonly X509Certificate2 _certificate;

    internal SamlFixture(X509Certificate2 certificate, XmlDocument document, string responseId, string assertionId)
    {
        _certificate = certificate;
        Document = document;
        ResponseId = responseId;
        AssertionId = assertionId;
    }

    /// <summary>Gets the signed document (mutable, so tests can inject wrapping attacks).</summary>
    internal XmlDocument Document { get; }

    /// <summary>Gets the ID attribute of the root Response element.</summary>
    internal string ResponseId { get; }

    /// <summary>Gets the ID attribute of the Assertion element.</summary>
    internal string AssertionId { get; }

    /// <summary>Gets the signing certificate exported as a Base64 DER string (the public part only).</summary>
    internal string CertificateBase64 => Convert.ToBase64String(_certificate.Export(X509ContentType.Cert));

    /// <summary>Gets a Base64 DER string of an unrelated certificate (for negative signature tests).</summary>
    internal static string ForeignCertificateBase64()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Someone Else", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        return Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
    }

    /// <summary>Encodes the current document as the Base64 SAMLResponse string the plugin expects.</summary>
    internal string EncodeResponse() => Encode(Document.OuterXml);

    /// <summary>Encodes an arbitrary XML string as a Base64 SAMLResponse.</summary>
    internal static string Encode(string xml) => Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));
}
