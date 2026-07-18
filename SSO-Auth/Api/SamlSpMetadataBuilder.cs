#nullable enable

using System.IO;
using System.Text;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Builds SAML 2.0 service-provider metadata — an <c>EntityDescriptor</c> carrying an
/// <c>SPSSODescriptor</c> — that an administrator can hand to an identity provider so it registers this
/// service provider by URL instead of by hand (#162). Pure and request-free: it emits exactly the entity
/// id, the HTTP-POST assertion-consumer URL, and — only when request signing is enabled — the PUBLIC
/// signing certificate it is given. It never touches a private key or any secret, and it never reads the
/// request <c>Host</c>: the caller resolves the entity id and ACS URL from the configured canonical Base
/// URL (#139), so a spoofed or proxy-forwarded host cannot poison the ACS the identity provider is told to
/// POST assertions to.
/// </summary>
internal static class SamlSpMetadataBuilder
{
    private const string MetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata";
    private const string ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";
    private const string DsigNamespace = "http://www.w3.org/2000/09/xmldsig#";
    private const string HttpPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    /// <summary>
    /// Renders the service-provider metadata document.
    /// </summary>
    /// <param name="entityId">
    /// The SP entity id — the same value this service provider sends as the AuthnRequest <c>Issuer</c>
    /// (the configured client id), so the identity provider correlates the two.
    /// </param>
    /// <param name="assertionConsumerServiceUrl">
    /// The absolute HTTP-POST assertion-consumer URL, built from the configured canonical Base URL (never
    /// the request host).
    /// </param>
    /// <param name="signingCertificateBase64">
    /// The Base64 (DER) PUBLIC signing certificate to advertise under a <c>KeyDescriptor use="signing"</c>
    /// when request signing is enabled, or <see langword="null"/> to advertise no signing key. This is only
    /// ever the public certificate — the private key must never be passed here.
    /// </param>
    /// <returns>The metadata document as an XML string.</returns>
    internal static string Build(string entityId, string assertionConsumerServiceUrl, string? signingCertificateBase64)
    {
        // A StringWriter is UTF-16 internally, which would make XmlWriter stamp encoding="utf-16" into the
        // XML declaration even though the bytes are served as UTF-8; report UTF-8 so the declaration matches
        // the wire encoding a strict metadata consumer validates.
        using var writer = new Utf8StringWriter();
        var settings = new XmlWriterSettings
        {
            Indent = true,
            Encoding = Encoding.UTF8,
        };

        using (var xml = XmlWriter.Create(writer, settings))
        {
            xml.WriteStartElement("md", "EntityDescriptor", MetadataNamespace);
            xml.WriteAttributeString("entityID", entityId);

            xml.WriteStartElement("md", "SPSSODescriptor", MetadataNamespace);

            // Advertise request signing exactly as it is configured, and always require signed assertions:
            // this SP rejects an unsigned assertion (Saml.cs verifies the signature on every response), so
            // WantAssertionsSigned="true" is a truthful statement of what the IdP must send.
            xml.WriteAttributeString("AuthnRequestsSigned", signingCertificateBase64 is null ? "false" : "true");
            xml.WriteAttributeString("WantAssertionsSigned", "true");
            xml.WriteAttributeString("protocolSupportEnumeration", ProtocolNamespace);

            if (signingCertificateBase64 is not null)
            {
                xml.WriteStartElement("md", "KeyDescriptor", MetadataNamespace);
                xml.WriteAttributeString("use", "signing");
                xml.WriteStartElement("ds", "KeyInfo", DsigNamespace);
                xml.WriteStartElement("ds", "X509Data", DsigNamespace);
                xml.WriteStartElement("ds", "X509Certificate", DsigNamespace);
                xml.WriteString(signingCertificateBase64);
                xml.WriteEndElement(); // ds:X509Certificate
                xml.WriteEndElement(); // ds:X509Data
                xml.WriteEndElement(); // ds:KeyInfo
                xml.WriteEndElement(); // md:KeyDescriptor
            }

            xml.WriteStartElement("md", "AssertionConsumerService", MetadataNamespace);
            xml.WriteAttributeString("Binding", HttpPostBinding);
            xml.WriteAttributeString("Location", assertionConsumerServiceUrl);
            xml.WriteAttributeString("index", "0");
            xml.WriteAttributeString("isDefault", "true");
            xml.WriteEndElement(); // md:AssertionConsumerService

            xml.WriteEndElement(); // md:SPSSODescriptor
            xml.WriteEndElement(); // md:EntityDescriptor
        }

        return writer.ToString();
    }

    // A StringWriter that reports UTF-8 so XmlWriter emits encoding="utf-8" in the XML declaration (the
    // default StringWriter reports UTF-16, which would mislabel the served UTF-8 document).
    private sealed class Utf8StringWriter : StringWriter
    {
        public override Encoding Encoding => Encoding.UTF8;
    }
}
