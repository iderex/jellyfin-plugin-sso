#nullable enable

using System.IO;
using System.Text;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Builds SAML 2.0 service-provider metadata — an <c>EntityDescriptor</c> carrying an
/// <c>SPSSODescriptor</c> — that an administrator can hand to an identity provider so it registers this
/// service provider by URL instead of by hand (#162). Pure and request-free: it emits exactly the entity
/// id, the HTTP-POST assertion-consumer URL(s), and — only when request signing is enabled — the PUBLIC
/// signing certificate(s) it is given. This SP accepts BOTH ACS spellings on the way back — the new-path
/// and the legacy one (<see cref="SsoUrlBuilder.SamlExpectedAcsUrls"/>) — so when a legacy ACS URL is
/// supplied the metadata advertises both as two <c>AssertionConsumerService</c> entries: the new spelling
/// stays the default at <c>index="0"</c>, the legacy spelling follows at <c>index="1"</c>
/// (<c>isDefault="false"</c>). During a signing-key rollover (#491) it advertises BOTH the primary
/// and the optional rollover PUBLIC certificate as two <c>KeyDescriptor use="signing"</c> entries, so the
/// identity provider trusts either while the administrator swaps. It never touches a private key or any
/// secret, and it never reads the request <c>Host</c>: the caller resolves the entity id and ACS URL(s) from
/// the configured canonical Base URL (#139), so a spoofed or proxy-forwarded host cannot poison the ACS the
/// identity provider is told to POST assertions to.
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
    /// The absolute HTTP-POST assertion-consumer URL — the new-path spelling — built from the configured
    /// canonical Base URL (never the request host). This is the default ACS at <c>index="0"</c>.
    /// </param>
    /// <param name="signingCertificateBase64">
    /// The Base64 (DER) PUBLIC signing certificate to advertise under a <c>KeyDescriptor use="signing"</c>
    /// when request signing is enabled, or <see langword="null"/> to advertise no signing key. This is only
    /// ever the public certificate — the private key must never be passed here.
    /// </param>
    /// <param name="rolloverSigningCertificateBase64">
    /// The OPTIONAL Base64 (DER) PUBLIC rollover signing certificate (#491), advertised as a SECOND
    /// <c>KeyDescriptor use="signing"</c> so the identity provider trusts either during an overlap window.
    /// <see langword="null"/> (the default) means no rollover — a single KeyDescriptor, byte-for-byte the
    /// pre-#491 output. Ignored when <paramref name="signingCertificateBase64"/> is <see langword="null"/>
    /// (no primary means signing is off, so there is nothing to roll over). Again only ever the public
    /// certificate — never a private key.
    /// </param>
    /// <param name="legacyAssertionConsumerServiceUrl">
    /// The OPTIONAL absolute HTTP-POST assertion-consumer URL for the LEGACY route spelling. This SP accepts
    /// either spelling at runtime (<see cref="SsoUrlBuilder.SamlExpectedAcsUrls"/>), so when this is supplied
    /// the metadata truthfully advertises both: the new spelling stays the default at <c>index="0"</c> and
    /// this legacy spelling is emitted as a SECOND <c>AssertionConsumerService</c> at <c>index="1"</c>,
    /// <c>isDefault="false"</c>. <see langword="null"/> (the default), or a value equal to
    /// <paramref name="assertionConsumerServiceUrl"/>, emits a single ACS — byte-for-byte the pre-#569
    /// output. Placed last so existing positional callers stay source-compatible.
    /// </param>
    /// <returns>The metadata document as an XML string.</returns>
    internal static string Build(string entityId, string assertionConsumerServiceUrl, string? signingCertificateBase64, string? rolloverSigningCertificateBase64 = null, string? legacyAssertionConsumerServiceUrl = null)
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
                WriteSigningKeyDescriptor(xml, signingCertificateBase64);

                // The rollover certificate (#491) is a SECOND signing KeyDescriptor during the overlap
                // window. It is only meaningful alongside a primary (signing must be on), so it is nested
                // under the primary guard; a null rollover leaves the single-descriptor output unchanged.
                if (rolloverSigningCertificateBase64 is not null)
                {
                    WriteSigningKeyDescriptor(xml, rolloverSigningCertificateBase64);
                }
            }

            xml.WriteStartElement("md", "AssertionConsumerService", MetadataNamespace);
            xml.WriteAttributeString("Binding", HttpPostBinding);
            xml.WriteAttributeString("Location", assertionConsumerServiceUrl);
            xml.WriteAttributeString("index", "0");
            xml.WriteAttributeString("isDefault", "true");
            xml.WriteEndElement(); // md:AssertionConsumerService

            // The SP accepts either ACS spelling on the way back (SsoUrlBuilder.SamlExpectedAcsUrls), so when a
            // distinct legacy spelling is supplied the metadata lists it too — a SECOND, non-default endpoint at
            // index="1". The new spelling above stays the default (index="0", isDefault="true"), so an identity
            // provider that honours isDefault keeps posting to it; the legacy entry only widens what the IdP may
            // pick to a URL this SP already honours. A null (the default) or duplicate legacy URL leaves the
            // single-ACS output unchanged.
            if (legacyAssertionConsumerServiceUrl is not null
                && !string.Equals(legacyAssertionConsumerServiceUrl, assertionConsumerServiceUrl, System.StringComparison.Ordinal))
            {
                xml.WriteStartElement("md", "AssertionConsumerService", MetadataNamespace);
                xml.WriteAttributeString("Binding", HttpPostBinding);
                xml.WriteAttributeString("Location", legacyAssertionConsumerServiceUrl);
                xml.WriteAttributeString("index", "1");
                xml.WriteAttributeString("isDefault", "false");
                xml.WriteEndElement(); // md:AssertionConsumerService
            }

            xml.WriteEndElement(); // md:SPSSODescriptor
            xml.WriteEndElement(); // md:EntityDescriptor
        }

        return writer.ToString();
    }

    // Writes one <md:KeyDescriptor use="signing"> wrapping the given PUBLIC certificate DER. The caller
    // passes only the public certificate (certificate.RawData); no private-key material ever reaches here.
    private static void WriteSigningKeyDescriptor(XmlWriter xml, string signingCertificateBase64)
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

    // A StringWriter that reports UTF-8 so XmlWriter emits encoding="utf-8" in the XML declaration (the
    // default StringWriter reports UTF-16, which would mislabel the served UTF-8 document).
    private sealed class Utf8StringWriter : StringWriter
    {
        public override Encoding Encoding => Encoding.UTF8;
    }
}
