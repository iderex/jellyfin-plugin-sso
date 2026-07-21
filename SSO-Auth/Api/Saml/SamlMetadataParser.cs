// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Parses an identity provider's SAML 2.0 metadata into the provider-configuration values an administrator
/// would otherwise hand-copy (#735): the entity id, the Single Sign-On endpoint, and the signing
/// certificate(s). The metadata is UNTRUSTED input, so it is parsed with the identical fail-closed hardening
/// <see cref="SamlResponse"/> uses on inbound assertions — DTD/DOCTYPE prohibited (no XXE, no billion-laughs
/// entity expansion), <c>XmlResolver = null</c> (no external-entity fetch / SSRF), and a bound on the DOM the
/// reader materializes. Any malformed, oversized, or incomplete document throws
/// <see cref="SamlMetadataException"/> with an admin-facing message; nothing is ever partially extracted.
/// </summary>
internal static class SamlMetadataParser
{
    private const string MetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata";
    private const string DsigNamespace = "http://www.w3.org/2000/09/xmldsig#";
    private const string RedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    private const string PostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    /// <summary>
    /// The maximum characters the metadata reader will materialize (#754), matching the inbound-response
    /// parser. A legitimate IdP metadata document is single- to low-double-digit KB; this bounds a hostile or
    /// accidental multi-megabyte document that DTD prohibition (which bounds entities, not bulk) would not.
    /// </summary>
    internal const int MaxCharactersInDocument = 256 * 1024;

    /// <summary>
    /// Parses IdP metadata XML into a <see cref="SamlMetadataImport"/>.
    /// </summary>
    /// <param name="xml">The raw metadata XML (fetched or pasted).</param>
    /// <returns>The extracted, validated configuration values.</returns>
    /// <exception cref="SamlMetadataException">The metadata is malformed, oversized, or incomplete.</exception>
    internal static SamlMetadataImport Parse(string? xml)
    {
        if (string.IsNullOrWhiteSpace(xml))
        {
            throw new SamlMetadataException("The metadata document was empty.");
        }

        var doc = ParseHardened(xml);

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("md", MetadataNamespace);
        ns.AddNamespace("ds", DsigNamespace);

        // The IdP role descriptor — anywhere in the tree, so a metadata aggregate (EntitiesDescriptor wrapping
        // several EntityDescriptors) resolves to the first entity that actually plays the IdP role.
        if (doc.SelectSingleNode("//md:EntityDescriptor/md:IDPSSODescriptor", ns) is not XmlElement idp)
        {
            throw new SamlMetadataException("No IDPSSODescriptor was found — this does not look like SAML identity-provider metadata.");
        }

        var entityId = ((XmlElement)idp.ParentNode!).GetAttribute("entityID").Trim();
        if (string.IsNullOrEmpty(entityId))
        {
            throw new SamlMetadataException("The EntityDescriptor carries no entityID.");
        }

        var endpoint = PickSsoLocation(idp, ns)
            ?? throw new SamlMetadataException("No SingleSignOnService with a usable HTTP-Redirect or HTTP-POST binding was found.");

        var certificates = ExtractSigningCertificates(idp, ns);
        if (certificates.Count == 0)
        {
            throw new SamlMetadataException("No signing certificate (a KeyDescriptor with use=\"signing\") was found in the metadata.");
        }

        // Every extracted certificate must load AND meet the minimum key-strength floor (#733), reusing the
        // one predicate the SAML config-save path uses — so an import can never pre-fill a cert that the save
        // would reject (or that would fail signature validation at login). Fail closed on the first bad one;
        // no partial result.
        foreach (var certificate in certificates)
        {
            if (SamlCertificate.IsInvalid(certificate))
            {
                throw new SamlMetadataException("A signing certificate in the metadata is not a loadable X.509 certificate or does not meet the minimum key strength.");
            }
        }

        return new SamlMetadataImport(
            entityId,
            endpoint,
            certificates[0],
            certificates.Count > 1 ? certificates[1] : null);
    }

    // Parses the untrusted metadata with the same hardening SamlResponse applies to inbound assertions: no
    // DTD/DOCTYPE (XXE + billion-laughs), no external-entity resolution, and a bound on the materialized DOM.
    private static XmlDocument ParseHardened(string xml)
    {
        // Strip a leading UTF-8 byte-order-mark: a BOM that survived into the string (a pasted document, or a
        // fetch decoded without BOM handling) is a U+FEFF character before the XML declaration, which the
        // reader rejects as "data at the root level is invalid" — so an otherwise-valid document (ADFS serves
        // its FederationMetadata.xml UTF-8-with-BOM) would fail. The fetch path decodes with BOM detection too.
        if (xml.Length > 0 && xml[0] == 0xFEFF)
        {
            xml = xml.Substring(1);
        }

        var doc = new XmlDocument { XmlResolver = null };
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxCharactersInDocument,
        };

        try
        {
            using var stringReader = new StringReader(xml);
            using var reader = XmlReader.Create(stringReader, settings);
            doc.Load(reader);
        }
        catch (XmlException ex)
        {
            // Malformed XML, a prohibited DOCTYPE/DTD, or the character bound exceeded — all fail closed with
            // an admin-facing message; the library's detail stays out of the response.
            throw new SamlMetadataException("The metadata is not well-formed XML, exceeds the size limit, or contains a prohibited DTD/DOCTYPE.", ex);
        }

        return doc;
    }

    // The SSO endpoint URL: prefer HTTP-Redirect (the binding this SP drives the browser with), then
    // HTTP-POST, then the first SingleSignOnService that carries any Location.
    private static string? PickSsoLocation(XmlElement idp, XmlNamespaceManager ns)
    {
        var services = idp.SelectNodes("md:SingleSignOnService", ns)?.Cast<XmlElement>().ToList() ?? new List<XmlElement>();

        // XmlElement.GetAttribute returns "" (not null) for a missing/empty Location, so normalize a blank to
        // null — otherwise a matching-binding service with no Location would short-circuit the ?? fallback and
        // skip a usable endpoint under another binding.
        string? ByBinding(string binding)
        {
            var candidate = services
                .FirstOrDefault(s => string.Equals(s.GetAttribute("Binding"), binding, StringComparison.Ordinal))
                ?.GetAttribute("Location");
            return string.IsNullOrWhiteSpace(candidate) ? null : candidate;
        }

        var location = ByBinding(RedirectBinding)
            ?? ByBinding(PostBinding)
            ?? services.Select(s => s.GetAttribute("Location")).FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));

        return string.IsNullOrWhiteSpace(location) ? null : location.Trim();
    }

    // The signing certificates: every KeyDescriptor marked use="signing" OR with no use attribute (which by
    // the SAML metadata schema serves both signing and encryption), in document order. Whitespace inside the
    // Base64 (metadata is commonly pretty-printed with wrapped certificate text) is stripped so the value is a
    // clean Base64 DER string the config fields and X509 loader accept.
    private static List<string> ExtractSigningCertificates(XmlElement idp, XmlNamespaceManager ns)
    {
        return (idp.SelectNodes("md:KeyDescriptor", ns)?.Cast<XmlElement>() ?? Enumerable.Empty<XmlElement>())
            .Where(k =>
            {
                var use = k.GetAttribute("use");
                return string.IsNullOrEmpty(use) || string.Equals(use, "signing", StringComparison.Ordinal);
            })
            .Select(k => k.SelectSingleNode("ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns)?.InnerText)
            .Where(text => !string.IsNullOrWhiteSpace(text))
            .Select(text => new string(text!.Where(c => !char.IsWhiteSpace(c)).ToArray()))
            .Where(text => text.Length > 0)
            .ToList();
    }
}
