/*
 Was Jitbit's simple SAML 2.0 component for ASP.NET
 https://github.com/jitbit/AspNetSaml/
 (c) Jitbit LP, 2016
 Use this freely under the Apache license (see https://choosealicense.com/licenses/apache-2.0/)
 version 1.2.3
*/

using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Represents a SAML request.
/// </summary>
internal sealed class SamlAuthnRequest
{
    private readonly string _id;
    private readonly string _issueInstant;

    private readonly string _issuer;
    private readonly string _assertionConsumerServiceUrl;

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlAuthnRequest"/> class..
    /// </summary>
    /// <param name="issuer">The issuer of the SAML request.</param>
    /// <param name="assertionConsumerServiceUrl">The SAML assertion URL.</param>
    public SamlAuthnRequest(string issuer, string assertionConsumerServiceUrl)
    {
        _id = "_" + Guid.NewGuid().ToString();
        _issueInstant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture);

        _issuer = issuer;
        _assertionConsumerServiceUrl = assertionConsumerServiceUrl;
    }

    /// <summary>
    /// Gets the request's unique ID (the value sent as the AuthnRequest ID). The service provider
    /// records it so a later response's InResponseTo can be correlated to this request (#156).
    /// </summary>
    public string Id => _id;

    /// <summary>
    /// Gets the SAML request.
    /// </summary>
    /// <returns>The request as a Base64-encoded, DEFLATE-compressed string.</returns>
    public string GetRequest()
    {
        using var sw = new StringWriter();
        var xws = new XmlWriterSettings();
        xws.OmitXmlDeclaration = true;

        using (var xw = XmlWriter.Create(sw, xws))
        {
            xw.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
            xw.WriteAttributeString("ID", _id);
            xw.WriteAttributeString("Version", "2.0");
            xw.WriteAttributeString("IssueInstant", _issueInstant);
            xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            xw.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl);

            xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
            xw.WriteString(_issuer);
            xw.WriteEndElement();

            xw.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
            xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
            xw.WriteAttributeString("AllowCreate", "true");
            xw.WriteEndElement();

            xw.WriteEndElement();
        }

        // https://stackoverflow.com/questions/25120025/acs75005-the-request-is-not-a-valid-saml2-protocol-message-is-showing-always%3C/a%3E
        var memoryStream = new MemoryStream();
        var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
        writer.Write(sw.ToString());
        writer.Close();
        var result = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
        return result;
    }

    /// <summary>
    /// Gets the the URL you should redirect your users to (i.e. your SAML-provider login URL with the Base64-ed request in the querystring.
    /// </summary>
    /// <param name="samlEndpoint">The SAML endpoint.</param>
    /// <param name="relayState">The relay state.</param>
    /// <returns>The redirect url.</returns>
    public string GetRedirectUrl(string samlEndpoint, string? relayState = null)
    {
        ArgumentNullException.ThrowIfNull(samlEndpoint);

        var queryStringSeparator = samlEndpoint.Contains('?') ? "&" : "?";

        var url = samlEndpoint + queryStringSeparator + "SAMLRequest=" + HttpUtility.UrlEncode(GetRequest());

        if (!string.IsNullOrEmpty(relayState))
        {
            url += "&RelayState=" + HttpUtility.UrlEncode(relayState);
        }

        return url;
    }

    /// <summary>
    /// Gets the redirect URL with the AuthnRequest SIGNED for the HTTP-Redirect binding (#167): the same
    /// DEFLATE/Base64 request, carrying a detached query-string signature (SigAlg + Signature) over the
    /// URL-encoded parameters, for identity providers that require signed AuthnRequests. Distinct from the
    /// unsigned <see cref="GetRedirectUrl"/> — which is byte-for-byte unchanged for deployments that do not
    /// sign — because the signed path must encode the query consistently with the octets it signs.
    /// </summary>
    /// <param name="samlEndpoint">The SAML endpoint.</param>
    /// <param name="relayState">The relay state, omitted when null or empty.</param>
    /// <param name="signingKey">The service-provider private key — RSA or ECDSA (#493).</param>
    /// <returns>The signed redirect url.</returns>
    public string GetSignedRedirectUrl(string samlEndpoint, string? relayState, AsymmetricAlgorithm signingKey)
    {
        ArgumentNullException.ThrowIfNull(samlEndpoint);

        return SamlRedirectSigner.BuildSignedRedirectUrl(samlEndpoint, "SAMLRequest", GetRequest(), relayState, signingKey);
    }
}
