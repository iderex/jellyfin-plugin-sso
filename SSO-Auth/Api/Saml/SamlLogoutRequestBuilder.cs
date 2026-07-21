// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// Builds an OUTBOUND SP-initiated SAML 2.0 <c>LogoutRequest</c> for the HTTP-Redirect binding (#727, SLO-3c)
/// — the mirror image of <see cref="SamlAuthnRequest"/> for the logout flow. It emits the same DEFLATE +
/// Base64 encoding as the AuthnRequest builder (<see cref="GetRequest"/>) and hands the encoded message to the
/// SHARED <see cref="SamlRedirectSigner"/> for the mandated detached SigAlg+Signature, so the outbound-signing
/// infrastructure is reused verbatim rather than re-implemented.
/// </summary>
/// <remarks>
/// This is the OUTBOUND builder and is deliberately distinct from <see cref="SamlLogoutRequest"/>, which is the
/// INBOUND (IdP-initiated) validator: conflating them would let a change to the session-destructive inbound
/// parser regress the outbound builder, or vice versa. The document carries the SP <c>Issuer</c> (the same
/// entity id the AuthnRequest sends), the subject <c>NameID</c> the caller logged in as, and the captured
/// <c>SessionIndex</c> when one is present, in the element order SAML core §3.7.1 fixes (Issuer, then the
/// identifier, then any SessionIndex).
/// </remarks>
internal sealed class SamlLogoutRequestBuilder
{
    private readonly string _id;
    private readonly string _issueInstant;

    private readonly string _issuer;
    private readonly string _nameId;
    private readonly string? _sessionIndex;

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlLogoutRequestBuilder"/> class.
    /// </summary>
    /// <param name="issuer">The SP entity id (the same value the AuthnRequest sends as its Issuer).</param>
    /// <param name="nameId">The subject NameID the caller authenticated as (their own, caller-scoped).</param>
    /// <param name="sessionIndex">The captured identity-provider SessionIndex, or null/blank when none.</param>
    public SamlLogoutRequestBuilder(string issuer, string nameId, string? sessionIndex)
    {
        _id = "_" + Guid.NewGuid().ToString();
        _issueInstant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

        _issuer = issuer;
        _nameId = nameId;
        _sessionIndex = sessionIndex;
    }

    /// <summary>
    /// Gets the request's unique <c>ID</c> (the value sent as the LogoutRequest ID).
    /// </summary>
    public string Id => _id;

    /// <summary>
    /// Builds the <c>LogoutRequest</c> as a Base64-encoded, DEFLATE-compressed string. The DEFLATE/encoding
    /// approach is copied verbatim from <see cref="SamlAuthnRequest.GetRequest"/> so both outbound
    /// redirect-binding messages encode identically.
    /// </summary>
    /// <returns>The request as a Base64-encoded, DEFLATE-compressed string.</returns>
    public string GetRequest()
    {
        using var sw = new StringWriter(CultureInfo.InvariantCulture);
        var xws = new XmlWriterSettings();
        xws.OmitXmlDeclaration = true;

        using (var xw = XmlWriter.Create(sw, xws))
        {
            xw.WriteStartElement("samlp", "LogoutRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
            xw.WriteAttributeString("ID", _id);
            xw.WriteAttributeString("Version", "2.0");
            xw.WriteAttributeString("IssueInstant", _issueInstant);

            xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
            xw.WriteString(_issuer);
            xw.WriteEndElement();

            xw.WriteStartElement("saml", "NameID", "urn:oasis:names:tc:SAML:2.0:assertion");
            xw.WriteString(_nameId);
            xw.WriteEndElement();

            // SessionIndex is optional (SAML core §3.7.1): emit it only when the login captured one, so a
            // provider that issues no SessionIndex still gets a well-formed request that logs the subject out.
            if (!string.IsNullOrEmpty(_sessionIndex))
            {
                xw.WriteStartElement("samlp", "SessionIndex", "urn:oasis:names:tc:SAML:2.0:protocol");
                xw.WriteString(_sessionIndex);
                xw.WriteEndElement();
            }

            xw.WriteEndElement();
        }

        // The exact DEFLATE + Base64 approach SamlAuthnRequest.GetRequest uses for the HTTP-Redirect binding.
        var memoryStream = new MemoryStream();
        var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
        writer.Write(sw.ToString());
        writer.Close();
        return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
    }

    /// <summary>
    /// Gets the redirect URL to the identity provider's Single-Logout endpoint with the LogoutRequest SIGNED
    /// for the HTTP-Redirect binding — delegating to the SHARED <see cref="SamlRedirectSigner"/> exactly as
    /// <see cref="SamlAuthnRequest.GetSignedRedirectUrl"/> does, so the SigAlg/Signature policy (key-type
    /// derived, allowlist-checked, no SHA-1) is reused rather than re-implemented.
    /// </summary>
    /// <param name="sloEndpoint">The identity provider's Single-Logout (SLO) endpoint URL.</param>
    /// <param name="relayState">The relay state, omitted when null or empty.</param>
    /// <param name="signingKey">The service-provider private key — RSA or ECDSA.</param>
    /// <returns>The signed redirect URL.</returns>
    public string GetSignedRedirectUrl(string sloEndpoint, string? relayState, AsymmetricAlgorithm signingKey)
    {
        ArgumentNullException.ThrowIfNull(sloEndpoint);

        return SamlRedirectSigner.BuildSignedRedirectUrl(sloEndpoint, "SAMLRequest", GetRequest(), relayState, signingKey);
    }
}
