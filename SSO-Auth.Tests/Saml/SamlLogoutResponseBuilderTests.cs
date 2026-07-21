// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlLogoutResponseBuilder"/> (#727, SLO-3c): the OUTBOUND signed <c>LogoutResponse</c>
/// the SP returns to close the IdP's Single-Logout loop. It mirrors <see cref="SamlLogoutRequestBuilder"/> —
/// the same DEFLATE/Base64 encoding and the shared <see cref="SamlRedirectSigner"/> — so these assertions pin
/// (a) the document is a well-formed LogoutResponse carrying the Issuer, InResponseTo, Destination, and a
/// Success status, and (b) the emitted redirect (under the SAMLResponse parameter, echoing RelayState) carries
/// a detached signature that verifies against the signer's public key over the exact octets.
/// </summary>
public class SamlLogoutResponseBuilderTests
{
    private const string SloEndpoint = "https://idp.example.com/slo";
    private const string Issuer = "jellyfin-sp";
    private const string InResponseTo = "_request-id-123";
    private const string SuccessStatus = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private const string EcdsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    [Fact]
    public void GetResponse_EmitsAWellFormedLogoutResponse_WithIssuerInResponseToDestinationAndSuccess()
    {
        var builder = new SamlLogoutResponseBuilder(Issuer, InResponseTo, SloEndpoint);

        var doc = Inflate(builder.GetResponse());
        var nsmgr = Namespaces(doc);

        Assert.Equal("LogoutResponse", doc.DocumentElement!.LocalName);
        Assert.Equal("urn:oasis:names:tc:SAML:2.0:protocol", doc.DocumentElement.NamespaceURI);
        Assert.False(string.IsNullOrEmpty(doc.DocumentElement.GetAttribute("ID")));
        Assert.Equal("2.0", doc.DocumentElement.GetAttribute("Version"));
        Assert.Equal(InResponseTo, doc.DocumentElement.GetAttribute("InResponseTo"));
        Assert.Equal(SloEndpoint, doc.DocumentElement.GetAttribute("Destination"));
        Assert.Equal(Issuer, doc.SelectSingleNode("/samlp:LogoutResponse/saml:Issuer", nsmgr)!.InnerText);
        Assert.Equal(SuccessStatus, ((XmlElement)doc.SelectSingleNode("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode", nsmgr)!).GetAttribute("Value"));
    }

    [Fact]
    public void GetResponse_ExposedIdMatchesTheDocumentId()
    {
        var builder = new SamlLogoutResponseBuilder(Issuer, InResponseTo, SloEndpoint);

        var doc = Inflate(builder.GetResponse());

        Assert.Equal(builder.Id, doc.DocumentElement!.GetAttribute("ID"));
    }

    [Fact]
    public void GetSignedRedirectUrl_EmitsSamlResponseSigAlgAndSignature_ThatVerify()
    {
        using var rsa = RSA.Create(2048);
        var builder = new SamlLogoutResponseBuilder(Issuer, InResponseTo, SloEndpoint);

        var url = builder.GetSignedRedirectUrl(SloEndpoint, relayState: null, rsa);

        // A response rides the SAMLResponse parameter, not SAMLRequest.
        Assert.StartsWith(SloEndpoint + "?SAMLResponse=", url, StringComparison.Ordinal);
        Assert.Contains("&SigAlg=", url, StringComparison.Ordinal);
        Assert.Contains("&Signature=", url, StringComparison.Ordinal);
        Assert.DoesNotContain("&RelayState=", url, StringComparison.Ordinal);
        Assert.True(RsaSignatureVerifies(url, rsa, relayState: null));
    }

    [Fact]
    public void GetSignedRedirectUrl_EchoesRelayState_AndSignsOverIt()
    {
        using var rsa = RSA.Create(2048);
        const string RelayState = "opaque-idp-state-42";
        var builder = new SamlLogoutResponseBuilder(Issuer, InResponseTo, SloEndpoint);

        var url = builder.GetSignedRedirectUrl(SloEndpoint, RelayState, rsa);

        Assert.Contains("&RelayState=" + Uri.EscapeDataString(RelayState), url, StringComparison.Ordinal);
        // The RelayState is part of the signed octet string (order: SAMLResponse, RelayState, SigAlg).
        Assert.True(RsaSignatureVerifies(url, rsa, RelayState));
    }

    [Fact]
    public void GetSignedRedirectUrl_ForeignKey_DoesNotVerify()
    {
        using var signer = RSA.Create(2048);
        using var attacker = RSA.Create(2048);
        var builder = new SamlLogoutResponseBuilder(Issuer, InResponseTo, SloEndpoint);

        var url = builder.GetSignedRedirectUrl(SloEndpoint, relayState: null, signer);

        // The signature check is real, not vacuous: the signer verifies, a different key does not.
        Assert.True(RsaSignatureVerifies(url, signer, relayState: null));
        Assert.False(RsaSignatureVerifies(url, attacker, relayState: null));
    }

    [Fact]
    public void GetSignedRedirectUrl_EcdsaKey_SelectsEcdsaSigAlg_AndVerifies()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var builder = new SamlLogoutResponseBuilder(Issuer, InResponseTo, SloEndpoint);

        var url = builder.GetSignedRedirectUrl(SloEndpoint, relayState: null, ecdsa);

        // The SigAlg is derived from the key type by the shared signer (#493), never SHA-1.
        Assert.Contains("&SigAlg=" + Uri.EscapeDataString(EcdsaSha256), url, StringComparison.Ordinal);
        Assert.True(EcdsaSignatureVerifies(url, ecdsa, relayState: null));
    }

    [Fact]
    public void GetSignedRedirectUrl_NullEndpoint_Throws()
    {
        using var rsa = RSA.Create(2048);
        var builder = new SamlLogoutResponseBuilder(Issuer, InResponseTo, SloEndpoint);

        Assert.Throws<ArgumentNullException>(() => { builder.GetSignedRedirectUrl(null!, null, rsa); });
    }

    // Inflates the DEFLATE+Base64 SAMLResponse back into its XML document, exactly as an identity provider does.
    private static XmlDocument Inflate(string encoded)
    {
        var compressed = Convert.FromBase64String(encoded);
        using var input = new MemoryStream(compressed);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var reader = new StreamReader(deflate, new UTF8Encoding(false));
        var xml = reader.ReadToEnd();

        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        return doc;
    }

    private static XmlNamespaceManager Namespaces(XmlDocument doc)
    {
        var nsmgr = new XmlNamespaceManager(doc.NameTable);
        nsmgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
        nsmgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
        return nsmgr;
    }

    private static bool RsaSignatureVerifies(string url, RSA publicKey, string? relayState)
        => publicKey.VerifyData(Encoding.UTF8.GetBytes(SignedQuery(url, relayState)), Signature(url), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    private static bool EcdsaSignatureVerifies(string url, ECDsa publicKey, string? relayState)
        => publicKey.VerifyData(Encoding.UTF8.GetBytes(SignedQuery(url, relayState)), Signature(url), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    // Reconstructs the signed octet string (SAMLResponse, then RelayState when present, then SigAlg) from the URL.
    private static string SignedQuery(string url, string? relayState)
    {
        var samlResponse = QueryValue(url, "SAMLResponse");
        var sigAlg = QueryValue(url, "SigAlg");
        var query = "SAMLResponse=" + Uri.EscapeDataString(samlResponse);
        if (!string.IsNullOrEmpty(relayState))
        {
            query += "&RelayState=" + Uri.EscapeDataString(relayState);
        }

        return query + "&SigAlg=" + Uri.EscapeDataString(sigAlg);
    }

    private static byte[] Signature(string url) => Convert.FromBase64String(QueryValue(url, "Signature"));

    private static string QueryValue(string url, string name)
    {
        foreach (var pair in url[(url.IndexOf('?') + 1)..].Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq > 0 && pair[..eq] == name)
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        throw new InvalidOperationException($"Query parameter '{name}' not found in {url}.");
    }
}
