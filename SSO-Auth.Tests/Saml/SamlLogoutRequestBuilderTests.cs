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
/// Tests for <see cref="SamlLogoutRequestBuilder"/> (#727, SLO-3c): the OUTBOUND SP-initiated
/// <c>LogoutRequest</c> builder. It mirrors <see cref="SamlAuthnRequest"/> — the same DEFLATE/Base64 encoding
/// and the same shared <see cref="SamlRedirectSigner"/> — so these assertions pin (a) the document is a
/// well-formed LogoutRequest carrying the Issuer, NameID, and optional SessionIndex, and (b) the emitted
/// redirect carries a detached signature that verifies against the signer's public key over the exact octets.
/// </summary>
public class SamlLogoutRequestBuilderTests
{
    private const string SloEndpoint = "https://idp.example.com/slo";
    private const string Issuer = "jellyfin-sp";
    private const string NameId = "user-nameid-123";
    private const string EcdsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    [Fact]
    public void GetRequest_EmitsAWellFormedLogoutRequest_WithIssuerNameIdAndSessionIndex()
    {
        var builder = new SamlLogoutRequestBuilder(Issuer, NameId, "session-index-abc");

        var doc = InflateRequest(builder.GetRequest());
        var nsmgr = Namespaces(doc);

        Assert.Equal("LogoutRequest", doc.DocumentElement!.LocalName);
        Assert.Equal("urn:oasis:names:tc:SAML:2.0:protocol", doc.DocumentElement.NamespaceURI);
        Assert.False(string.IsNullOrEmpty(doc.DocumentElement.GetAttribute("ID")));
        Assert.Equal("2.0", doc.DocumentElement.GetAttribute("Version"));
        Assert.Equal(Issuer, doc.SelectSingleNode("/samlp:LogoutRequest/saml:Issuer", nsmgr)!.InnerText);
        Assert.Equal(NameId, doc.SelectSingleNode("/samlp:LogoutRequest/saml:NameID", nsmgr)!.InnerText);
        Assert.Equal("session-index-abc", doc.SelectSingleNode("/samlp:LogoutRequest/samlp:SessionIndex", nsmgr)!.InnerText);
    }

    [Fact]
    public void GetRequest_ExposedIdMatchesTheDocumentId()
    {
        var builder = new SamlLogoutRequestBuilder(Issuer, NameId, null);

        var doc = InflateRequest(builder.GetRequest());

        Assert.Equal(builder.Id, doc.DocumentElement!.GetAttribute("ID"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void GetRequest_OmitsSessionIndex_WhenNoneCaptured(string? sessionIndex)
    {
        var builder = new SamlLogoutRequestBuilder(Issuer, NameId, sessionIndex);

        var doc = InflateRequest(builder.GetRequest());
        var nsmgr = Namespaces(doc);

        // A provider that issued no SessionIndex still yields a well-formed request that names the subject.
        Assert.Null(doc.SelectSingleNode("/samlp:LogoutRequest/samlp:SessionIndex", nsmgr));
        Assert.Equal(NameId, doc.SelectSingleNode("/samlp:LogoutRequest/saml:NameID", nsmgr)!.InnerText);
    }

    [Fact]
    public void GetSignedRedirectUrl_EmitsSamlRequestSigAlgAndSignature_ThatVerify()
    {
        using var rsa = RSA.Create(2048);
        var builder = new SamlLogoutRequestBuilder(Issuer, NameId, "session-index-abc");

        var url = builder.GetSignedRedirectUrl(SloEndpoint, relayState: null, rsa);

        Assert.StartsWith(SloEndpoint + "?SAMLRequest=", url, StringComparison.Ordinal);
        Assert.Contains("&SigAlg=", url, StringComparison.Ordinal);
        Assert.Contains("&Signature=", url, StringComparison.Ordinal);
        Assert.True(RsaSignatureVerifies(url, rsa));
    }

    [Fact]
    public void GetSignedRedirectUrl_ForeignKey_DoesNotVerify()
    {
        using var signer = RSA.Create(2048);
        using var attacker = RSA.Create(2048);
        var builder = new SamlLogoutRequestBuilder(Issuer, NameId, null);

        var url = builder.GetSignedRedirectUrl(SloEndpoint, relayState: null, signer);

        // The signature check is real, not vacuous: the signer verifies, a different key does not.
        Assert.True(RsaSignatureVerifies(url, signer));
        Assert.False(RsaSignatureVerifies(url, attacker));
    }

    [Fact]
    public void GetSignedRedirectUrl_EcdsaKey_SelectsEcdsaSigAlg_AndVerifies()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var builder = new SamlLogoutRequestBuilder(Issuer, NameId, null);

        var url = builder.GetSignedRedirectUrl(SloEndpoint, relayState: null, ecdsa);

        // The SigAlg is derived from the key type by the shared signer (#493), never SHA-1.
        Assert.Contains("&SigAlg=" + Uri.EscapeDataString(EcdsaSha256), url, StringComparison.Ordinal);
        Assert.True(EcdsaSignatureVerifies(url, ecdsa));
    }

    [Fact]
    public void GetSignedRedirectUrl_NullEndpoint_Throws()
    {
        using var rsa = RSA.Create(2048);
        var builder = new SamlLogoutRequestBuilder(Issuer, NameId, null);

        Assert.Throws<ArgumentNullException>(() => { builder.GetSignedRedirectUrl(null!, null, rsa); });
    }

    // Inflates the DEFLATE+Base64 SAMLRequest back into its XML document, exactly as an identity provider does.
    private static XmlDocument InflateRequest(string encoded)
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

    private static bool RsaSignatureVerifies(string url, RSA publicKey)
        => publicKey.VerifyData(Encoding.UTF8.GetBytes(SignedQuery(url)), Signature(url), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    private static bool EcdsaSignatureVerifies(string url, ECDsa publicKey)
        => publicKey.VerifyData(Encoding.UTF8.GetBytes(SignedQuery(url)), Signature(url), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    // Reconstructs the signed octet string (SAMLRequest, then SigAlg — no RelayState here) from the URL.
    private static string SignedQuery(string url)
    {
        var samlRequest = QueryValue(url, "SAMLRequest");
        var sigAlg = QueryValue(url, "SigAlg");
        return "SAMLRequest=" + Uri.EscapeDataString(samlRequest) + "&SigAlg=" + Uri.EscapeDataString(sigAlg);
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
