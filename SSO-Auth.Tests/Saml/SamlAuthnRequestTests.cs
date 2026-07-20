using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlAuthnRequest"/>'s two redirect builders (#167): the unsigned
/// <see cref="SamlAuthnRequest.GetRedirectUrl"/> stays exactly as before (no signature parameters), and the
/// opt-in <see cref="SamlAuthnRequest.GetSignedRedirectUrl"/> carries a verifiable HTTP-Redirect binding
/// signature over the same DEFLATE/Base64 request.
/// </summary>
public class SamlAuthnRequestTests
{
    private const string Endpoint = "https://idp.example.com/sso";

    [Fact]
    public void GetRedirectUrl_Unsigned_CarriesNoSignatureParameters()
    {
        var request = new SamlAuthnRequest("jellyfin-sp", "https://jellyfin.example.com/sso/SAML/p/adfs");

        var url = request.GetRedirectUrl(Endpoint, relayState: null);

        Assert.Contains("SAMLRequest=", url);
        Assert.DoesNotContain("SigAlg=", url);
        Assert.DoesNotContain("Signature=", url);
    }

    [Fact]
    public void GetSignedRedirectUrl_CarriesAVerifiableSignatureOverTheRequest()
    {
        var request = new SamlAuthnRequest("jellyfin-sp", "https://jellyfin.example.com/sso/SAML/p/adfs");
        using var certificate = SamlSigningKeyFactory.CreateCertificate();
        using var privateKey = certificate.GetRSAPrivateKey()!;

        var url = request.GetSignedRedirectUrl(Endpoint, relayState: null, privateKey);

        Assert.Contains("SAMLRequest=", url);
        Assert.Contains("SigAlg=", url);
        Assert.Contains("Signature=", url);

        using var publicKey = certificate.GetRSAPublicKey()!;
        Assert.True(SignatureVerifies(url, publicKey));
    }

    [Fact]
    public void GetSignedRedirectUrl_EcdsaKey_CarriesAVerifiableEcdsaSignature()
    {
        var request = new SamlAuthnRequest("jellyfin-sp", "https://jellyfin.example.com/sso/SAML/p/adfs");
        using var certificate = SamlSigningKeyFactory.CreateEcdsaCertificate();
        using var privateKey = certificate.GetECDsaPrivateKey()!;

        var url = request.GetSignedRedirectUrl(Endpoint, relayState: null, privateKey);

        Assert.Contains("SigAlg=" + Uri.EscapeDataString("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"), url);
        using var publicKey = certificate.GetECDsaPublicKey()!;
        Assert.True(EcdsaSignatureVerifies(url, publicKey));
    }

    [Fact]
    public void GetSignedRedirectUrl_NullEndpoint_Throws()
    {
        var request = new SamlAuthnRequest("jellyfin-sp", "https://jellyfin.example.com/sso/SAML/p/adfs");
        using var certificate = SamlSigningKeyFactory.CreateCertificate();
        using var privateKey = certificate.GetRSAPrivateKey()!;

        Assert.Throws<ArgumentNullException>(() => { request.GetSignedRedirectUrl(null!, null, privateKey); });
    }

    private static bool SignatureVerifies(string url, RSA publicKey)
    {
        var samlRequest = QueryValue(url, "SAMLRequest");
        var sigAlg = QueryValue(url, "SigAlg");
        var signature = Convert.FromBase64String(QueryValue(url, "Signature"));

        var signedQuery = "SAMLRequest=" + Uri.EscapeDataString(samlRequest) + "&SigAlg=" + Uri.EscapeDataString(sigAlg);
        return publicKey.VerifyData(Encoding.UTF8.GetBytes(signedQuery), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static bool EcdsaSignatureVerifies(string url, ECDsa publicKey)
    {
        var samlRequest = QueryValue(url, "SAMLRequest");
        var sigAlg = QueryValue(url, "SigAlg");
        var signature = Convert.FromBase64String(QueryValue(url, "Signature"));

        var signedQuery = "SAMLRequest=" + Uri.EscapeDataString(samlRequest) + "&SigAlg=" + Uri.EscapeDataString(sigAlg);
        return publicKey.VerifyData(Encoding.UTF8.GetBytes(signedQuery), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

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
