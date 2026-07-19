using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlRedirectSigner"/> (#167): the HTTP-Redirect binding detached signature over the
/// URL-encoded query string. The signature is verified empirically against the signer's public key over the
/// exact octets it must cover (SAMLRequest, then RelayState when present, then SigAlg), and the algorithm is
/// pinned to the shared allowlist so no SHA-1 downgrade can slip in.
/// </summary>
public class SamlRedirectSignerTests
{
    private const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private const string EcdsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    private const string RsaSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    private const string Endpoint = "https://idp.example.com/sso";
    private const string Message = "deflated+base64==/message";

    [Fact]
    public void BuildSignedRedirectUrl_EmitsSigAlgAndSignature()
    {
        using var rsa = RSA.Create(2048);

        var url = SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, relayState: null, rsa);

        Assert.StartsWith(Endpoint + "?SAMLRequest=", url);
        Assert.Contains("&SigAlg=" + Uri.EscapeDataString(RsaSha256), url);
        Assert.Contains("&Signature=", url);
    }

    [Fact]
    public void BuildSignedRedirectUrl_SignatureVerifiesOverTheExactQueryOctets_NoRelayState()
    {
        using var rsa = RSA.Create(2048);

        var url = SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, relayState: null, rsa);

        AssertSignatureVerifies(url, rsa, expectedRelayState: null);
    }

    [Fact]
    public void BuildSignedRedirectUrl_IncludesRelayStateInOrder_AndSignatureCoversIt()
    {
        using var rsa = RSA.Create(2048);

        var url = SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, relayState: "linking", rsa);

        // RelayState sits between SAMLRequest and SigAlg, the SAML Bindings 3.4.4.1 order.
        var samlRequestIndex = url.IndexOf("SAMLRequest=", StringComparison.Ordinal);
        var relayStateIndex = url.IndexOf("RelayState=", StringComparison.Ordinal);
        var sigAlgIndex = url.IndexOf("SigAlg=", StringComparison.Ordinal);
        Assert.True(samlRequestIndex < relayStateIndex && relayStateIndex < sigAlgIndex);
        AssertSignatureVerifies(url, rsa, expectedRelayState: "linking");
    }

    [Fact]
    public void BuildSignedRedirectUrl_EmptyRelayState_IsOmitted()
    {
        using var rsa = RSA.Create(2048);

        var url = SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, relayState: string.Empty, rsa);

        Assert.DoesNotContain("RelayState=", url);
    }

    [Fact]
    public void BuildSignedRedirectUrl_EndpointWithQuery_UsesAmpersandSeparator()
    {
        using var rsa = RSA.Create(2048);

        var url = SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint + "?realm=corp", "SAMLRequest", Message, relayState: null, rsa);

        Assert.StartsWith(Endpoint + "?realm=corp&SAMLRequest=", url);
    }

    [Fact]
    public void BuildSignedRedirectUrl_ForeignKey_DoesNotVerify()
    {
        using var signer = RSA.Create(2048);
        using var attacker = RSA.Create(2048);

        var url = SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, relayState: null, signer);

        // Sanity: a different key must not validate the signature — the check is real, not vacuous.
        Assert.True(SignatureVerifies(url, signer, expectedRelayState: null));
        Assert.False(SignatureVerifies(url, attacker, expectedRelayState: null));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void BuildSignedRedirectUrl_BlankEndpoint_Throws(string? endpoint)
    {
        using var rsa = RSA.Create(2048);
        Assert.Throws<ArgumentException>(() => { SamlRedirectSigner.BuildSignedRedirectUrl(endpoint!, "SAMLRequest", Message, null, rsa); });
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void BuildSignedRedirectUrl_BlankMessage_Throws(string? message)
    {
        using var rsa = RSA.Create(2048);
        Assert.Throws<ArgumentException>(() => { SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", message!, null, rsa); });
    }

    [Fact]
    public void BuildSignedRedirectUrl_NullKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => { SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, null, null!); });
    }

    [Fact]
    public void BuildSignedRedirectUrl_EcdsaKey_EmitsEcdsaSigAlg_AndSignatureVerifiesOverTheOctets()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var url = SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, relayState: "linking", ecdsa);

        // An ECDSA key selects ecdsa-sha256 (#493), on the same allowlist, never SHA-1.
        Assert.Contains("&SigAlg=" + Uri.EscapeDataString(EcdsaSha256), url);
        Assert.True(SamlSignatureAlgorithms.IsSignatureMethodAllowed(EcdsaSha256));
        Assert.True(EcdsaSignatureVerifies(url, ecdsa, expectedRelayState: "linking"));
    }

    [Fact]
    public void BuildSignedRedirectUrl_EcdsaKey_ForeignKey_DoesNotVerify()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var url = SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, relayState: null, signer);

        Assert.True(EcdsaSignatureVerifies(url, signer, expectedRelayState: null));
        Assert.False(EcdsaSignatureVerifies(url, attacker, expectedRelayState: null));
    }

    [Fact]
    public void BuildSignedRedirectUrl_EcdsaCertificateFromPkcs12_RoundTripsThroughTheLoader()
    {
        // The full production path: an ECDSA PKCS#12 loads, the key type is detected, and the emitted
        // signature verifies against the certificate's ECDSA public key with SigAlg=ecdsa-sha256.
        Assert.True(SamlSigningKey.TryLoad(SamlSigningKeyFactory.CreateEcdsaPfxBase64(), out var certificate));
        using (certificate)
        using (var signingKey = SamlSigningKey.GetSigningKey(certificate))
        {
            Assert.NotNull(signingKey);

            var url = SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, relayState: null, signingKey);

            Assert.Contains("&SigAlg=" + Uri.EscapeDataString(EcdsaSha256), url);
            using var publicKey = certificate.GetECDsaPublicKey()!;
            Assert.True(EcdsaSignatureVerifies(url, publicKey, expectedRelayState: null));
        }
    }

    [Fact]
    public void BuildSignedRedirectUrl_UnsupportedKeyType_ThrowsRatherThanSigningUnknown()
    {
        // A key that is neither RSA nor ECDSA is rejected, never silently left unsigned or signed weakly.
        using var dsa = DSA.Create();

        Assert.Throws<InvalidOperationException>(
            () => { SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, relayState: null, dsa); });
    }

    [Fact]
    public void SignatureAlgorithm_IsOnTheInboundAllowlist_AndIsNotSha1()
    {
        using var rsa = RSA.Create(2048);
        var url = SamlRedirectSigner.BuildSignedRedirectUrl(Endpoint, "SAMLRequest", Message, relayState: null, rsa);

        var sigAlg = ExtractQueryValue(url, "SigAlg");

        // The outgoing signer must reuse the inbound response-validator's allowlist, and never SHA-1.
        Assert.True(SamlSignatureAlgorithms.IsSignatureMethodAllowed(sigAlg));
        Assert.False(SamlSignatureAlgorithms.IsSignatureMethodAllowed(RsaSha1));
        Assert.NotEqual(RsaSha1, sigAlg);
    }

    // Reconstructs the exact signed octet string (SAMLRequest[, RelayState], SigAlg — in order, URL-encoded)
    // from the emitted URL and verifies the Signature parameter against the public key, exactly as an
    // identity provider would.
    private static void AssertSignatureVerifies(string url, RSA publicKey, string? expectedRelayState)
        => Assert.True(SignatureVerifies(url, publicKey, expectedRelayState));

    private static bool SignatureVerifies(string url, RSA publicKey, string? expectedRelayState)
    {
        var samlRequest = ExtractQueryValue(url, "SAMLRequest");
        var sigAlg = ExtractQueryValue(url, "SigAlg");
        var signature = Convert.FromBase64String(ExtractQueryValue(url, "Signature"));

        var signedQuery = "SAMLRequest=" + Uri.EscapeDataString(samlRequest);
        if (!string.IsNullOrEmpty(expectedRelayState))
        {
            signedQuery += "&RelayState=" + Uri.EscapeDataString(expectedRelayState);
        }

        signedQuery += "&SigAlg=" + Uri.EscapeDataString(sigAlg);

        return publicKey.VerifyData(Encoding.UTF8.GetBytes(signedQuery), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    // The ECDSA counterpart of SignatureVerifies: the XML-DSig ecdsa-sha256 signature value is the raw
    // IEEE P1363 r||s concatenation the signer emits, so verification must use the same format.
    private static bool EcdsaSignatureVerifies(string url, ECDsa publicKey, string? expectedRelayState)
    {
        var samlRequest = ExtractQueryValue(url, "SAMLRequest");
        var sigAlg = ExtractQueryValue(url, "SigAlg");
        var signature = Convert.FromBase64String(ExtractQueryValue(url, "Signature"));

        var signedQuery = "SAMLRequest=" + Uri.EscapeDataString(samlRequest);
        if (!string.IsNullOrEmpty(expectedRelayState))
        {
            signedQuery += "&RelayState=" + Uri.EscapeDataString(expectedRelayState);
        }

        signedQuery += "&SigAlg=" + Uri.EscapeDataString(sigAlg);

        return publicKey.VerifyData(Encoding.UTF8.GetBytes(signedQuery), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static string ExtractQueryValue(string url, string name)
    {
        var query = url[(url.IndexOf('?') + 1)..];
        foreach (var pair in query.Split('&'))
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
