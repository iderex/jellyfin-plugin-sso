using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Unit tests for <see cref="SamlSignatureAlgorithms"/> — the XML-DSig algorithm allowlist that
/// rejects weak/legacy primitives (A-3). Uses the standard XML-DSig algorithm identifier URIs.
/// </summary>
public class SamlSignatureAlgorithmsTests
{
    private const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private const string RsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    private const string EcdsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    private const string EcdsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    private const string RsaSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    private const string EcdsaSha1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";

    private const string DigestSha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    private const string DigestSha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    private const string DigestSha512 = "http://www.w3.org/2001/04/xmlenc#sha512";
    private const string DigestSha1 = "http://www.w3.org/2000/09/xmldsig#sha1";

    [Fact]
    public void IsAllowed_RsaSha256WithSha256Digest_ReturnsTrue()
    {
        Assert.True(SamlSignatureAlgorithms.IsAllowed(RsaSha256, new[] { DigestSha256 }));
    }

    [Fact]
    public void IsAllowed_StrongerVariants_ReturnTrue()
    {
        Assert.True(SamlSignatureAlgorithms.IsAllowed(RsaSha512, new[] { DigestSha512 }));
        Assert.True(SamlSignatureAlgorithms.IsAllowed(EcdsaSha384, new[] { DigestSha384 }));
    }

    [Fact]
    public void IsAllowed_RsaSha1Signature_ReturnsFalse()
    {
        Assert.False(SamlSignatureAlgorithms.IsAllowed(RsaSha1, new[] { DigestSha256 }));
    }

    [Fact]
    public void IsAllowed_Sha1Digest_ReturnsFalse()
    {
        Assert.False(SamlSignatureAlgorithms.IsAllowed(RsaSha256, new[] { DigestSha1 }));
    }

    [Fact]
    public void IsAllowed_OneWeakDigestAmongStrong_ReturnsFalse()
    {
        // A single weak digest anywhere in the reference set poisons the whole response.
        Assert.False(SamlSignatureAlgorithms.IsAllowed(RsaSha256, new[] { DigestSha256, DigestSha1 }));
    }

    [Fact]
    public void IsAllowed_NullSignatureMethod_ReturnsFalse()
    {
        Assert.False(SamlSignatureAlgorithms.IsAllowed(null!, new[] { DigestSha256 }));
    }

    [Fact]
    public void IsAllowed_NullDigestEnumerable_ReturnsFalse()
    {
        Assert.False(SamlSignatureAlgorithms.IsAllowed(RsaSha256, null!));
    }

    [Fact]
    public void IsAllowed_NoReferences_ReturnsFalse()
    {
        // No digest to vouch for anything -> fail closed.
        Assert.False(SamlSignatureAlgorithms.IsAllowed(RsaSha256, new List<string>()));
    }

    [Fact]
    public void IsAllowed_NullDigestValue_ReturnsFalse()
    {
        Assert.False(SamlSignatureAlgorithms.IsAllowed(RsaSha256, new string?[] { null }));
    }

    [Fact]
    public void IsAllowed_UnknownSignatureMethod_ReturnsFalse()
    {
        Assert.False(SamlSignatureAlgorithms.IsAllowed("urn:made:up", new[] { DigestSha256 }));
    }

    [Fact]
    public void IsAllowed_DisallowedSignatureWithNullDigests_ReturnsFalseWithoutThrowing()
    {
        // The signature method is checked first and short-circuits, so a disallowed signature with a
        // null digest enumerable fails closed rather than dereferencing the null (#395).
        Assert.False(SamlSignatureAlgorithms.IsAllowed("urn:made:up", null!));
    }

    // --- Signature-method allowlist shared with the outgoing-request signer (#167) ---

    [Theory]
    [InlineData(RsaSha256)]
    [InlineData(RsaSha512)]
    [InlineData(EcdsaSha256)] // the algorithm the outgoing ECDSA signer emits (#493)
    [InlineData(EcdsaSha384)]
    public void IsSignatureMethodAllowed_StrongMethods_ReturnTrue(string method)
    {
        Assert.True(SamlSignatureAlgorithms.IsSignatureMethodAllowed(method));
    }

    [Theory]
    [InlineData(RsaSha1)]
    [InlineData(EcdsaSha1)] // no SHA-1 variant is admitted, ECDSA included (#493)
    [InlineData("urn:made:up")]
    [InlineData(null)]
    public void IsSignatureMethodAllowed_WeakOrUnknownOrNull_ReturnFalse(string? method)
    {
        Assert.False(SamlSignatureAlgorithms.IsSignatureMethodAllowed(method!));
    }

    // --- Canonicalization allowlist (#137) ---

    private const string ExcC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string InclusiveC14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    private const string ExcC14nWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
    private const string InclusiveC14nWithComments = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    private const string EnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    [Theory]
    [InlineData(ExcC14n)]
    [InlineData(InclusiveC14n)]
    public void IsCanonicalizationAllowed_CommentFreeC14n_ReturnsTrue(string method)
    {
        Assert.True(SamlSignatureAlgorithms.IsCanonicalizationAllowed(method));
    }

    [Theory]
    [InlineData(ExcC14nWithComments)]
    [InlineData(InclusiveC14nWithComments)]
    [InlineData("urn:made:up")]
    [InlineData(null)]
    public void IsCanonicalizationAllowed_WithCommentsOrUnknown_ReturnsFalse(string? method)
    {
        // Comment-preserving c14n breaks "sign what is seen", so it is rejected.
        Assert.False(SamlSignatureAlgorithms.IsCanonicalizationAllowed(method!));
    }

    [Fact]
    public void AreTransformsAllowed_EnvelopedThenC14n_ReturnsTrue()
    {
        Assert.True(SamlSignatureAlgorithms.AreTransformsAllowed(new[] { EnvelopedSignature, ExcC14n }));
    }

    [Fact]
    public void AreTransformsAllowed_EnvelopedOnly_ReturnsTrue()
    {
        Assert.True(SamlSignatureAlgorithms.AreTransformsAllowed(new[] { EnvelopedSignature }));
    }

    [Fact]
    public void AreTransformsAllowed_WithCommentsTransform_ReturnsFalse()
    {
        Assert.False(SamlSignatureAlgorithms.AreTransformsAllowed(new[] { EnvelopedSignature, ExcC14nWithComments }));
    }

    [Fact]
    public void AreTransformsAllowed_UnknownTransform_ReturnsFalse()
    {
        // An XPath/XSLT filter transform is a wrapping lever — reject the whole chain.
        Assert.False(SamlSignatureAlgorithms.AreTransformsAllowed(new[] { EnvelopedSignature, "http://www.w3.org/TR/1999/REC-xslt-19991116" }));
    }

    [Fact]
    public void AreTransformsAllowed_Empty_ReturnsFalse()
    {
        Assert.False(SamlSignatureAlgorithms.AreTransformsAllowed(new List<string>()));
    }

    [Fact]
    public void AreTransformsAllowed_Null_ReturnsFalse()
    {
        Assert.False(SamlSignatureAlgorithms.AreTransformsAllowed(null!));
    }
}
