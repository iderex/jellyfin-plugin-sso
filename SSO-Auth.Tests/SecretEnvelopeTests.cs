using System;
using System.Security.Cryptography;
using Jellyfin.Plugin.SSO_Auth.Api;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Coverage for the at-rest secret envelope: it must round-trip, use a fresh nonce each time, and fail
/// closed (throw / return false) on tampering, a wrong key, or a non-envelope value.
/// </summary>
public class SecretEnvelopeTests
{
    private static byte[] NewKey() => RandomNumberGenerator.GetBytes(SecretEnvelope.KeySizeBytes);

    [Fact]
    public void ProtectThenUnprotect_RoundTrips()
    {
        var key = NewKey();

        var protectedValue = SecretEnvelope.Protect(key, "super-secret-client-secret");

        Assert.True(SecretEnvelope.IsProtected(protectedValue));
        Assert.Equal("super-secret-client-secret", SecretEnvelope.Unprotect(key, protectedValue));
    }

    [Fact]
    public void ProtectThenUnprotect_EmptyString_RoundTrips()
    {
        var key = NewKey();

        var protectedValue = SecretEnvelope.Protect(key, string.Empty);

        Assert.Equal(string.Empty, SecretEnvelope.Unprotect(key, protectedValue));
    }

    [Fact]
    public void Protect_IsNonDeterministic_FreshNoncePerCall()
    {
        var key = NewKey();

        var first = SecretEnvelope.Protect(key, "same-input");
        var second = SecretEnvelope.Protect(key, "same-input");

        // A fresh random nonce per encryption means the two envelopes differ even for identical input.
        Assert.NotEqual(first, second);
        Assert.Equal("same-input", SecretEnvelope.Unprotect(key, first));
        Assert.Equal("same-input", SecretEnvelope.Unprotect(key, second));
    }

    [Fact]
    public void IsProtected_DistinguishesEnvelopeFromPlaintext()
    {
        var key = NewKey();

        Assert.True(SecretEnvelope.IsProtected(SecretEnvelope.Protect(key, "x")));
        Assert.False(SecretEnvelope.IsProtected("just-a-plaintext-secret"));
        Assert.False(SecretEnvelope.IsProtected(null));
    }

    [Fact]
    public void Unprotect_WrongKey_ThrowsAndFailsClosed()
    {
        var protectedValue = SecretEnvelope.Protect(NewKey(), "secret");

        // AuthenticationTagMismatchException derives from CryptographicException; either is fail-closed.
        Assert.ThrowsAny<CryptographicException>(() => SecretEnvelope.Unprotect(NewKey(), protectedValue));
    }

    [Fact]
    public void IsWellFormedEnvelope_DistinguishesRealEnvelopeFromPrefixedPlaintext()
    {
        Assert.True(SecretEnvelope.IsWellFormedEnvelope(SecretEnvelope.Protect(NewKey(), "x")));

        // Carries the prefix but is not a real envelope: invalid Base64, or valid Base64 that is too short.
        Assert.False(SecretEnvelope.IsWellFormedEnvelope("ssoenc:v1:this is not base64!!"));
        Assert.False(SecretEnvelope.IsWellFormedEnvelope("ssoenc:v1:AAAA"));
        Assert.False(SecretEnvelope.IsWellFormedEnvelope("a-normal-plaintext-secret"));
        Assert.False(SecretEnvelope.IsWellFormedEnvelope(null));
    }

    [Fact]
    public void Unprotect_TamperedCiphertext_Throws()
    {
        var key = NewKey();
        var protectedValue = SecretEnvelope.Protect(key, "secret");

        const string prefix = "ssoenc:v1:";
        var envelope = Convert.FromBase64String(protectedValue.Substring(prefix.Length));
        envelope[^1] ^= 0xFF; // Flip a byte in the ciphertext/tag region.
        var tampered = prefix + Convert.ToBase64String(envelope);

        Assert.ThrowsAny<CryptographicException>(() => SecretEnvelope.Unprotect(key, tampered));
    }

    [Fact]
    public void TryUnprotect_WrongKey_ReturnsFalse()
    {
        var protectedValue = SecretEnvelope.Protect(NewKey(), "secret");

        Assert.False(SecretEnvelope.TryUnprotect(NewKey(), protectedValue, out var plaintext));
        Assert.Null(plaintext);
    }

    [Fact]
    public void TryUnprotect_ValidEnvelope_ReturnsTrue()
    {
        var key = NewKey();
        var protectedValue = SecretEnvelope.Protect(key, "secret");

        Assert.True(SecretEnvelope.TryUnprotect(key, protectedValue, out var plaintext));
        Assert.Equal("secret", plaintext);
    }

    [Fact]
    public void Unprotect_PlaintextValue_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => SecretEnvelope.Unprotect(NewKey(), "not-an-envelope"));
    }

    [Fact]
    public void Protect_WrongKeySize_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => SecretEnvelope.Protect(new byte[16], "secret"));
    }
}
