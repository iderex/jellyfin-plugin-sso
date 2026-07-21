// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace Jellyfin.Plugin.SSO_Auth.Api.Secrets;

/// <summary>
/// Authenticated envelope encryption for the plugin's at-rest secrets (the OpenID client secret and the
/// SAML signing key). A value is AES-256-GCM encrypted under a plugin-owned data-encryption key and stored
/// as a versioned, self-describing string (<c>ssoenc:v1:base64(nonce|tag|ciphertext)</c>). The version
/// prefix lets encrypted and legacy plaintext values coexist during migration and lets the format evolve
/// without a breaking change; GCM's authentication tag means tampering or a wrong key fails closed rather
/// than returning garbage.
/// </summary>
internal static class SecretEnvelope
{
    private const string Prefix = "ssoenc:v1:";
    private const int KeySize = 32; // AES-256.
    private const int NonceSize = 12; // The nonce size AES-GCM is defined for.
    private const int TagSize = 16; // Full-length GCM authentication tag.

    /// <summary>
    /// Gets the exact length, in bytes, of the data-encryption key this scheme requires.
    /// </summary>
    internal static int KeySizeBytes => KeySize;

    /// <summary>
    /// Determines whether a stored value is an <c>ssoenc:v1</c> envelope (as opposed to a legacy plaintext
    /// secret). This only inspects the prefix; authenticity is checked when the value is decrypted.
    /// </summary>
    /// <param name="value">The stored value.</param>
    /// <returns>True when the value carries the envelope prefix.</returns>
    internal static bool IsProtected([NotNullWhen(true)] string? value)
        => value != null && value.StartsWith(Prefix, StringComparison.Ordinal);

    /// <summary>
    /// Determines whether a value is a structurally well-formed envelope: it carries the prefix and the
    /// remainder is valid Base64 that decodes to at least a nonce and a tag. Used to decide whether a value
    /// is already encrypted (and so encryption should be skipped), so that a plaintext secret that merely
    /// happens to start with the prefix is still encrypted rather than stored verbatim.
    /// </summary>
    /// <param name="value">The stored value.</param>
    /// <returns>True when the value is a structurally valid envelope.</returns>
    internal static bool IsWellFormedEnvelope(string? value)
    {
        if (!IsProtected(value))
        {
            return false;
        }

        try
        {
            return Convert.FromBase64String(value.Substring(Prefix.Length)).Length >= NonceSize + TagSize;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Encrypts a plaintext secret into an <c>ssoenc:v1</c> envelope with a fresh random nonce.
    /// </summary>
    /// <param name="key">The 32-byte data-encryption key.</param>
    /// <param name="plaintext">The secret to protect.</param>
    /// <returns>The encrypted, prefixed, Base64 envelope string.</returns>
    internal static string Protect(byte[] key, string plaintext)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(plaintext);
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"The data-encryption key must be {KeySize} bytes.", nameof(key));
        }

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        // A fresh random nonce per encryption is mandatory: reusing a nonce under one key breaks GCM.
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSize];

        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        }

        var envelope = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, envelope, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, envelope, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, envelope, NonceSize + TagSize, ciphertext.Length);

        return Prefix + Convert.ToBase64String(envelope);
    }

    /// <summary>
    /// Decrypts an <c>ssoenc:v1</c> envelope, verifying its authentication tag.
    /// </summary>
    /// <param name="key">The 32-byte data-encryption key the value was encrypted with.</param>
    /// <param name="value">The envelope string produced by <see cref="Protect"/>.</param>
    /// <returns>The recovered plaintext secret.</returns>
    /// <exception cref="FormatException">The value is not an envelope or is not valid Base64.</exception>
    /// <exception cref="CryptographicException">The tag does not verify (tampering or a wrong key).</exception>
    internal static string Unprotect(byte[] key, string value)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"The data-encryption key must be {KeySize} bytes.", nameof(key));
        }

        if (!IsProtected(value))
        {
            throw new FormatException("The value is not an ssoenc:v1 envelope.");
        }

        var envelope = Convert.FromBase64String(value.Substring(Prefix.Length));
        if (envelope.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("The envelope is truncated.");
        }

        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        var ciphertext = new byte[envelope.Length - NonceSize - TagSize];
        Buffer.BlockCopy(envelope, 0, nonce, 0, NonceSize);
        Buffer.BlockCopy(envelope, NonceSize, tag, 0, TagSize);
        Buffer.BlockCopy(envelope, NonceSize + TagSize, ciphertext, 0, ciphertext.Length);

        var plaintext = new byte[ciphertext.Length];
        using (var aes = new AesGcm(key, TagSize))
        {
            // Throws AuthenticationTagMismatchException (a CryptographicException) if the tag does not
            // verify, so a corrupted value or a wrong key fails closed instead of returning garbage.
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }

        return Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>
    /// Attempts to decrypt an envelope, returning false instead of throwing on any malformed or
    /// unauthentic input.
    /// </summary>
    /// <param name="key">The 32-byte data-encryption key.</param>
    /// <param name="value">The envelope string.</param>
    /// <param name="plaintext">The recovered plaintext when successful; otherwise null.</param>
    /// <returns>True when the value decrypted and its tag verified.</returns>
    internal static bool TryUnprotect(byte[] key, string value, [NotNullWhen(true)] out string? plaintext)
    {
        try
        {
            plaintext = Unprotect(key, value);
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            plaintext = null;
            return false;
        }
    }
}
