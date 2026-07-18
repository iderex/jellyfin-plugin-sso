using System;
using System.IO;
using System.Security.Cryptography;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Owns the plugin's data-encryption key (DEK) and turns config secrets into (and back out of) at-rest
/// <see cref="SecretEnvelope"/> envelopes. The key lives in a dedicated file in the plugin's data folder -
/// the same volume the admin must already persist for configuration to survive - kept separate from the
/// config XML so a leaked config alone cannot decrypt anything. The key is created once (only when a secret
/// is first encrypted) and never rolled automatically. Two failure modes fail closed rather than orphaning
/// every previously-encrypted secret: a wrong-length (corrupt) key file is rejected, and revealing an
/// encrypted value when the key file is <b>missing</b> throws instead of silently generating a new key.
/// </summary>
internal sealed class SecretStore
{
    private readonly string _keyFilePath;
    private readonly object _lock = new object();
    private byte[] _cachedKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretStore"/> class.
    /// </summary>
    /// <param name="keyFilePath">Absolute path of the file that holds (or will hold) the DEK.</param>
    internal SecretStore(string keyFilePath)
    {
        _keyFilePath = keyFilePath;
    }

    /// <summary>
    /// Returns the data-encryption key, generating and persisting a fresh one on first use. Used only when
    /// encrypting a value (there is no key yet on a first run).
    /// </summary>
    /// <returns>The 32-byte data-encryption key.</returns>
    /// <exception cref="CryptographicException">The key file exists but is not the expected length.</exception>
    internal byte[] GetOrCreateKey()
    {
        lock (_lock)
        {
            if (_cachedKey != null)
            {
                return _cachedKey;
            }

            if (File.Exists(_keyFilePath))
            {
                return LoadKeyLocked();
            }

            return CreateKeyLocked();
        }
    }

    /// <summary>
    /// Encrypts a plaintext secret for storage. An empty value or an already-encrypted value is returned
    /// unchanged, so the method is safe to apply to a whole config on every save.
    /// </summary>
    /// <param name="storedValue">The secret as currently held.</param>
    /// <returns>The value in encrypted-at-rest form.</returns>
    internal string Protect(string storedValue)
    {
        // Skip only a genuinely-encrypted value (idempotency); a plaintext that merely starts with the
        // envelope prefix is not a well-formed envelope and is still encrypted here rather than stored raw.
        if (string.IsNullOrEmpty(storedValue) || SecretEnvelope.IsWellFormedEnvelope(storedValue))
        {
            return storedValue;
        }

        return SecretEnvelope.Protect(GetOrCreateKey(), storedValue);
    }

    /// <summary>
    /// Recovers the plaintext for a stored secret: decrypts an envelope, or passes through a legacy
    /// plaintext (or empty) value unchanged. Revealing an envelope requires the key file to exist; if it is
    /// missing the call fails closed rather than generating a replacement key.
    /// </summary>
    /// <param name="storedValue">The secret as read from configuration.</param>
    /// <returns>The plaintext secret.</returns>
    /// <exception cref="CryptographicException">The key file is missing/corrupt, or the value did not decrypt.</exception>
    internal string Reveal(string storedValue)
    {
        if (string.IsNullOrEmpty(storedValue) || !SecretEnvelope.IsProtected(storedValue))
        {
            return storedValue;
        }

        return SecretEnvelope.Unprotect(GetKey(), storedValue);
    }

    // Reads the existing key without ever creating one. Fails closed when the file is missing: reaching here
    // means we were asked to decrypt an already-encrypted value, so a missing key was lost (not absent on a
    // first run), and regenerating it would orphan every secret.
    private byte[] GetKey()
    {
        lock (_lock)
        {
            if (_cachedKey != null)
            {
                return _cachedKey;
            }

            if (!File.Exists(_keyFilePath))
            {
                throw new CryptographicException(
                    $"The SSO secret key file '{_keyFilePath}' is missing while encrypted secrets are present. Restore it from a backup - do not delete it or let it be regenerated, or every encrypted secret becomes permanently unrecoverable.");
            }

            return LoadKeyLocked();
        }
    }

    private byte[] LoadKeyLocked()
    {
        var existing = File.ReadAllBytes(_keyFilePath);
        if (existing.Length != SecretEnvelope.KeySizeBytes)
        {
            throw new CryptographicException(
                $"The SSO secret key file '{_keyFilePath}' is corrupt (unexpected length). Restore it from a backup - do not delete it, or every encrypted secret becomes unrecoverable.");
        }

        _cachedKey = existing;
        return _cachedKey;
    }

    private byte[] CreateKeyLocked()
    {
        var key = RandomNumberGenerator.GetBytes(SecretEnvelope.KeySizeBytes);
        var directory = Path.GetDirectoryName(_keyFilePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // Write to a temp file, then move it into place. The two-argument File.Move fails if the target
        // already exists, so a concurrent writer (another process/instance sharing the volume) that won the
        // race cannot be clobbered - we discard our key and adopt theirs instead. This also makes the write
        // atomic: a crash mid-write leaves the temp file, never a truncated key file.
        var tempPath = _keyFilePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllBytes(tempPath, key);
        TryRestrictToOwner(tempPath);

        try
        {
            File.Move(tempPath, _keyFilePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(tempPath);
            return LoadKeyLocked();
        }

        _cachedKey = key;
        return _cachedKey;
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort.
        }
    }

    private static void TryRestrictToOwner(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            // NTFS inherits ACLs from the (already access-controlled) Jellyfin data directory; there is
            // no portable owner-only chmod equivalent to apply here without pulling in Windows ACL APIs.
            return;
        }

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            // Best effort: the key is still separated from the config, so a failure to tighten the mode is
            // not fatal.
        }
    }
}
