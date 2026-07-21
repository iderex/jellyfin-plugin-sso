// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Security.Cryptography;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Secrets;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Coverage for the data-encryption-key file lifecycle and the protect/reveal helpers that migrate config
/// secrets to and from at-rest envelopes.
/// </summary>
public class SecretStoreTests
{
    private static void WithTempKeyPath(Action<string> test)
    {
        var path = Path.Combine(Path.GetTempPath(), "sso-key-test-" + Guid.NewGuid().ToString("N") + ".key");
        try
        {
            test(path);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void GetOrCreateKey_CreatesAndPersistsAStableKey()
    {
        WithTempKeyPath(path =>
        {
            var store = new SecretStore(path);

            var key = store.GetOrCreateKey();

            Assert.Equal(SecretEnvelope.KeySizeBytes, key.Length);
            Assert.True(File.Exists(path));
            Assert.Equal(key, store.GetOrCreateKey()); // cached, same instance value
            Assert.Equal(key, new SecretStore(path).GetOrCreateKey()); // persisted, read back by a fresh store
        });
    }

    [Fact]
    public void GetOrCreateKey_CorruptKeyFile_FailsClosed()
    {
        WithTempKeyPath(path =>
        {
            File.WriteAllBytes(path, new byte[10]); // wrong length

            Assert.Throws<CryptographicException>(() => new SecretStore(path).GetOrCreateKey());
        });
    }

    [Fact]
    public void Reveal_EncryptedValue_MissingKeyFile_FailsClosedWithoutRegenerating()
    {
        WithTempKeyPath(path =>
        {
            var protectedValue = new SecretStore(path).Protect("client-secret"); // creates the key + encrypts
            Assert.True(File.Exists(path));

            File.Delete(path); // the key file was lost (e.g. restored config but not the key)

            var store = new SecretStore(path);
            Assert.Throws<CryptographicException>(() => store.Reveal(protectedValue));

            // Must NOT have silently regenerated the key - that would orphan every encrypted secret.
            Assert.False(File.Exists(path));
        });
    }

    [Fact]
    public void Protect_ConfigHasEnvelopes_MissingKeyFile_RefusesToMintAndFailsClosed()
    {
        WithTempKeyPath(path =>
        {
            var store = new SecretStore(path); // no key file exists

            // A well-formed envelope is present in the config but the key was lost: minting a fresh key would
            // orphan that envelope (and mask the loss), so encrypting must fail closed instead.
            Assert.Throws<CryptographicException>(() => store.Protect("new-plaintext", configHasEnvelopes: true));

            Assert.False(File.Exists(path)); // no replacement key minted
        });
    }

    [Fact]
    public void Protect_CleanInstall_NoEnvelopes_MintsKeyAndEncrypts()
    {
        WithTempKeyPath(path =>
        {
            var store = new SecretStore(path); // no key file exists

            var protectedValue = store.Protect("client-secret", configHasEnvelopes: false);

            Assert.True(File.Exists(path)); // first run legitimately mints the key
            Assert.True(SecretEnvelope.IsProtected(protectedValue));
            Assert.Equal("client-secret", store.Reveal(protectedValue));
        });
    }

    [Fact]
    public void CreateKey_KeyFile_IsOwnerOnlyOnUnix()
    {
        WithTempKeyPath(path =>
        {
            new SecretStore(path).GetOrCreateKey();

            Assert.True(File.Exists(path));

            // The temp file is created with the restrictive mode atomically and File.Move preserves it, so the
            // persisted key file is owner-only with no permissive window. The mode call is a no-op on Windows.
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            }
        });
    }

    [Fact]
    public void Protect_PlaintextStartingWithTheEnvelopePrefix_IsStillEncrypted()
    {
        WithTempKeyPath(path =>
        {
            var store = new SecretStore(path);
            const string tricky = "ssoenc:v1:this looks like an envelope but is plaintext";

            var protectedValue = store.Protect(tricky);

            Assert.NotEqual(tricky, protectedValue);
            Assert.True(SecretEnvelope.IsWellFormedEnvelope(protectedValue));
            Assert.Equal(tricky, store.Reveal(protectedValue));
        });
    }

    [Fact]
    public void Reveal_LegacyPlaintext_MissingKeyFile_ReturnsUnchangedAndNeverCreatesKey()
    {
        WithTempKeyPath(path =>
        {
            var store = new SecretStore(path); // no key file exists

            Assert.Equal("legacy-plaintext", store.Reveal("legacy-plaintext"));
            Assert.False(File.Exists(path)); // revealing a non-envelope value never touches the key
        });
    }

    [Fact]
    public void ProtectThenReveal_RoundTrips()
    {
        WithTempKeyPath(path =>
        {
            var store = new SecretStore(path);

            var protectedValue = store.Protect("client-secret");

            Assert.True(SecretEnvelope.IsProtected(protectedValue));
            Assert.Equal("client-secret", store.Reveal(protectedValue));
        });
    }

    [Fact]
    public void Protect_AlreadyEncrypted_IsIdempotent()
    {
        WithTempKeyPath(path =>
        {
            var store = new SecretStore(path);
            var once = store.Protect("client-secret");

            Assert.Equal(once, store.Protect(once));
        });
    }

    [Fact]
    public void Reveal_LegacyPlaintext_ReturnsUnchanged()
    {
        WithTempKeyPath(path =>
        {
            var store = new SecretStore(path);

            Assert.Equal("legacy-plaintext", store.Reveal("legacy-plaintext"));
        });
    }

    [Fact]
    public void ProtectAndReveal_EmptyOrNull_PassThrough()
    {
        WithTempKeyPath(path =>
        {
            var store = new SecretStore(path);

            Assert.Equal(string.Empty, store.Protect(string.Empty));
            Assert.Null(store.Protect(null));
            Assert.Equal(string.Empty, store.Reveal(string.Empty));
            Assert.Null(store.Reveal(null));
        });
    }
}
