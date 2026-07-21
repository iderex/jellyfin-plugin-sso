// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using MediaBrowser.Model.Cryptography;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// A minimal real <see cref="ICryptoProvider"/> for tests. NSubstitute cannot proxy the
/// <c>ReadOnlySpan&lt;char&gt;</c> overloads (a ref struct cannot cross a dynamic-proxy boundary), so the
/// account-provisioning path — which hashes a random password — needs a concrete implementation. The
/// values are inert; no test asserts on the produced hash.
/// </summary>
internal sealed class FakeCryptoProvider : ICryptoProvider
{
    public string DefaultHashMethod => "PBKDF2-SHA512";

    public PasswordHash CreatePasswordHash(ReadOnlySpan<char> password) =>
        new PasswordHash(DefaultHashMethod, Array.Empty<byte>());

    public bool Verify(PasswordHash hash, ReadOnlySpan<char> password) => true;

    public byte[] GenerateSalt() => Array.Empty<byte>();

    public byte[] GenerateSalt(int length) => new byte[length];
}
