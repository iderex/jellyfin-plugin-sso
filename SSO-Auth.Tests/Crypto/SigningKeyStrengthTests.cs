// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Crypto;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SigningKeyStrength"/> — the shared minimum signing-key policy (#733). RSA keys must
/// be at least 2048 bits and EC keys must sit on an approved NIST P-curve; the same floor gates both the
/// OpenID id_token JWKS path and the SAML certificate path so they cannot drift.
/// </summary>
public class SigningKeyStrengthTests
{
    [Theory]
    [InlineData(2048, true)] // the floor
    [InlineData(3072, true)]
    [InlineData(4096, true)]
    [InlineData(2047, false)] // one bit under the floor
    [InlineData(1024, false)] // the classic weak key
    [InlineData(512, false)]
    [InlineData(0, false)]
    public void IsAcceptableRsaKeySize_EnforcesThe2048BitFloor(int keySizeBits, bool expected)
        => Assert.Equal(expected, SigningKeyStrength.IsAcceptableRsaKeySize(keySizeBits));

    [Fact]
    public void MinimumRsaKeyBits_IsPinnedTo2048()
        // NIST SP 800-131A / OWASP ASVS 5.0 V11. Pinned so a weakening of the floor is a conscious, reviewed
        // change rather than a silent drift.
        => Assert.Equal(2048, SigningKeyStrength.MinimumRsaKeyBits);

    [Theory]
    [InlineData("1.2.840.10045.3.1.7", true)] // P-256
    [InlineData("1.3.132.0.34", true)] // P-384
    [InlineData("1.3.132.0.35", true)] // P-521
    [InlineData("1.3.132.0.10", false)] // secp256k1 — not an approved NIST P-curve
    [InlineData("1.3.36.3.3.2.8.1.1.7", false)] // brainpoolP256r1
    [InlineData(null, false)] // an explicit/unknown curve exposes no OID
    [InlineData("", false)]
    public void IsApprovedEcCurveOid_AcceptsOnlyTheNistPCurves(string? curveOid, bool expected)
        => Assert.Equal(expected, SigningKeyStrength.IsApprovedEcCurveOid(curveOid));
}
