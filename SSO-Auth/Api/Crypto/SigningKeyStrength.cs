// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Crypto;

/// <summary>
/// The one home for the plugin's minimum asymmetric signing-key policy (#733), referenced by both protocol
/// paths — the OpenID <c>id_token</c> JWKS conversion and the SAML certificate verification — so the two can
/// never drift apart. The floor follows NIST SP 800-131A and OWASP ASVS 5.0 V11: RSA signing keys must be at
/// least 2048 bits, and EC keys must use one of the approved NIST P-curves. A weaker key is skipped/rejected
/// fail-closed at signature verification (and rejected at the admin write path), never trusted.
/// </summary>
internal static class SigningKeyStrength
{
    /// <summary>
    /// The minimum RSA signing-key size, in bits (NIST SP 800-131A / ASVS 5.0 V11). Below this, an id_token
    /// or SAML signature is not trusted regardless of algorithm — weak keys are as forgeable as weak hashes.
    /// </summary>
    internal const int MinimumRsaKeyBits = 2048;

    /// <summary>Whether an RSA key of the given bit size meets the minimum floor.</summary>
    /// <param name="keySizeBits">The RSA key size in bits.</param>
    /// <returns><see langword="true"/> when the key is at least <see cref="MinimumRsaKeyBits"/> bits.</returns>
    internal static bool IsAcceptableRsaKeySize(int keySizeBits) => keySizeBits >= MinimumRsaKeyBits;

    /// <summary>
    /// Whether an elliptic-curve public key's curve OID is one of the approved NIST P-curves (P-256, P-384,
    /// P-521) — the same set the OpenID JWK converter constrains EC keys to.
    /// </summary>
    /// <param name="curveOid">The dotted OID value of the EC named curve, or null when unknown.</param>
    /// <returns><see langword="true"/> when the curve is P-256, P-384, or P-521.</returns>
    internal static bool IsApprovedEcCurveOid(string? curveOid) =>
        curveOid is "1.2.840.10045.3.1.7" // P-256 (prime256v1 / nistP256)
                 or "1.3.132.0.34" // P-384 (nistP384)
                 or "1.3.132.0.35";         // P-521 (nistP521)
}
