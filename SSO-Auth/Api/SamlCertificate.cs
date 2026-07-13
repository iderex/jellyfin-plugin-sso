using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Validates the per-provider SAML signing certificate (#206). A non-blank but unloadable
/// <c>SamlCertificate</c> makes the <see cref="SamlResponse"/> constructor throw on every callback
/// (<see cref="FormatException"/> on non-base64, <see cref="CryptographicException"/> on bytes that are
/// not a certificate), which escaped as an unhandled HTTP 500. Rejecting an invalid certificate at every
/// admin write path — and treating it as a parse failure at login — keeps that fail-closed and out of the
/// 500 path.
/// </summary>
internal static class SamlCertificate
{
    /// <summary>
    /// Whether a certificate value is set but is not a loadable X.509 certificate. Blank is valid (a
    /// half-configured provider; the login then fails closed for lack of a certificate rather than being
    /// blocked from saving).
    /// </summary>
    /// <param name="certificateStr">The Base64-encoded (DER) certificate string.</param>
    /// <returns><see langword="true"/> if the value is set but not a loadable certificate.</returns>
    internal static bool IsInvalid(string certificateStr)
    {
        if (string.IsNullOrWhiteSpace(certificateStr))
        {
            return false;
        }

        try
        {
            using var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificateStr));
            return false;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            return true;
        }
    }
}
