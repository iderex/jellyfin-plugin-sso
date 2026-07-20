#nullable enable

using System;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>
/// The values extracted from an identity provider's SAML metadata (#735): the IdP entity id, the Single
/// Sign-On endpoint URL (→ <c>SamlEndpoint</c>), and the signing certificate(s) (→ <c>SamlCertificate</c>
/// plus an optional <c>SamlSecondaryCertificate</c> for a rollover overlap). The importer only ever
/// PRE-FILLS; the admin reviews and saves through the normal validated write path.
/// <para>
/// <see cref="EntityId"/> is the IDENTITY PROVIDER's own <c>entityID</c> (the issuer of its assertions), NOT
/// the plugin's <c>SamlClientId</c> — that field is the SERVICE PROVIDER's own entity id (sent as the
/// AuthnRequest issuer and used as the expected audience), which the admin sets and the IdP does not supply.
/// The entity id is surfaced for the admin's reference only; it is deliberately not mapped onto
/// <c>SamlClientId</c>, which would break the issuer/audience semantics.
/// </para>
/// </summary>
/// <param name="EntityId">The IdP's <c>entityID</c> (its assertion issuer), for reference — not the SP <c>SamlClientId</c>.</param>
/// <param name="Endpoint">The <c>SingleSignOnService</c> Location the browser is redirected to (→ <c>SamlEndpoint</c>).</param>
/// <param name="PrimaryCertificate">The primary Base64 (DER) signing certificate (→ <c>SamlCertificate</c>).</param>
/// <param name="SecondaryCertificate">The optional secondary signing certificate (→ <c>SamlSecondaryCertificate</c>), or null.</param>
internal sealed record SamlMetadataImport(
    string EntityId,
    string Endpoint,
    string PrimaryCertificate,
    string? SecondaryCertificate);

/// <summary>
/// Thrown when SAML metadata cannot be parsed into a usable provider configuration (#735) — malformed or
/// oversized XML, a prohibited DOCTYPE/DTD, a missing <c>IDPSSODescriptor</c>/entityID/endpoint, or no usable
/// signing certificate. The message is admin-facing and free of internal detail; the import applies nothing
/// on failure (never a partial result).
/// </summary>
internal sealed class SamlMetadataException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SamlMetadataException"/> class with an admin-facing
    /// message.
    /// </summary>
    /// <param name="message">The admin-facing failure message, free of internal detail.</param>
    internal SamlMetadataException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlMetadataException"/> class wrapping the underlying
    /// parse failure.
    /// </summary>
    /// <param name="message">The admin-facing failure message, free of internal detail.</param>
    /// <param name="innerException">The underlying exception that caused the failure.</param>
    internal SamlMetadataException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
