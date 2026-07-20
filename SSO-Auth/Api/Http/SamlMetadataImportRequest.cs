#nullable enable

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// The request body for the SAML metadata-import endpoint (#735): exactly one of a metadata <see cref="Url"/>
/// (fetched server-side, SSRF-hardened) or pasted metadata <see cref="Xml"/>. Both null/blank, or both set,
/// is rejected.
/// </summary>
public sealed class SamlMetadataImportRequest
{
    /// <summary>Gets or sets the IdP metadata URL to fetch, or null when pasting XML.</summary>
    public string? Url { get; set; }

    /// <summary>Gets or sets the pasted IdP metadata XML, or null when fetching a URL.</summary>
    public string? Xml { get; set; }
}
