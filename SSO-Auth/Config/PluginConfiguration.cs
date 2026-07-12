using System;
using System.Collections.Generic;
using System.Xml.Serialization;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Plugin Configuration.
/// </summary>
public class PluginConfiguration : MediaBrowser.Model.Plugins.BasePluginConfiguration
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PluginConfiguration"/> class.
    /// </summary>
    public PluginConfiguration()
    {
        SamlConfigs = new SerializableDictionary<string, SamlConfig>();
        OidConfigs = new SerializableDictionary<string, OidConfig>();
        RateLimitMaxAttempts = 30;
        RateLimitWindowSeconds = 60;
    }

    /// <summary>
    /// Gets or sets the SAML configurations available.
    /// </summary>
    [XmlElement("SamlConfigs")]
    public SerializableDictionary<string, SamlConfig> SamlConfigs { get; set; }

    /// <summary>
    /// Gets or sets the OpenID configurations available.
    /// </summary>
    [XmlElement("OidConfigs")]
    public SerializableDictionary<string, OidConfig> OidConfigs { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the anonymous SSO flow endpoints are rate-limited
    /// per client address (best-effort, in-process). Opt-in (default off). The limiter keys on the
    /// connection's remote address only. CAUTION: behind a reverse proxy, first configure
    /// Jellyfin's own "Known proxies" networking setting so the server resolves the real client
    /// from the forwarded headers — without it every client shares the proxy's address and one
    /// abuser throttles logins for everyone; in that case leave this off. Refs #128.
    /// </summary>
    public bool EnableRateLimit { get; set; }

    /// <summary>
    /// Gets or sets how many hits per window a client may make against the anonymous SSO endpoints
    /// before being throttled with 429. One login is several hits (challenge, callback,
    /// authentication), so keep this generous; the default is 30. A value below 1 disables the
    /// limiter (it never means "block everything").
    /// </summary>
    public int RateLimitMaxAttempts { get; set; }

    /// <summary>
    /// Gets or sets the rate-limit window length in seconds. The default is 60.
    /// </summary>
    public int RateLimitWindowSeconds { get; set; }
}

/// <summary>
/// The configuration required for a SAML flow.
/// </summary>
[XmlRoot("PluginConfiguration")]
public class SamlConfig
{
    private SerializableDictionary<string, Guid> _canonicalLinks;

    /// <summary>
    /// Gets or sets the SAML information endpoint.
    /// </summary>
    public string SamlEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the SAML provider's client ID.
    /// </summary>
    public string SamlClientId { get; set; }

    /// <summary>
    /// Gets or sets the SAML public key.
    /// </summary>
    public string SamlCertificate { get; set; }

    /// <summary>
    /// Gets or sets the audience (SP entity id) that a SAML response must be addressed to. When
    /// unset, the SamlClientId is used. Ignored when <see cref="DoNotValidateAudience"/> is set.
    /// </summary>
    public string SamlAudience { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to skip validating the assertion's AudienceRestriction.
    /// Off by default: responses must be addressed to this service provider (fail closed). Only enable
    /// for a provider that cannot emit a matching AudienceRestriction.
    /// </summary>
    public bool DoNotValidateAudience { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to bind the assertion to this service provider's
    /// assertion-consumer URL by validating the bearer SubjectConfirmationData Recipient (and the
    /// Response Destination when present) against it. Opt-in (default off): enable it once the
    /// identity provider is confirmed to emit a Recipient matching the configured ACS URL. Refs #156.
    /// </summary>
    public bool ValidateRecipient { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to accept only solicited responses, by correlating the
    /// assertion's InResponseTo against an AuthnRequest this server issued. Opt-in (default off):
    /// enabling it rejects IdP-initiated (unsolicited) SSO, which carries no InResponseTo. Refs #156.
    /// </summary>
    public bool ValidateInResponseTo { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the provider is enabled.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is enabled.
    /// </summary>
    public bool EnableAuthorization { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an SSO login may adopt a pre-existing, unlinked
    /// Jellyfin account whose username matches the SSO name. Off by default (fail closed): a first
    /// login that matches an existing account is rejected rather than taking it over.
    /// </summary>
    public bool AllowExistingAccountLink { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether all folders are allowed by default.
    /// </summary>
    public bool EnableAllFolders { get; set; }

    /// <summary>
    /// Gets or sets what folders should users have access to by default.
    /// </summary>
    public string[] EnabledFolders { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is an administrator.
    /// </summary>
    public string[] AdminRoles { get; set; }

    /// <summary>
    /// Gets or sets what roles are checked to determine whether the user is allowed to use Jellyfin.
    /// </summary>
    public string[] Roles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is used to manage folder access.
    /// </summary>
    public bool EnableFolderRoles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is used to manage Live TV access.
    /// </summary>
    public bool EnableLiveTvRoles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Live TV is enabled by default.
    /// </summary>
    public bool EnableLiveTv { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Live TV is allowed to be managed by default.
    /// </summary>
    public bool EnableLiveTvManagement { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is allowed to view Live TV.
    /// </summary>
    public string[] LiveTvRoles { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is allowed to manage Live TV.
    /// </summary>
    public string[] LiveTvManagementRoles { get; set; }

    /// <summary>
    /// Gets or sets which folders map to what roles in RBAC.
    /// </summary>
    [XmlArray("FolderRoleMappings")]
    [XmlArrayItem(typeof(FolderRoleMap), ElementName = "FolderRoleMappings")]
    public List<FolderRoleMap> FolderRoleMapping { get; set; }

    /// <summary>
    /// Gets or sets the default provider the user after logging in with SSO.
    /// </summary>
    public string DefaultProvider { get; set; }

    /// <summary>
    /// Gets or sets the redirect scheme override.
    /// </summary>
    public string SchemeOverride { get; set; }

    /// <summary>
    /// Gets or sets the redirect port override.
    /// </summary>
    public int? PortOverride { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the new, more descriptive paths are to be used.
    /// </summary>
    public bool NewPath { get; set; }

    /// <summary>
    /// Gets or sets a mapping of canonical names from the provider to jellyfin user ids.
    /// </summary>
    // Server-managed (written by logins), not admin-edited: persisted in the config XML but withheld
    // from every JSON response (#157). This stops the account-link map leaking off the server, closes
    // the tear from serializing it while a login writes it, and blocks setting links via a config PUT.
    // Its preservation on save is handled server-side in SSOPlugin.PreserveServerManagedFields.
    [XmlElement("CanonicalLinks")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, Guid> CanonicalLinks
    {
        get
        {
            if (_canonicalLinks == null)
            {
                return new SerializableDictionary<string, Guid>();
            }

            return _canonicalLinks;
        }
        set => _canonicalLinks = value;
    }
}

/// <summary>
/// The configuration required for a OpenID flow.
/// </summary>
[XmlRoot("PluginConfiguration")]
public class OidConfig
{
    private SerializableDictionary<string, Guid> _canonicalLinks;

    /// <summary>
    /// Gets or sets the OpenID well-known information endpoint.
    /// </summary>
    public string OidEndpoint { get; set; }

    /// <summary>
    /// Gets or sets OpenID client ID.
    /// </summary>
    public string OidClientId { get; set; }

    /// <summary>
    /// Gets or sets OpenID shared secret.
    /// </summary>
    public string OidSecret { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the provider is enabled.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is enabled.
    /// </summary>
    public bool EnableAuthorization { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an SSO login may adopt a pre-existing, unlinked
    /// Jellyfin account whose username matches the SSO name. Off by default (fail closed): a first
    /// login that matches an existing account is rejected rather than taking it over.
    /// </summary>
    public bool AllowExistingAccountLink { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether all folders are allowed by default.
    /// </summary>
    public bool EnableAllFolders { get; set; }

    /// <summary>
    /// Gets or sets what folders should users have access to by default.
    /// </summary>
    public string[] EnabledFolders { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is an administrator.
    /// </summary>
    public string[] AdminRoles { get; set; }

    /// <summary>
    /// Gets or sets what roles are checked to determine whether the user is allowed to use Jellyfin.
    /// </summary>
    public string[] Roles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is used to manage folder access.
    /// </summary>
    public bool EnableFolderRoles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether RBAC is used to manage Live TV access.
    /// </summary>
    public bool EnableLiveTvRoles { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Live TV is enabled by default.
    /// </summary>
    public bool EnableLiveTv { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether Live TV is allowed to be managed by default.
    /// </summary>
    public bool EnableLiveTvManagement { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is allowed to view Live TV.
    /// </summary>
    public string[] LiveTvRoles { get; set; }

    /// <summary>
    /// Gets or sets the roles that are checked to determine whether the user is allowed to manage Live TV.
    /// </summary>
    public string[] LiveTvManagementRoles { get; set; }

    /// <summary>
    /// Gets or sets which folders map to what roles in RBAC.
    /// </summary>
    [XmlArray("FolderRoleMappings")]
    [XmlArrayItem(typeof(FolderRoleMap), ElementName = "FolderRoleMappings")]
    public List<FolderRoleMap> FolderRoleMapping { get; set; }

    /// <summary>
    /// Gets or sets the claim to check roles against. Separated by "."s.
    /// </summary>
    public string RoleClaim { get; set; }

    /// <summary>
    /// Gets or Sets additional Scopes to request access to in the authorization request.
    /// </summary>
    public string[] OidScopes { get; set; }

    /// <summary>
    /// Gets or sets the default provider the user after logging in with SSO.
    /// </summary>
    public string DefaultProvider { get; set; }

    /// <summary>
    /// Gets or sets the redirect scheme override.
    /// </summary>
    public string SchemeOverride { get; set; }

    /// <summary>
    /// Gets or sets the redirect port override.
    /// </summary>
    public int? PortOverride { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the new, more descriptive paths are to be used.
    /// </summary>
    public bool NewPath { get; set; }

    /// <summary>
    /// Gets or sets a mapping of canonical names from the provider to jellyfin user ids.
    /// </summary>
    // Server-managed (written by logins), not admin-edited: persisted in the config XML but withheld
    // from every JSON response (#157). This stops the account-link map leaking off the server, closes
    // the tear from serializing it while a login writes it, and blocks setting links via a config PUT.
    // Its preservation on save is handled server-side in SSOPlugin.PreserveServerManagedFields.
    [XmlElement("CanonicalLinks")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, Guid> CanonicalLinks
    {
        get
        {
            if (_canonicalLinks == null)
            {
                return new SerializableDictionary<string, Guid>();
            }

            return _canonicalLinks;
        }
        set => _canonicalLinks = value;
    }

    /// <summary>
    /// Gets or sets the default username claim when creating new accounts.
    /// </summary>
    public string DefaultUsernameClaim { get; set; }

    /// <summary>
    /// Gets or sets the URL format of the new user avatar.
    /// </summary>
    public string AvatarUrlFormat { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether HTTPS in the discovery endpoint is required.
    /// </summary>
    public bool DisableHttps { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether pushed authorization is required.
    /// </summary>
    public bool DisablePushedAuthorization { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the OpenID endpoints are validated.
    /// </summary>
    public bool DoNotValidateEndpoints { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the OpenID issuer name is validated.
    /// </summary>
    public bool DoNotValidateIssuerName { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the UserInfo endpoint is used to get profile data.
    /// </summary>
    public bool DoNotLoadProfile { get; set; }
}

/// <summary>
/// The OpenID client ID.
/// </summary>
public class FolderRoleMap
{
    /// <summary>
    /// Gets or sets the role of the mapping.
    /// </summary>
    public string Role { get; set; }

    /// <summary>
    /// Gets or sets the folders that are allowed from the given role.
    /// </summary>
    public List<string> Folders { get; set; }
}
