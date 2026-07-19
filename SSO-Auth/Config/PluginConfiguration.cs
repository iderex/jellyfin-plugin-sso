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
/// Configuration shared by every SSO provider (OpenID and SAML). Both <see cref="SamlConfig"/> and
/// <see cref="OidConfig"/> inherit these members; the concrete types are what get XML-serialized
/// (SerializableDictionary serializes each value as its concrete type), so inherited members emit the
/// same as declared ones and no <c>[XmlInclude]</c>/polymorphism handling is needed (#204). XML
/// deserialization is by element name, so moving these up — which places them before the
/// provider-specific elements in newly written XML — does not stop existing configs from loading.
/// </summary>
// Model-binding contract for every value-type member here and on the derived SamlConfig/OidConfig
// (the bool flags and the int? PortOverride): the OID/SAML `Add` endpoints (SSOController.OidAdd /
// SamlAdd) and the config-page PUT bind the whole provider object [FromBody] under RequiresElevation
// and REPLACE it wholesale (configuration.OidConfigs[provider] = config), re-injecting only the
// server-managed fields via ServerManagedFields.Preserve. An omitted bool therefore deserializes to
// its default and that default is persisted BY DESIGN — the admin is replacing the object, not
// patching it. This is why the value-type properties stay non-nullable and un-annotated (SonarCloud
// S6964, #196): marking them [JsonRequired] would reject the intended partial post and break the
// write-only-secret / blank-means-keep save flows that deliberately omit fields, while bool? would
// invent an "unset" third state the replace contract does not have. Under-posting here is admin-only
// and crosses no privilege boundary (non-security), so the documented whole-object-replace contract
// is the disposition rather than a per-property annotation.
public abstract class ProviderConfigBase
{
    private SerializableDictionary<string, Guid> _canonicalLinks;

    /// <summary>
    /// Gets or sets the canonical external base URL for this provider, e.g.
    /// <c>https://jellyfin.example.com</c>. When set, the provider's derived external URLs (the OpenID
    /// redirect_uri, or the SAML base and assertion-consumer URL) are built from it instead of the request
    /// <c>Host</c> header (#139), so a spoofed or proxy-forwarded host cannot redirect the login elsewhere.
    /// It overrides the scheme and port overrides. Blank keeps the request-host behavior.
    /// </summary>
    public string BaseUrlOverride { get; set; }

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
    /// login that matches an existing account is rejected rather than taking it over. Settable in the
    /// admin provider form as well as the config XML (#484, #488).
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
    /// Gets or sets a value indicating whether the generic role-to-permission mapping
    /// (<see cref="PermissionRoleMappings"/>) is applied at login (#164). Off by default (fail closed):
    /// a deployment that does not set it sees no change on upgrade, and the extra permission surface is
    /// only ever managed by SSO when an administrator opts in AND lists explicit mappings. Gated
    /// additionally by <see cref="EnableAuthorization"/> at the mint, exactly like the admin/folder/Live TV
    /// grants, so turning RBAC off leaves every permission untouched.
    /// </summary>
    public bool EnablePermissionRoles { get; set; }

    /// <summary>
    /// Gets or sets the generic role-to-permission mappings applied at login when
    /// <see cref="EnablePermissionRoles"/> is on (#164): each entry names a single Jellyfin
    /// <c>PermissionKind</c> and the roles that grant it. The mapping is authoritative and default-deny —
    /// a listed permission is granted only when the login carries a matching role and is otherwise
    /// explicitly revoked, so a missing or unmapped claim never silently grants a permission. Permissions
    /// with their own dedicated configuration (administrator, all-folders, Live TV access/management) are
    /// rejected here so each permission has exactly one authoritative source. A permission not listed at all
    /// is never touched by SSO — Jellyfin's own default governs it. Validated fail-closed on save (an
    /// unknown or dedicated permission name is rejected before it is persisted).
    /// </summary>
    [XmlArray("PermissionRoleMappings")]
    [XmlArrayItem(typeof(PermissionRoleMap), ElementName = "PermissionRoleMappings")]
    public List<PermissionRoleMap> PermissionRoleMappings { get; set; }

    /// <summary>
    /// Gets or sets the authentication provider id written to the user's Jellyfin account
    /// (<c>User.AuthenticationProviderId</c>) after a successful SSO login. This is a Jellyfin-native
    /// user attribute; SSO logins themselves always resolve through the per-provider canonical-link maps,
    /// not this field. Blank leaves the account's existing provider id untouched.
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
    /// Gets or sets a value indicating whether the last non-linking login used the newer redirect path
    /// spelling (the "/start/" form rather than the legacy short form). This is server-managed runtime
    /// state, not an admin-facing setting: every non-linking challenge overwrites it from the incoming
    /// request path so that a later linking flow — which cannot know which redirect path the identity
    /// provider has registered — reuses the same spelling. It is persisted in the config XML for that
    /// reason, not because it is user-configurable.
    /// </summary>
    public bool NewPath { get; set; }

    /// <summary>
    /// Gets or sets a mapping of canonical names from the provider to jellyfin user ids.
    /// </summary>
    // Server-managed (written by logins), not admin-edited: persisted in the config XML but withheld
    // from every JSON response (#157). This stops the account-link map leaking off the server, closes
    // the tear from serializing it while a login writes it, and blocks setting links via a config PUT.
    // Its preservation on save is handled server-side in ServerManagedFields.Preserve.
    [XmlElement("CanonicalLinks")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, Guid> CanonicalLinks
    {
        // Self-healing lazy init: the backing map is created and stored on first access, so a direct
        // `CanonicalLinks[key] = id` persists into the stored map instead of a discarded throwaway.
        // Every access runs under the config lock (ReadConfiguration/MutateConfiguration), so the
        // assignment cannot race; an empty map serializes the same as the old throwaway did.
        get => _canonicalLinks ??= new SerializableDictionary<string, Guid>();
        set => _canonicalLinks = value;
    }
}

/// <summary>
/// The configuration required for a SAML flow.
/// </summary>
// Load-bearing, not copy-paste cruft: this names the element SerializableDictionary.WriteXml persists
// via new XmlSerializer(typeof(TValue)); removing it renames that element and every stored provider
// entry on disk stops deserializing.
[XmlRoot("PluginConfiguration")]
public class SamlConfig : ProviderConfigBase
{
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
    /// Gets or sets an OPTIONAL second identity-provider signing certificate accepted alongside
    /// <see cref="SamlCertificate"/> during an INBOUND (IdP-side) signing-key rotation (#491). A response
    /// is accepted when its signature verifies against EITHER this certificate or the primary, under the
    /// SAME algorithm allowlist (no SHA-1), signature-scope, and fail-closed checks; when blank, the trial
    /// narrows to the primary alone. Note the validity-window check added with this field applies to the
    /// primary too, so an already-EXPIRED primary certificate — which the pre-#491 path still accepted, as
    /// XML-DSig verification ignores certificate dates — is now rejected on upgrade unless a current
    /// certificate is configured (here or promoted into <see cref="SamlCertificate"/>). Unlike
    /// <see cref="SamlSigningKeyPfx"/> and
    /// <see cref="SamlRolloverSigningKeyPfx"/> — the SP's own PRIVATE signing keys — this is the identity
    /// provider's PUBLIC signing certificate, exactly like <see cref="SamlCertificate"/>: it is NOT a
    /// secret, so it carries no write-only/encrypted-at-rest handling and is stored and returned in the
    /// clear. An expired certificate is rejected, so an administrator adds the identity provider's new
    /// certificate here before the cutover and promotes it into <see cref="SamlCertificate"/> (clearing
    /// this field) once the provider has fully rotated — with no login downtime across the overlap window.
    /// </summary>
    public string SamlSecondaryCertificate { get; set; }

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
    /// Gets or sets a value indicating whether the outgoing AuthnRequest is signed with this service
    /// provider's signing key, for identity providers that require signed requests (#167). Opt-in
    /// (default off): with it off the request is sent exactly as before (unsigned), so existing
    /// deployments are unaffected. When on, a valid <see cref="SamlSigningKeyPfx"/> must be configured —
    /// the challenge fails closed (rather than silently sending an unsigned request) if the key is
    /// missing or unloadable.
    /// </summary>
    public bool SignAuthnRequests { get; set; }

    /// <summary>
    /// Gets or sets the service-provider signing key used when <see cref="SignAuthnRequests"/> is on,
    /// as a Base64-encoded, unencrypted PKCS#12 (PFX) blob carrying the certificate and its RSA private
    /// key (#167). Supply the keypair whose public certificate the identity provider is configured to
    /// trust. Treated as a secret: write-only across the JSON boundary (deserialized from a save so it
    /// can be set and rotated, but serialized back as null so the private key never reaches the admin
    /// browser or a config export), and preserved on a save that leaves it blank. It is still persisted
    /// to the config XML.
    /// </summary>
    [System.Text.Json.Serialization.JsonConverter(typeof(WriteOnlySecretConverter))]
    public string SamlSigningKeyPfx { get; set; }

    /// <summary>
    /// Gets or sets an OPTIONAL second service-provider signing key for a zero-downtime rollover of the
    /// SP's own signing certificate (#491, capability 1), as a Base64-encoded, unencrypted PKCS#12 (PFX)
    /// blob in the same shape as <see cref="SamlSigningKeyPfx"/>. It is PUBLISH-ONLY: outgoing
    /// AuthnRequests are always signed with the PRIMARY <see cref="SamlSigningKeyPfx"/>, and this key is
    /// never used to sign. Its purpose is the metadata overlap window — when it is set and
    /// <see cref="SignAuthnRequests"/> is on, the SP metadata advertises BOTH public certificates as two
    /// <c>KeyDescriptor use="signing"</c> entries, so the identity provider accepts the primary's
    /// signature while the administrator stages the swap (publish both, then promote the rollover key
    /// into the primary field, then clear this one). Blank means no overlap: byte-for-byte the pre-#491
    /// single-key, single-KeyDescriptor behavior. It carries the same private key, so it is treated as a
    /// secret exactly like the primary: write-only across the JSON boundary, encrypted at rest (#158),
    /// and preserved on a save that leaves it blank.
    /// </summary>
    [System.Text.Json.Serialization.JsonConverter(typeof(WriteOnlySecretConverter))]
    public string SamlRolloverSigningKeyPfx { get; set; }
}

/// <summary>
/// The configuration required for a OpenID flow.
/// </summary>
// Load-bearing, not copy-paste cruft: this names the element SerializableDictionary.WriteXml persists
// via new XmlSerializer(typeof(TValue)); removing it renames that element and every stored provider
// entry on disk stops deserializing.
[XmlRoot("PluginConfiguration")]
public class OidConfig : ProviderConfigBase
{
    private SerializableDictionary<string, string> _canonicalLinkIssuers;

    /// <summary>
    /// Gets or sets the OpenID well-known information endpoint.
    /// </summary>
    public string OidEndpoint { get; set; }

    /// <summary>
    /// Gets or sets, per canonical link, the discovered issuer the link was minted under (#186). Keyed
    /// by the same stable subject (<c>sub</c>) as <see cref="ProviderConfigBase.CanonicalLinks"/>, the
    /// value is the id_token issuer that asserted that subject when the link was created. At login the
    /// resolved link's stored issuer is compared to the current login's issuer and a mismatch refuses the
    /// login (fail closed), so an admin repointing this provider entry at a DIFFERENT identity provider
    /// (same discovery URL, new issuer) can no longer silently map a new-IdP user whose <c>sub</c>
    /// collides with an old link onto the old user's account. A link that carries no stored issuer (one
    /// minted before this store existed) is stamped with the current issuer on its next successful login
    /// (trust-on-first-use), so existing links keep working while the provider is unchanged and gain the
    /// binding transparently — no userbase lockout on upgrade. OpenID only; SAML is out of scope.
    /// </summary>
    // Server-managed exactly like CanonicalLinks: persisted in the config XML but withheld from every JSON
    // response ([JsonIgnore]) so it cannot be read back or set via a config PUT, self-healing lazy init so
    // a direct index assignment persists, and preserved on save by ServerManagedFields.Preserve (which
    // also CLEARS it, alongside the links, when OidEndpoint changes — the repoint belt, #186).
    [XmlElement("CanonicalLinkIssuers")]
    [System.Text.Json.Serialization.JsonIgnore]
    public SerializableDictionary<string, string> CanonicalLinkIssuers
    {
        get => _canonicalLinkIssuers ??= new SerializableDictionary<string, string>();
        set => _canonicalLinkIssuers = value;
    }

    /// <summary>
    /// Gets or sets OpenID client ID.
    /// </summary>
    public string OidClientId { get; set; }

    /// <summary>
    /// Gets or sets OpenID shared secret.
    /// </summary>
    // Write-only across the JSON boundary (#189): still deserialized from an incoming save (so it
    // can be set and rotated), but serialized back out as null, so the plaintext client secret
    // never reaches the admin browser (HAR, proxy log, shared screen) on a config-page load and
    // cannot be read back via a config GET. It is still persisted to the config XML. On save, a
    // blank incoming value re-injects the live secret (see ServerManagedFields.Preserve),
    // so leaving the field blank keeps the stored secret; a new value replaces it. A plain
    // [JsonIgnore] is wrong here — it is bidirectional and would also drop the value on save.
    [System.Text.Json.Serialization.JsonConverter(typeof(WriteOnlySecretConverter))]
    public string OidSecret { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether adopting a same-named pre-existing account additionally
    /// requires the login to carry <c>email_verified == true</c> (#218). Only meaningful when
    /// <see cref="ProviderConfigBase.AllowExistingAccountLink"/> is on. Off by default (fail closed for
    /// availability, not for the takeover threat): name-based adoption of an administrator account is
    /// always refused regardless of this flag, so the headline takeover is closed without it; this flag
    /// hardens the residual non-admin, name-based adoption. Enabling it needs the <c>email</c> scope so
    /// the provider actually returns <c>email_verified</c>; an absent or false claim then refuses
    /// adoption. Settable in the admin provider form as well as the config XML (#484, #488).
    /// </summary>
    public bool RequireVerifiedEmailForAdoption { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether every OpenID login for this provider must carry
    /// <c>email_verified == true</c> (#166). Off by default (fail closed for availability, not the threat):
    /// a deployment that does not set it — or an identity provider that omits the claim — is unaffected, so
    /// the whole userbase sees no change on upgrade. When on, a login whose <c>email_verified</c> is not
    /// exactly <c>true</c> (absent, false, or unparseable) is refused, so an identity provider that permits
    /// unverified emails cannot be used to sign in. Distinct from <see cref="RequireVerifiedEmailForAdoption"/>,
    /// which only gates same-name account adoption; this gates the login itself, before any account is
    /// resolved. Enabling it needs the <c>email</c> scope so the provider returns <c>email_verified</c>.
    /// Settable in the admin provider form as well as the config XML (#524, #525).
    /// </summary>
    public bool RequireVerifiedEmailForLogin { get; set; }

    /// <summary>
    /// Gets or sets the claim to check roles against. Separated by "."s.
    /// </summary>
    public string RoleClaim { get; set; }

    /// <summary>
    /// Gets or Sets additional Scopes to request access to in the authorization request.
    /// </summary>
    public string[] OidScopes { get; set; }

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
    /// Gets or sets a value indicating whether the RFC 9207 authorization-response <c>iss</c> parameter
    /// is validated against the id_token issuer (an OpenID Connect mix-up defense). Off by default;
    /// enabling it disables the check for a provider whose response <c>iss</c> legitimately differs.
    /// </summary>
    public bool DoNotValidateResponseIssuer { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the UserInfo endpoint is used to get profile data.
    /// </summary>
    public bool DoNotLoadProfile { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the authorization server must advertise PKCE with S256
    /// (in the discovery document's <c>code_challenge_methods_supported</c>) before a login proceeds.
    /// When true, a login is refused if the server does not advertise S256 — fail closed, RFC 9700
    /// §2.1.1. When false (the default), an unsupported server only logs an <c>[SSO Audit]</c> warning
    /// and the login proceeds (PKCE is still sent, but the server may ignore it).
    /// </summary>
    public bool RequirePkce { get; set; }
}

/// <summary>
/// Maps a single provider role to the library folders granted to users who hold that role (RBAC folder access).
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

/// <summary>
/// Maps a single Jellyfin permission (by its <c>PermissionKind</c> name) to the roles that grant it,
/// for the generic role-to-permission RBAC mapping (#164). The permission name is validated fail-closed
/// on save; at login the permission is granted only when a matching role is present and otherwise
/// explicitly revoked (default-deny).
/// </summary>
public class PermissionRoleMap
{
    /// <summary>
    /// Gets or sets the Jellyfin permission this mapping grants, as the exact <c>PermissionKind</c>
    /// enum name (e.g. <c>EnableContentDownloading</c>). An unknown name, or one of the dedicated
    /// permissions managed elsewhere (administrator, all-folders, Live TV), is rejected on save.
    /// </summary>
    public string Permission { get; set; }

    /// <summary>
    /// Gets or sets the roles that grant the permission. A login holding any of these roles is granted
    /// the permission; a login holding none has it explicitly revoked.
    /// </summary>
    public string[] Roles { get; set; }
}
