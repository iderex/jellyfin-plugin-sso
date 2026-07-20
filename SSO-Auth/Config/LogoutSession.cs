using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// The per-session state a Single Logout needs, captured at login and discarded once the session ends
/// (#727, prerequisite #154). Persisted (server-managed, never over the JSON boundary) so an RP-initiated
/// OpenID logout can present a real <c>id_token_hint</c>, and an inbound SAML <c>LogoutRequest</c> can be
/// matched to the session it terminates, even across a server restart.
/// </summary>
/// <remarks>
/// A plain XML-serializable class (public parameterless ctor + get/set) because it is stored as the value of
/// a <see cref="SerializableDictionary{TKey,TValue}"/> on <see cref="PluginConfiguration"/>, exactly like
/// <see cref="OidConfig"/>/<see cref="SamlConfig"/>. <see cref="IdToken"/> is a bearer secret: it is encrypted
/// at rest (the <c>ssoenc:</c> envelope, via ConfigSecretProtection) and withheld from every JSON response
/// with the enclosing map, so it never reaches the admin browser or a config export.
/// </remarks>
public class LogoutSession
{
    /// <summary>
    /// Gets or sets the protocol that minted the session — <c>"OID"</c> or <c>"SAML"</c> (the audit-protocol
    /// spelling), selecting which logout mechanism applies.
    /// </summary>
    public string Protocol { get; set; }

    /// <summary>
    /// Gets or sets the provider name (its config-dictionary key) the session was authenticated through.
    /// </summary>
    public string Provider { get; set; }

    /// <summary>
    /// Gets or sets the stable subject (the OpenID <c>sub</c> claim or the SAML <c>NameID</c>) the inbound
    /// SAML <c>LogoutRequest</c> path matches on.
    /// </summary>
    public string Subject { get; set; }

    /// <summary>
    /// Gets or sets the identity-provider session identifier (the OpenID <c>sid</c> claim or the SAML
    /// <c>SessionIndex</c>), when the provider issued one; otherwise blank.
    /// </summary>
    public string SessionIndex { get; set; }

    /// <summary>
    /// Gets or sets the id_token issuer (the <c>iss</c> claim) the logout URL is host-bound to, so an
    /// RP-initiated logout can only be built against the discovered authority (OpenID only).
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    /// Gets or sets the raw OpenID <c>id_token</c> used as the <c>id_token_hint</c> for an RP-initiated
    /// logout (OpenID only; blank for SAML). A bearer secret: encrypted at rest and never returned over JSON.
    /// </summary>
    // Defense in depth: the enclosing LogoutSessions map is already [JsonIgnore], so this never reaches a
    // JSON response today; the field-level ignore additionally guarantees that a LogoutSession serialized
    // DIRECTLY (a future debug/admin endpoint) still cannot leak the id_token — a freshly captured token is
    // plaintext in memory until the next persist, so the belt-and-suspenders matters. XML persistence is
    // unaffected (XmlSerializer ignores this attribute), so the encrypted token still round-trips to disk.
    [System.Text.Json.Serialization.JsonIgnore]
    public string IdToken { get; set; }

    /// <summary>
    /// Gets or sets the Jellyfin user id whose tokens a logout revokes.
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Gets or sets the UTC ticks at which the session was captured, used to bound the store (oldest entries
    /// are evicted first) and to expire stale entries.
    /// </summary>
    public long CapturedUtcTicks { get; set; }
}
