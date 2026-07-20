# Privacy & data handling

What personal data this plugin touches, why, and where it lives — written for
the **self-hosting operator**, who is the GDPR **data controller** for their
Jellyfin server. This document exists so an operator can meet their own
transparency (Art. 13/14) and records-of-processing (Art. 30) duties.

**Scope honesty:** this plugin is a self-hosted, single-tenant component. The
project — its code, its repository, its CI — is **not a processor**, and I have
**no access of any kind** to any deployment's data. Nothing the plugin
processes ever leaves the operator's server except the operator's own traffic
to their chosen identity provider. This document does **not** claim GDPR
compliance on the operator's behalf — it supports the operator's compliance.

## Data inventory

| Data element                                                                         | Category                                  | Purpose                                                              | Where it lives                                                                                                                   | Retention                                                                                                                   |
| ------------------------------------------------------------------------------------ | ----------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| IdP subject identifier (`sub` / SAML `NameID`), with the OpenID issuer bound to it   | Pseudonymous identifier (GDPR Recital 26) | Stable account linking — maps the IdP identity to a Jellyfin user id | Plugin configuration (`SSO-Auth.xml` in the Jellyfin config directory), as a canonical link keyed per provider                   | Until unlinked (self-service linking page or admin), the link is revoked, or the operator removes it from the configuration |
| Jellyfin user id (GUID)                                                              | Pseudonymous identifier                   | The Jellyfin-side half of each link                                  | Plugin configuration (as above); also appears in **log lines** for login events                                                  | Links: as above. Logs: per the operator's Jellyfin log retention                                                            |
| Username / `preferred_username` / `name` claims                                      | Identity data                             | Account provisioning and display-name selection at login             | Transient during login; the resulting username is stored by **Jellyfin's own user store** (Jellyfin is then the store of record) | Transient in the plugin; in Jellyfin until the operator deletes the user                                                    |
| Email claim (if the IdP sends it)                                                    | Identity data                             | Available to identity resolution during login                        | Transient during login only — the plugin does not persist it                                                                     | Request-scoped                                                                                                              |
| Role / group claims                                                                  | Authorization data                        | Mapped to Jellyfin permissions (login, admin, folders, Live TV)      | Transient during login; the **resulting permissions** are stored by Jellyfin                                                     | Transient in the plugin; permissions in Jellyfin until changed                                                              |
| Avatar image (if avatar sync is enabled for a provider)                              | Identity data                             | Profile-image sync from the IdP                                      | Fetched from the IdP (SSRF-guarded) and stored as the user's **Jellyfin profile image**                                          | In Jellyfin until replaced/removed; disable per provider to avoid it                                                        |
| Client IP address                                                                    | Network identifier                        | Rate-limiting of the anonymous SSO endpoints (opt-in feature)        | **In-memory only** (rate-limit buckets); never persisted by the plugin                                                           | Evicted with the rate-limit window; gone on restart                                                                         |
| Login flow state (state, nonce, one-time outcome tokens, SAML request/replay caches) | Protocol data                             | CSRF/replay protection and flow integrity                            | In-memory only, single-use, short-lived                                                                                          | Minutes (single-use, expiring)                                                                                              |
| OpenID client secret / SAML signing keys                                             | Operator secrets (not personal data)      | Provider authentication                                              | Plugin configuration, AES-256-GCM-encrypted at rest (`ssoenc:v1:`) with a separate key file                                      | Until the operator changes them                                                                                             |

## Data minimization

- The plugin persists **only** the subject-keyed link (plus the bound issuer)
  — no email, no display name, no claims are stored by the plugin itself.
- **Avatar sync is per-provider** — leave it off and no image is fetched.
- Role/group claims can be scoped at the IdP: send only the groups the mapping
  actually uses.
- The IdP consent screen (where supported) is the right place to make the data
  flow visible to end users; the plugin only ever sees what the IdP releases.

## Data-subject rights (operator runbook)

- **Access / erasure of the link:** the self-service linking page
  (`/SSOViews/linking`) shows and removes a user's own links; an admin can
  remove any link. Erasing the Jellyfin account itself is a Jellyfin-core
  operation. A dedicated export path for link data is tracked in
  [#760](https://github.com/iderex/jellyfin-plugin-sso/issues/760).
- **Everything else the login produced** (username, permissions, avatar) lives
  in Jellyfin's own user store and follows Jellyfin's user deletion.
- **Logs** follow the operator's Jellyfin log rotation/retention.

## Third parties

The only external party in the flow is the **operator's own identity
provider**. The plugin makes no telemetry, update-check, or analytics calls of
any kind.
