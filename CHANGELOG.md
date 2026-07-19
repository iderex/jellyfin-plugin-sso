# Changelog

All notable changes to this plugin are documented here. Versions are three-part
`X.Y.Z` as described in the release policy — **X** a breaking / Jellyfin-ABI
change, **Y** a feature, **Z** a bug-fix or security patch (the two share the
digit and differ by release cadence). The channel and Jellyfin generation are a
suffix on the git tag and GitHub release name only (`-stable`, `-beta.<run>`,
`-JF12-*`), never part of the installed numeric version.

## 4.2.1

A bug-fix release.

### Fixed

- **Admin-or-self authorization now denies explicitly on a null auth context
  (#626).** `RequestHelpers.AssertCanUpdateUser` previously failed closed by
  throwing a `NullReferenceException` (which could surface as a 500) on a null
  or ambiguous authorization context. It now returns an explicit `false` — a
  clean, total deny. Normal authenticated requests are unaffected; the fix
  removes a fragile reliance on an exception for a security-critical denial and
  eliminates the internal-error surface. A masked test that had tolerated the
  old exception was corrected to assert the explicit deny.

## 4.2.0

A breaking release.

### Removed

- **`SAML/Auth` no longer accepts a raw SAML assertion (BREAKING, #528).** #251
  replaced the assertion browser round-trip with a one-time, server-side login
  outcome token: the assertion-consumer callback (`SAML/post`) validates the
  signed assertion once and hands the intermediate page only an opaque token,
  and `SAML/Auth` redeems that token to mint the session without re-parsing the
  assertion. For one release `SAML/Auth` also still accepted and fully
  re-validated the pre-#251 shape — a full base64 assertion POSTed straight to
  it — so a login already in flight during an upgrade would not break. That
  deprecation window has now closed: `SAML/Auth` accepts **only** the opaque
  outcome token. A scripted client that POSTs a raw assertion straight to
  `SAML/Auth`, bypassing the rendered page, is now rejected fail-closed (a clean
  400 in the uniform SAML body, nothing minted). The normal browser login and
  linking flows are unaffected — the plugin has rendered only tokens for login
  since #251. Callers that scripted the legacy direct-assertion POST must switch
  to the callback-plus-token round-trip.

## 4.1.1

A bug-fix release that restores plugin loading on Jellyfin 10.11. No
configuration changes.

### Fixed

- **The plugin no longer fails to load on Jellyfin 10.11 (#590).** 4.1.0.0
  shipped with `Duende.IdentityModel.OidcClient` 7.x, whose assemblies are built
  against the .NET 10 framework and reference
  `Microsoft.Extensions.Logging.Abstractions` 10.0.0.0 in their manifest — an
  assembly the host provides (Jellyfin 10.11 runs on .NET 9 and ships 9.0.0.0)
  and the plugin therefore does not bundle. Because .NET rolls a host assembly
  reference forward to a newer host but never down a major version, the packaged
  plugin threw `FileNotFoundException` the moment the host constructed it, and
  the server disabled it at startup — taking down every OpenID and SAML login.
  `dotnet build` and `dotnet test` stayed green because they run against the full
  publish output, which contains the 10.x assembly; the failure only surfaced on
  a real host, the same blind spot the SAML/OIDC crypto DLLs hit in 4.1.0.0.

  The OIDC client is pinned back to the 6.x line, which references
  `Logging.Abstractions` 8.0.0.0 and rolls forward onto the host's 9.0.0.0
  cleanly; the whole dependency graph stays on the .NET 9 ABI. No behaviour
  changes — the OpenID and SAML flows are identical to 4.1.0.0.

### Added

- **A conformance test locks the ABI floor in.**
  `ArchitectureConformanceTests.HostProvidedFrameworkAssemblies_StayOnTheHostNet9Abi`
  fails the build if any host-provided `Microsoft.Extensions.*` assembly is
  referenced above the .NET 9 host ABI, so a future dependency bump that
  re-crosses the floor is caught before release instead of in the field.

## 4.1.0

The first feature release of the revived plugin. It folds in a full
security-parity pass over the SAML and OpenID login path, encrypts provider
secrets at rest, adds outgoing SAML request signing, exposes the previously
config-only provider flags in the admin UI, and lands a large internal rework
that decomposes the login controller into small, testable services.

### Breaking

- **Provider secrets are now encrypted at rest (#158).** Client secrets and
  signing keys are stored as an AES-256-GCM envelope (`ssoenc:` values) instead
  of plaintext. **Upgrading is transparent** — an existing plaintext config is
  read as-is and re-encrypted on the next save, no action required.
  **Downgrading is breaking:** an older plugin build cannot read `ssoenc:`
  values. Before rolling back, open each provider on the settings page and
  re-enter its secret in plaintext (or restore the pre-upgrade config backup),
  then install the older build. See
  [Secrets encrypted at rest and downgrade](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#secrets-encrypted-at-rest-and-downgrade).
- **OpenID logins that relied on legacy username matching are refused until you
  migrate (#358).** Links created by 4.0.0.4 and earlier are keyed on the
  username, which the IdP controls. After upgrade, a login carrying such a
  legacy link is not followed automatically — the account is adopted only when
  the provider has `AllowExistingAccountLink` enabled (treat this as a short,
  supervised maintenance window, not a standing setting), or when an admin links
  the account explicitly via `AddCanonicalLink`. A returning administrator with
  a pre-existing legacy link must be linked by an admin; self-migration is
  refused for admins even with the flag on. Plan this before upgrading — see the
  migration runbook under
  [OpenID Connect id_token requirements](https://github.com/iderex/jellyfin-plugin-sso/wiki/Provider-Setup#openid-connect-id_token-requirements)
  and the
  [Security Model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model)
  wiki page.

### Security

The login path was hardened end to end and now fails closed by default.

- **SAML:** XXE-safe XML loading, strict single-assertion conformance, a signed
  algorithm allowlist (SHA-1 and other weak algorithms rejected), replay
  protection with a bounded cache, and enforced time-bound, audience, and
  recipient checks.
- **OpenID Connect:** PKCE S256, `state`, and `iss` / RFC 9207 response
  validation, all sourced from the login's own discovery document rather than
  trusting request-supplied facts; full `id_token` validation; and a verified-
  email gate for account login and adoption.
- **Account linking:** OpenID links are bound to the IdP issuer (#186) and to
  the stable `sub` / `NameID`, so a renamed or re-pointed account cannot be
  silently taken over.
- **Abuse resistance:** rate limiting across the login, link/unlink, and
  unregister endpoints; active session/token revocation when a user is
  unregistered or their last link is removed; and provider-name validation that
  rejects control characters.
- **Transport and supply chain:** security response headers / CSP on the plugin
  pages, SSRF-guarded avatar fetches, and a Trojan-Source (unicode) guard in CI.

### Features

- **Outgoing SAML AuthnRequest signing (#167),** including ECDSA signing keys
  (#493) alongside RSA, for IdPs that require signed requests.
- **Admin-UI toggles for provider flags** that were previously config-file only
  (for example `AllowExistingAccountLink` and the verified-email requirement),
  plus a real device name on linked sessions.
- **Provider-name hardening** so invalid names are rejected at configuration
  time.

### Architecture / internal

- The monolithic `SSOController` was decomposed into a thin controller over pure,
  single-responsibility helpers and `Api/Flows/*Service` login services (#318),
  with a fail-closed `VerifiedIdentity` keystone. Structural rules are locked in
  as architecture-conformance tests that run in CI. This is an internal change
  with no user-facing configuration impact.

### Fixes

- Login rejections consistently return their intended status codes and never
  surface as HTTP 500.
- Corrected avatar handling (missing-file self-heal, file-extension and path
  handling) and disabled-provider handling across the login and linking flows.
- Numerous smaller robustness fixes in state handling, session minting, and the
  admin/linking pages.
