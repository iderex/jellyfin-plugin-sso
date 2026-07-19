# Single-Logout (SLO) design constraints

**Status: NOT IMPLEMENTED.** This document records the constraints and the
intended design so a future single-logout implementation starts from a
threat-modelled position. No logout endpoint, logout-token receiver, or
`LogoutRequest` issuer exists in the plugin today. This is a design record only
(issue #154); building SLO is a separate, threat-modelled work item.

## What the plugin retains today (the grounding facts)

SLO of any flavour needs artifacts from the login that the plugin currently
does **not** keep. The login pipeline verifies a protocol response, projects it
to a small protocol-agnostic identity, and discards the raw protocol material:

- **OIDC — the raw `id_token` is discarded after the callback.** In
  `SSO-Auth/Api/Flows/OidcLoginService.cs` (`CallbackAsync`), `result.IdentityToken`
  (the raw id_token from `ProcessResponseAsync`) is read for exactly two purposes:
  the RFC 9207 response-`iss` mix-up check
  (`OidcResponseIssuer.IsRejected(..., result.IdentityToken, ...)`) and to derive
  the account-link issuer (`OidcResponseIssuer.IdTokenIssuer(result.IdentityToken)`,
  which only extracts the `iss` claim — `SSO-Auth/Api/OidcResponseIssuer.cs`). The
  token itself is never stored. It does not survive into `AuthorizeSession`/
  `VerifiedIdentity`.
- **`VerifiedIdentity` (the keystone carried into session minting) has no token
  field.** `SSO-Auth/Api/VerifiedIdentity.cs` carries only `Subject`, `Issuer`
  (the id_token `iss` string, not the token), `Username`, `EmailVerified`, and the
  privilege flags — no `id_token`, no `sid`, no SAML `SessionIndex`.
- **SAML — no `SessionIndex` is captured.** The assertion parser
  (`SSO-Auth/Saml.cs`) exposes `GetNameID()`, `GetInResponseTo()`, and `Xml`, but
  there is **no** `GetSessionIndex()` accessor. `SamlLoginService.AuthenticateAsync`
  keeps only `InResponseTo` (for browser-binding correlation) in the in-flight
  `SamlLoginOutcome`; the `NameID` survives as `VerifiedIdentity.Subject`. A SAML
  `LogoutRequest` requires **both** the `NameID` and the `SessionIndex` of the
  session being terminated — the latter is not retained.
- **The OIDC `end_session_endpoint` is read but never persisted.**
  `SSO-Auth/Api/OidcDiscoveryReader.cs` maps `discovery.EndSessionEndpoint` into the
  in-memory `ProviderInformation`, but that object lives only for the duration of a
  single login round-trip. Nothing writes the end-session endpoint anywhere durable.
- **The account-link store persists no per-session data.** Canonical links
  (`SSO-Auth/Api/Linking/CanonicalLinkService.cs`) key on
  `provider + subject (+ issuer for OIDC)` → Jellyfin user id. There is no
  mapping from an SSO subject/session to a concrete Jellyfin session or device,
  and no place a logout handler could look up "which Jellyfin sessions belong to
  this SSO login."
- **In-flight stores are transient and capped.** `OidcStateStore` and
  `SamlOutcomeStore`/`SamlRequestCache` are process-wide, in-memory, time-bounded
  (~15 min), and CSPRNG-keyed. They are login-correlation caches, not a session
  ledger; they are gone on restart and are the wrong home for anything a logout
  needs minutes-to-hours later.

**Consequence:** SLO is cheap to _plan for_ now and expensive to retrofit. The
one prerequisite worth deciding now is **what to persist per Jellyfin session at
login time** (see the OIDC and SAML sections). Persisting it later means it is
simply absent for every session created before the change.

### Library note (affects what OIDC SLO can call)

The plugin multi-targets, and the OidcClient version differs per TFM
(`SSO-Auth/SSO-Auth.csproj`): **OidcClient 6.0.1 on `net9.0`** (Jellyfin 10.11)
and **OidcClient 7.1.0 on `net10.0`** (Jellyfin 12.0). Any reliance on
7.1.0's `LogoutRequest`/`EndSessionEndpoint` modelling must be conditioned on
the target — the `net9.0` build cannot assume the 7.x logout surface. RP-initiated
logout is a plain front-channel redirect and can be built without the library
either way.

## OIDC single-logout

### Prefer back-channel logout

- **Back-channel logout (OP → RP `logout_token`) is the target.** The OP POSTs a
  signed `logout_token` (a JWT) to a plugin-hosted back-channel logout URI; the
  plugin validates it and terminates the corresponding Jellyfin session(s)
  server-to-server. No browser, no third-party cookies.
- **Front-channel logout is effectively dead and is ruled out.** The
  OpenID Front-Channel Logout model relies on the OP loading per-RP `<iframe>`s in
  the user's browser; under third-party-cookie blocking (now default in major
  browsers) those iframes do not carry the RP session cookie, so the notification
  silently fails. The spec itself warns of this. Do not build front-channel iframe
  logout.
- **Reachability caveat for LAN-only installs.** Back-channel logout requires the
  **OP to reach the plugin's logout URI**. Jellyfin is frequently deployed
  LAN-only / behind NAT with no inbound path from a public OP. Back-channel is
  therefore _best-effort_: when the OP cannot reach the RP, no `logout_token`
  arrives and the Jellyfin session is not terminated by SLO. The design must treat
  a missing logout notification as "SLO did not happen," never as "logout
  succeeded" — and must not present LAN-only operators a guarantee it cannot keep.

### RP-initiated logout and the `id_token_hint` retention constraint

- **RP-initiated logout** (user clicks "log out", the RP redirects the browser to
  the OP's `end_session_endpoint`) is the realistic complement to best-effort
  back-channel, and works through the browser without third-party cookies.
- **It wants an `id_token_hint`.** `end_session_endpoint` takes `id_token_hint` so
  the OP can identify the session to end and skip a logout-confirmation prompt.
  Without it many OPs either refuse or force an interactive confirmation.
- **The plugin does not retain the id_token today** (see grounding facts). To send
  `id_token_hint`, the plugin must **persist the raw id_token** (or, as a minimum,
  `iss` / `sid` / `sub`, which cover session correlation and back-channel
  `logout_token` matching but do **not** satisfy `id_token_hint`, which wants the
  full JWT) against the Jellyfin session at login time.

**Security cost of storing the id_token (must be honoured, fail-closed):**

- A stored id_token is **sensitive**: it is a signed assertion of identity and
  claims. Treat it like the client secret and signing keys already are —
  encrypted at rest via the existing `Secrets` envelope (`#158`, the same path
  `OidSecret`/`SamlSigningKeyPfx` use), never logged, redacted on export.
- **Scope-minimise.** Prefer persisting only `iss` + `sid` + `sub` when the OP
  supports back-channel logout (that is all a `logout_token` needs to match), and
  store the full id_token _only_ when RP-initiated `id_token_hint` is actually a
  configured requirement for that provider.
- **Expiry.** Bind the stored token/identifiers to the Jellyfin session lifetime
  and purge on session end; do not keep an id_token past the session it belongs to.
  An expired id_token is still a valid `id_token_hint` for `end_session` per spec,
  so retention is a storage-lifetime decision, not an `exp` decision — but never
  keep it beyond the session.
- Persist it **per Jellyfin session**, so logout can map an SSO logout signal to
  the specific session(s) to kill (see "Jellyfin session invalidation" below).

## SAML single-logout

- **Back-channel (SOAP) vs front-channel (HTTP-Redirect/POST).** SAML SLO exchanges
  a `LogoutRequest`/`LogoutResponse`. Back-channel uses SOAP directly between SP and
  IdP (no browser, same reachability caveat as OIDC back-channel — an inbound path
  from the IdP to the plugin is required, often absent on LAN-only installs).
  Front-channel uses browser redirects/POST and is subject to the same
  third-party-context erosion, though SAML front-channel is a top-level navigation
  rather than a hidden iframe, so it degrades less severely than OIDC
  front-channel — it is a usable fallback, not dead.
- **`NameID` + `SessionIndex` retention.** Building a `LogoutRequest` requires the
  `NameID` **and** the `SessionIndex` of the authenticated session. The `NameID` is
  retained today (as `VerifiedIdentity.Subject`); the **`SessionIndex` is not
  captured at all** — `SSO-Auth/Saml.cs` has no accessor for it and nothing stores
  it. Capturing and persisting the `SessionIndex` (alongside `NameID`) per Jellyfin
  session at login is the SAML prerequisite, symmetric to the OIDC id_token/sid
  retention.
- The IdP's `SingleLogoutService` endpoint is **not** in the config today
  (`SamlEndpoint` is the SSO endpoint only — `SSO-Auth/Config/PluginConfiguration.cs`);
  SLO needs a separately configured logout endpoint (and, for signed logout, reuse
  of the existing request-signing key material).

## Constraints and threats (STRIDE-style, brief)

Logout messages are **security-relevant inbound requests** and must be validated
with the same rigour as login — an unauthenticated "log this user out" endpoint
is itself an attack surface.

- **Spoofing / Tampering (forged logout messages).** An OIDC `logout_token` and a
  SAML `LogoutRequest` must be validated _exactly like a login assertion_:
  signature verified against the provider's keys, `iss`/issuer bound to the
  configured provider, audience/recipient checked, and timing/`iat` bounded. Reuse
  the existing validators' posture (`OidcIdTokenValidator`, `SamlAssertionValidator`)
  — do not hand-roll a laxer path for logout. A `logout_token` additionally must
  carry the `events` claim and MUST NOT carry `nonce` (per the back-channel spec);
  reject non-conformant tokens fail-closed.
- **Replay.** Logout messages must be one-time, mirroring the login replay caches
  (`jti` for `logout_token`; the SAML replay cache for `LogoutRequest`). A replayed
  logout that merely re-kills an already-dead session is low-harm, but the
  validation path must not become a weaker oracle than login.
- **Elevation / DoS — "logout as an unauthenticated session-kill vector."** The
  single most important threat: a logout endpoint must never let an unauthenticated
  or cross-user caller terminate an arbitrary user's session. A logout only
  terminates a session when the presenter **proves control** of the SSO session
  being ended (a validly-signed `logout_token`/`LogoutRequest` from the bound
  provider that correlates to a stored session identifier). RP-initiated logout
  triggered from the browser must be CSRF-protected and may only end the caller's
  own session. Fail closed: unresolvable correlation → terminate nothing, not
  everything.
- **Repudiation / audit.** Every SLO-driven session termination should be audited
  the way logins are (`SsoAudit`), so an operator can see that a session ended via
  SLO and why.
- **Availability / mass-logout.** A malformed or storm of logout signals must not
  become a mass-lockout: throttle like the login rate-limit gate, and never let one
  logout signal fan out to kill unrelated sessions. Losing the correlation store on
  restart must degrade to "SLO no-op" (sessions simply live out their normal
  Jellyfin lifetime), never to "kill all sessions."

### Jellyfin session invalidation mapping

- Jellyfin sessions are minted through `ISessionManager` in
  `SSO-Auth/Api/SessionMinter.cs` (`AuthenticateDirect`); the plugin holds **no**
  mapping from an SSO subject/session to the resulting Jellyfin session/device.
- To act on a logout signal, the design needs a durable
  **`(provider, iss/sub, sid | SessionIndex)` → Jellyfin session/device** map,
  written at mint time. Terminating the session then means invalidating that
  Jellyfin session/token through the server's session API — the exact mechanism
  (and whether the plugin may revoke a session it did not itself own) is an
  open design question to resolve against the Jellyfin session API at
  implementation time, empirically, not by assumption.

## Fail-closed and scope notes

- **Fail-closed throughout.** Missing/invalid signature, unresolvable session
  correlation, unreachable OP/IdP, or an unconfigured logout endpoint → terminate
  **no** session and surface the condition; never default to "logged out" and never
  fan out to unrelated sessions.
- **Scope of retained material is minimised and encrypted at rest.** Store the
  least that satisfies the enabled logout mode (prefer `iss`/`sid`/`sub` and SAML
  `SessionIndex`; full id_token only when `id_token_hint` is required), always via
  the existing at-rest `Secrets` envelope, never logged, purged on session end.
- **Best-effort, honestly presented.** Back-channel and SOAP SLO depend on OP/IdP →
  plugin reachability that LAN-only installs usually lack; the feature must not
  claim a logout guarantee it cannot deliver in those topologies.
- **Not implemented yet.** This document records constraints only. The retention
  decision (persist `iss`/`sid`/`sub` and SAML `SessionIndex` per Jellyfin session
  at login) is the one cheap-now / expensive-later prerequisite to settle before or
  alongside the first SLO code.
