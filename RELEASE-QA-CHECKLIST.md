# Release QA checklist

The testability program (#192) makes every behaviour that _can_ be automated an
automated test (unit, in-process endpoint, and full round-trip suites in
`SSO-Auth.Tests`). The items below are the residue that genuinely cannot be
automated in-repo — they depend on a real Jellyfin host, a real identity
provider, a browser DOM, or live packaging/install. Per #192's acceptance
("every behaviour automated-tested **or** an explicit release-QA item"), they are
enumerated here as explicit manual checks, each with the reason it stays manual.

Run these against a release candidate before publishing a stable. They are the
manual E2E gate the beta soak requires: a candidate clears
[RELEASE-POLICY.md](RELEASE-POLICY.md)'s promotion gate only once this checklist
passes against its soaked beta build.

## Federation against a real IdP

- [ ] **OIDC login against a real provider** (Keycloak / Authelia / authentik):
      challenge → callback → login succeeds; roles map; PKCE and nonce are
      honoured.
      _Why manual:_ the in-repo `OidcRoundTripTests` drive a self-consistent fake
      IdP; real providers have discovery/JWKS/token quirks the fake cannot model.
- [ ] **SAML login against a real IdP**: signed assertion accepted; secondary
      certificate rollover works; role gating applies.
      _Why manual:_ same as above — a real IdP's signing, clock, and metadata
      behaviour is outside the plugin.

## Deployment topology

- [ ] **Reverse-proxy forwarded-header / rate-limit attribution**: behind a proxy
      with `KnownProxies` configured, the client IP the rate limiter buckets on is
      the real client, not the proxy; throttling still fails open for
      unattributable clients.
      _Why manual:_ depends on the proxy and network config, not plugin code
      (the gate's fail-open logic itself is unit-tested in `SsoRateLimitGateTests`).
- [ ] **Packaging / install / upgrade on a live server**: the JPRM artifact
      installs; an upgrade preserves config; **secret-at-rest migration (#158)**
      re-wraps legacy plaintext secrets on first load; **KEK loss fails closed
      (#550)** rather than logging users in without protection.
      _Why manual:_ install-time filesystem/permission and process-restart
      behaviour (the serializer-level secret migration is covered by
      `ConfigXmlLifecycleTests`).

## Browser / dashboard

- [ ] **jellyfin-web dashboard rendering**: the config page and the account-link
      page render inside the Jellyfin dashboard — tabs, the folder checkbox
      rebuild (#221), and the insecure-toggle warnings (#140) all display.
      _Why manual:_ DOM rendering inside the host web app.
- [ ] **Config-page JS behaviour**: DOM-XSS hardening holds; the link / unlink
      round-trip works in the browser; a successful link shows success, not the
      login-failure text (see #614).
      _Why manual:_ browser-side JavaScript/DOM behaviour.
- [ ] **View-asset `If-None-Match` → 304 conditional revalidation (#253)**: a
      second request with the served `ETag` gets a 304.
      _Why manual:_ the ETag the action emits is unit-tested
      (`SSOViewsControllerTests`), but the conditional-GET negotiation is ASP.NET
      middleware, not plugin code.
