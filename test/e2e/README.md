# End-to-end SSO login harness

An automated, reproducible end-to-end login test (#720/#727) that boots a **real Jellyfin 10.11
server with the packaged plugin installed** and a **real Keycloak identity provider**, then drives
full login round-trips headlessly and asserts the outcomes. It supplements — it does **not** replace
— the manual `Release-QA-Checklist`.

It runs in CI via [`.github/workflows/e2e-login.yml`](../../.github/workflows/e2e-login.yml) and can
be run locally with one command once you have built the plugin.

## Provider matrix (release/beta, or an explicit dispatch)

Keycloak is the **canonical** harness and the only one that runs on a pull request touching the harness,
on the nightly schedule, and on a **default** manual dispatch (there is deliberately no `push` trigger —
the PR run already validated it). Additional self-hostable identity providers get their own harness under
`test/e2e/<provider>/`. **Authelia** (`test/e2e/authelia/`, OIDC), **authentik**
(`test/e2e/authentik/`, OIDC **and** SAML), **Dex** (`test/e2e/dex/`, OIDC) and **Zitadel**
(`test/e2e/zitadel/`, OIDC) are implemented; the rest are
one issue each — Pocket ID, Kanidm; tracked in
[#919](https://github.com/iderex/jellyfin-plugin-sso/issues/919). The **full provider matrix runs at a
release and a beta-release** — never on a routine merge, so the cross-provider pass is release-gate
evidence, not a per-commit cost — **and on a manual dispatch with `providers: all`**, which is how a newly
added harness is proven green before a release rather than on release day. A provider joins that matrix by
adding one `{ name, compose }` object to the list in the workflow's `select` job, pointing at its
`test/e2e/<provider>/docker-compose.yml`.
Cloud providers (Google, Entra ID) cannot run in ephemeral CI, so they are verified manually and marked as
such in the README provider table.

The shared driver (`harness/harness.sh`) keeps the Jellyfin setup and the assertions common and swaps only
the provider-specific browser login (`idp_oidc_login` / `idp_saml_login`, selected by `IDP_KIND`): Keycloak
and Dex render a server-side HTML form (differing only in the form's user field name, a parameter, and in
whether the form action is absolute or site-relative, which the driver detects), Zitadel is a **chain** of
single-form pages (login name → password → a two-factor setup prompt this stack skips) driven generically by
each page's form action — an action the driver does not know is a loud failure naming it, never a silent
skip. Authelia is a single JSON
first-factor call, and
authentik is a **stateful
multi-stage flow-executor** that CHAINS flows (the authentication flow, then the provider's authorization
flow) and must be driven with exactly one request per step — for SAML it ends in an `autosubmit` stage that
carries the POST-binding fields as JSON rather than rendered HTML, which the driver renders back into the
equivalent form so the shared parser can consume it. Provider
shape is passed entirely through the
compose `environment` (issuer/discovery, the role claim and scopes, `RUN_SAML`, whether to load the
profile, and `DISABLE_HTTPS`), so the defaults reproduce the Keycloak run unchanged. The **Authelia**
harness additionally serves TLS with a self-signed cert (Authelia 4.38 requires a secure session URL); the
cert is appended to Jellyfin's system CA bundle at container start (never replacing it) and trusted by the
harness via `CURL_CA_BUNDLE`, so the plugin's real https OIDC path is exercised.

**Zitadel is the one provider that cannot be seeded from a file.** Only its first instance, org and a
machine account with a personal access token come from environment; the project, the OIDC application, the
role and the user grants exist only through its management API — and the client id and secret are
_generated_ by that call, so they can only be known after seeding. The harness therefore seeds it in a
Phase-0b step before any assertion, using the token Zitadel writes to a shared volume. Two Zitadel quirks
are handled there and documented in its compose file: it panics at startup without an RFC1918 address (so
it identifies itself by hostname instead, since these networks are deliberately public-looking), and it
publishes an **empty JWKS** until its `webKey` feature is enabled — which makes every login fail with
`invalid_signature` and nothing in the login path say why. Its roles arrive as an **object map**, read
through the plugin's `RoleClaimIsObjectMap` option (#934).

## What it verifies

- The **packaged JPRM zip** loads on Linux (the `#181` packaged-crypto-DLL load path that
  `dotnet test` cannot see), proven by the plugin's anonymous `GET /sso/OID/GetNames` listing the
  configured, enabled provider.
- A **full OIDC round-trip** for `alice` (challenge → Keycloak login → callback → `OID/Auth`) mints a
  Jellyfin session token that works against `GET /Users/Me`.
- A **full SAML round-trip** for `carol` (challenge → Keycloak login → ACS POST → `SAML/Auth`) mints a
  Jellyfin session token that works against `GET /Users/Me` — exercising the packaged SAML crypto DLLs
  (#181) and the signed-assertion validation path.
- **Asymmetric id_token signing**: the provider's discovery must advertise an **asymmetric** algorithm
  (any of `RS*`/`ES*`/`PS*`/`EdDSA` — not RS256 alone, since a correctly configured provider may default to
  ES256) **and its JWKS must publish at least one key**. An identity provider that falls back to symmetric
  HS256 (authentik does this when its provider has no signing key), or that advertises RS256 while
  publishing an empty key set (Zitadel, until its `webKey` feature is enabled), makes the plugin reject
  every login with `invalid_signature`, so both halves are asserted before any login is driven.
- **Role gating**: `bob` (OIDC) and `dave` (SAML), who lack the `jellyfin-access` role, are refused at
  the callback — and the refusal must be the role gate's **exact HTTP 401**, not merely "some error", so a
  token-exchange failure or a 500 cannot masquerade as a passing role-gate test. A provider that cannot
  express group membership at all (Dex's local password database) is configured with an **empty allow-list**
  and the phase is skipped — driven off that one configured value, so a run can never skip a gate it did
  configure, nor assert one it did not.
- **Fail-closed negatives**: a replayed one-time OIDC state, and a replayed one-time SAML login-outcome
  token, are both refused — and, like the role gate, with the redeem miss's **exact HTTP 400**, so a
  connection failure, a throttle or a 500 cannot masquerade as "one-time-use holds".

## Architecture (avoiding the issuer-hostname trap)

Everything runs in one `docker compose` stack on a shared network, **including the harness**. Every
service is addressed by its service-DNS name, so the OIDC issuer and redirect URLs are byte-identical
whether Jellyfin resolves them server-to-server (discovery, token exchange) or the harness resolves
them in its browser role:

- issuer: `http://keycloak:8080/realms/e2e`
- Jellyfin: `http://jellyfin:8096`
- plugin redirect: `http://jellyfin:8096/sso/OID/redirect/keycloak`

The Keycloak realm (`test/e2e/keycloak/e2e-realm.json`) defines the `jellyfin-oidc` and `jellyfin-saml`
clients, the `jellyfin-access` realm role, and four users: `alice`/`carol` (in the role) and
`bob`/`dave` (not). OIDC uses `alice`/`bob`; SAML uses the distinct `carol`/`dave` so the two protocols
never contend over the same Jellyfin account. A protocol mapper emits the realm roles into the id_token
as `realm_access.roles` (read by the plugin's OIDC `RoleClaim`) and into the SAML assertion as a `Role`
attribute (read by the SAML role gate). The SAML IdP signing certificate is fetched at run time from
Keycloak's SAML descriptor and configured through the plugin's `SAML/Add` admin API.

## Run it locally

Local Docker must be working. The harness installs the **packaged** plugin, so build the zip first.

```sh
# 1. Build the packaged plugin zip (requires the .NET 9 SDK and JPRM: `pip install jprm`).
jprm --verbosity=debug plugin build . --output ./artifacts --dotnet-framework net9.0

# 2. Unpack it into the Jellyfin plugins directory the compose stack mounts.
mkdir -p test/e2e/jellyfin/config/plugins/SSO-Auth
unzip -o ./artifacts/sso-authentication_*.zip -d test/e2e/jellyfin/config/plugins/SSO-Auth
chmod -R 0777 test/e2e/jellyfin

# 3. Boot the stack and run the harness (its exit code is the run's exit code).
docker compose -f test/e2e/docker-compose.yml up \
  --abort-on-container-exit --exit-code-from harness

# 4. Tear down.
docker compose -f test/e2e/docker-compose.yml down -v
```

A green run prints `ALL E2E CHECKS PASSED`. In CI, container logs are dumped automatically on
failure.

**The Zitadel stack is the one harness that cannot be re-run in place.** Every other provider is seeded
from a file (an imported realm, a reapplied blueprint, or a static config) and the driver deliberately
reuses an already-initialised Jellyfin. Zitadel is seeded through its API against a stateful Postgres and a
named volume holding its access token, and the seed is not idempotent — a second `up` on the same stack hits
`ALREADY_EXISTS` on the project create and dies there. Always tear it down with `down -v` between runs. CI
is unaffected: each matrix entry gets a fresh runner and tears the stack down with `-v`.

**Running more than one provider locally:** every provider's compose bind-mounts the same
`test/e2e/jellyfin/config`, and `docker compose down -v` does not clear a bind mount. Wipe it (and re-unpack
the plugin) between providers — otherwise the second run reuses a Jellyfin that already completed the wizard
and already has `alice` linked to the first provider, which is not what CI does (each matrix entry runs on a
fresh runner).

To run the **Authelia** harness instead, generate its self-signed TLS cert first (never committed), then
point `docker compose` at its file — the plugin drop from step 2 is reused unchanged:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout test/e2e/authelia/tls.key -out test/e2e/authelia/tls.crt \
  -days 3650 -subj "/CN=login.example.com" -addext "subjectAltName=DNS:login.example.com"

docker compose -f test/e2e/authelia/docker-compose.yml up \
  --abort-on-container-exit --exit-code-from harness
```
