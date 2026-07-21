# End-to-end SSO login harness

An automated, reproducible end-to-end login test (#720/#727) that boots a **real Jellyfin 10.11
server with the packaged plugin installed** and a **real Keycloak identity provider**, then drives
full login round-trips headlessly and asserts the outcomes. It supplements — it does **not** replace
— the manual `Release-QA-Checklist`.

It runs in CI via [`.github/workflows/e2e-login.yml`](../../.github/workflows/e2e-login.yml) and can
be run locally with one command once you have built the plugin.

## What it verifies

- The **packaged JPRM zip** loads on Linux (the `#181` packaged-crypto-DLL load path that
  `dotnet test` cannot see), proven by the plugin's anonymous `GET /sso/OID/GetNames` listing the
  configured, enabled provider.
- A **full OIDC round-trip** for `alice` (challenge → Keycloak login → callback → `OID/Auth`) mints a
  Jellyfin session token that works against `GET /Users/Me`.
- A **full SAML round-trip** for `carol` (challenge → Keycloak login → ACS POST → `SAML/Auth`) mints a
  Jellyfin session token that works against `GET /Users/Me` — exercising the packaged SAML crypto DLLs
  (#181) and the signed-assertion validation path.
- **Role gating**: `bob` (OIDC) and `dave` (SAML), who lack the `jellyfin-access` role, are refused at
  the callback.
- **Fail-closed negatives**: a replayed one-time OIDC state, and a replayed one-time SAML login-outcome
  token, are both refused.

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
