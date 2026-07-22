#!/bin/sh
# End-to-end SSO login harness (#720/#727). Runs inside a container on the compose network so it
# reaches Jellyfin and Keycloak by their service-DNS names — the same names Jellyfin uses
# server-to-server — so every issuer/redirect URL is identical from both sides.
#
# It (1) waits for both servers, (2) completes the Jellyfin first-run wizard and grabs an admin
# token, (3) configures the OpenID provider through the plugin's admin API, (4) asserts the plugin
# loaded and the provider is enabled, then drives full browser-role login round-trips:
#   - alice (in the jellyfin-access role)  -> a Jellyfin session token, usable against /Users/Me
#   - bob   (no role)                      -> refused at the callback (role gate)
#   - a replayed one-time state            -> refused (fail-closed)
#
# Fail-closed: any assertion miss increments FAILURES; the script exits non-zero at the end, which
# (with --exit-code-from harness) reds the whole compose run and the CI job.
set -eu

JELLYFIN="${JELLYFIN_URL:-http://jellyfin:8096}"
KEYCLOAK="${KEYCLOAK_URL:-http://keycloak:8080}"
REALM="${REALM:-e2e}"
PROVIDER="${PROVIDER:-keycloak}"
CLIENT_ID="${OIDC_CLIENT_ID:-jellyfin-oidc}"
CLIENT_SECRET="${OIDC_CLIENT_SECRET:-jellyfin-oidc-secret}"
ADMIN_USER="${JF_ADMIN_USER:-e2eadmin}"
ADMIN_PASS="${JF_ADMIN_PASS:-e2e-admin-pw}"

# Provider-shape parameters. Defaults reproduce the Keycloak harness byte-for-byte; another OIDC provider
# (e.g. Authelia) overrides them from its compose env. IDP_KIND selects the provider-specific browser-login
# sequence in idp_oidc_login (Keycloak and Dex render a server-side HTML form, Authelia is a JSON-API login
# portal, authentik is a stateful multi-stage flow executor).
IDP_KIND="${IDP_KIND:-keycloak}"
RUN_SAML="${RUN_SAML:-true}"
OID_ENDPOINT="${OID_ENDPOINT:-$KEYCLOAK/realms/$REALM}"
DISCOVERY_URL="${DISCOVERY_URL:-$KEYCLOAK/realms/$REALM/.well-known/openid-configuration}"
# What the readiness wait probes. Defaults to the discovery document, which every provider that declares its
# client statically already serves. Kanidm cannot: its discovery document only comes into existence once the
# OAuth2 client is seeded, and seeding needs the server up — so it points this at a plain liveness endpoint
# and the discovery document is still asserted afterwards by the signing check.
READINESS_URL="${READINESS_URL:-$DISCOVERY_URL}"
ROLE_CLAIM="${ROLE_CLAIM:-realm_access.roles}"
OID_SCOPES_JSON="${OID_SCOPES_JSON:-[\"email\"]}"
# Keycloak carries the roles in the id_token, so the profile fetch is skipped; a provider that only exposes
# the group/role claim at the userinfo endpoint (e.g. Authelia) sets this false so the plugin fetches it.
DO_NOT_LOAD_PROFILE="${DO_NOT_LOAD_PROFILE:-true}"
# DisableHttps relaxes the plugin's https-only issuer requirement for a plaintext-http test IdP (Keycloak).
# A provider served over real TLS (Authelia) sets this false so the production https path is exercised.
DISABLE_HTTPS="${DISABLE_HTTPS:-true}"
AUTHELIA_URL="${AUTHELIA_URL:-http://authelia:9091}"
AUTHENTIK_URL="${AUTHENTIK_URL:-http://authentik:9000}"
# SAML provider shape (defaults reproduce the Keycloak realm exactly).
SAML_DESCRIPTOR_URL="${SAML_DESCRIPTOR_URL:-$KEYCLOAK/realms/$REALM/protocol/saml/descriptor}"
SAML_ENDPOINT="${SAML_ENDPOINT:-$KEYCLOAK/realms/$REALM/protocol/saml}"
SAML_CLIENT_ID="${SAML_CLIENT_ID:-jellyfin-saml}"
# Canonical base URL the plugin builds its AssertionConsumerService URL from. Blank (the Keycloak default)
# leaves the feature off and the ACS is derived from the request host. A provider that validates the ACS
# against a configured value needs both sides to agree — authentik rejects a mismatch with HTTP 400, and its
# provider ACS must use a dotted host, so that harness pins the same dotted host here.
SAML_BASE_URL_OVERRIDE="${SAML_BASE_URL_OVERRIDE:-}"
# The HTML-form login's user field. Keycloak names it `username`; Dex's local connector names it `login`.
LOGIN_USER_FIELD="${LOGIN_USER_FIELD:-username}"
# The claim the plugin turns into the Jellyfin account name. Dex's local connector emits no
# preferred_username (only `name`), so that harness repoints it rather than failing to resolve a username.
USERNAME_CLAIM="${USERNAME_CLAIM:-preferred_username}"
# The plugin's login allow-list. A non-empty list IS the role gate; an EMPTY list turns it off, which is the
# only honest setting for a provider that cannot express group membership at all (Dex's local password
# database carries none). The role-gate phase is driven off this ONE value rather than a second switch, so
# the configured gate and the asserted gate can never disagree.
OID_ROLES_JSON="${OID_ROLES_JSON:-[\"jellyfin-access\"]}"
# Whether the role claim's terminal is an object whose property NAMES are the roles (#934) rather than a
# list of role strings. Only Zitadel emits that shape.
ROLE_CLAIM_IS_OBJECT_MAP="${ROLE_CLAIM_IS_OBJECT_MAP:-false}"
# The admin-elevation allow-list (#928 U5). Empty by default so every existing provider stack is
# byte-unchanged; a stack that grants an IdP role admin rights sets this AND seeds the role.
ADMIN_ROLES_JSON="${ADMIN_ROLES_JSON:-[]}"
# Extended phases (#928 U5): second-login identity-binding, admin-elevation policy assert, and the
# SSO-only login round-trip. Off by default — the canonical Keycloak stack turns them on; other
# providers opt in once their seeds carry the required roles.
EXTENDED_PHASES="${EXTENDED_PHASES:-false}"
# The two OIDC test users' passwords. They default to the username (every other harness seeds them that
# way); Zitadel's default password policy rejects anything that simple, so that harness overrides both. The
# SAME variables seed the account and drive the login, so the two can never disagree.
PASSWORD_ALICE="${PASSWORD_ALICE:-alice}"
PASSWORD_BOB="${PASSWORD_BOB:-bob}"
# Kanidm seeding: its origin, and the admin unix socket that is the only non-interactive way into a fresh
# instance. The socket must be on a named volume — over a bind mount every connect is refused.
KANIDM_URL="${KANIDM_URL:-https://idm.example.com:8443}"
KANIDM_SOCKET="${KANIDM_SOCKET:-/kanidm-data/kanidmd.sock}"
# Pocket ID seeding: its origin, and the SQLite file the harness writes the bootstrap rows into.
POCKETID_URL="${POCKETID_URL:-http://pocketid:1411}"
POCKETID_DB="${POCKETID_DB:-/pid-data/pocket-id.db}"
# Zitadel seeding: where its setup migration writes the machine account's personal access token.
ZITADEL_URL="${ZITADEL_URL:-http://zitadel:8080}"
ZITADEL_PAT_PATH="${ZITADEL_PAT_PATH:-/pat/e2e.pat}"

# A stable device identity for the harness's Jellyfin API calls (the MediaBrowser auth scheme).
CLIENT="e2e-harness"
DEVICE="harness"
DEVICE_ID="e2e-harness-device"
VERSION="1.0.0"
EMBY_AUTH="MediaBrowser Client=\"$CLIENT\", Device=\"$DEVICE\", DeviceId=\"$DEVICE_ID\", Version=\"$VERSION\""

# The plugin's browser-binding cookie (#326). It is always marked Secure (every real OpenID deployment is
# HTTPS at the browser edge), so over the harness's plaintext http, curl stores it but will NOT send it
# back. We therefore capture its value from the /start response and present it EXPLICITLY as a Cookie
# header on the callback and OID/Auth legs — curl does not enforce Secure on a manually-set header, and the
# server reads the cookie by name regardless of the __Host- prefix. This exercises the real binding check
# without weakening the production Secure/__Host- policy.
BINDING_COOKIE_NAME="__Host-sso_oid_state_binding"

FAILURES=0
log()  { printf '%s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
# die writes to STDERR: a fatal message is worthless if a caller's `$(...)` or a `>/dev/null` swallows it,
# and the run then ends with an unexplained exit 1. (pass/fail stay on stdout — they are the transcript.)
die()  { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

log "== Installing curl + jq =="
apk add --no-cache curl jq >/dev/null 2>&1 || die "could not install curl/jq"

wait_for() {
  # wait_for <label> <url>
  label="$1"; url="$2"; i=0
  log "Waiting for $label ($url) ..."
  while [ "$i" -lt 90 ]; do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then
      log "$label is up"
      return 0
    fi
    i=$((i + 1))
    sleep 5
  done
  die "$label did not become ready in time"
}

# --------------------------------------------------------------------------------------------------
# Phase 0 — readiness
# --------------------------------------------------------------------------------------------------
wait_for "identity provider" "$READINESS_URL"
wait_for "Jellyfin" "$JELLYFIN/System/Info/Public"

# --------------------------------------------------------------------------------------------------
# Phase 0b — seed the identity provider (only where its OIDC client cannot be declared up front)
# --------------------------------------------------------------------------------------------------
# Two providers need it, and for the same underlying reason: their OIDC client is CREATED by the seeding
# call, so its id and secret cannot be declared in a compose file up front.
#
#   Zitadel   — only the first instance, its org and a machine account with a personal access token come
#               from environment; the project, the application, the role and the user grants exist solely
#               through its management API. Seeding also turns on the feature that makes Zitadel publish a
#               signing key at all, which is why this phase runs BEFORE the signing assertion below.
#   Pocket ID — authenticates with passkeys only and has no non-interactive way into a fresh instance at
#               all, so the seeding starts by writing the very first admin into its database.
#
# Every other harness declares its client statically and this whole phase is a no-op for them.
# Mints a Pocket ID one-time access token for a user by INSERTing it, and prints it. Pocket ID's admin API
# for this (POST /api/users/{id}/one-time-access-token) answers 500 for every documented body shape on a
# default instance, so the harness uses the one mechanism that works for both the bootstrap admin and the
# test users rather than two half-working ones. The row is exactly what Pocket ID's own CLI writes.
pocket_id_mint_token() {
  # pocket_id_mint_token <user-id> <token>
  sqlite3 -cmd ".timeout 5000" "$POCKETID_DB" "INSERT INTO one_time_access_tokens (id, created_at, token, expires_at, user_id) VALUES ('ot-$2', datetime('now'), '$2', datetime('now', '+1 day'), '$1');" \
    || die "pocket-id: could not write a one-time access token for user $1"
}

# Exchanges a Pocket ID one-time access token for a session, and prints the Cookie header value to present.
# The cookie is marked Secure (as every real Pocket ID deployment is HTTPS at the browser edge), so over
# this stack's plaintext http curl stores it but will NOT send it back — the same reason the plugin's own
# browser-binding cookie is captured and replayed explicitly below.
pocket_id_session() {
  # pocket_id_session <token>
  curl -sS -D /tmp/pid.h -o /dev/null -X POST "$POCKETID_URL/api/one-time-access-token/$1" 2>/dev/null || return 1
  pid_ck="$(grep -i '^set-cookie' /tmp/pid.h | sed -e 's/^[Ss]et-[Cc]ookie: //' -e 's/;.*//' | paste -sd';' -)"
  [ -n "$pid_ck" ] || return 1
  printf '%s' "$pid_ck"
}

# Runs Kanidm's auth step machine and prints the resulting bearer token. Every step after the first carries
# the session id in a HEADER, not the body.
kanidm_auth() {
  # kanidm_auth <username> <password>
  curl -sS -D /tmp/kan.h -o /dev/null -X POST "$KANIDM_URL/v1/auth" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$1" '{step:{init2:{username:$u,issue:"token"}}}')" 2>/dev/null || return 1
  kan_sid="$(grep -i '^x-kanidm-auth-session-id:' /tmp/kan.h | sed -e 's/^[^:]*: //' | tr -d '\r\n')"
  [ -n "$kan_sid" ] || return 1
  curl -sS -o /dev/null -X POST "$KANIDM_URL/v1/auth" -H 'Content-Type: application/json' \
    -H "X-KANIDM-AUTH-SESSION-ID: $kan_sid" -d '{"step":{"begin":"password"}}' 2>/dev/null || return 1
  kan_out="$(curl -sS -X POST "$KANIDM_URL/v1/auth" -H 'Content-Type: application/json' \
    -H "X-KANIDM-AUTH-SESSION-ID: $kan_sid" -d "$(jq -nc --arg p "$2" '{step:{cred:{password:$p}}}')" 2>/dev/null || true)"
  kan_tok="$(printf '%s' "$kan_out" | jq -r '.state.success // empty' 2>/dev/null || true)"
  [ -n "$kan_tok" ] || return 1
  printf '%s' "$kan_tok"
}

seed_kanidm() {
  log "== Seeding Kanidm (admin recovery, groups, users, OAuth2 client) =="
  apk add --no-cache socat >/dev/null 2>&1 || die "kanidm: could not install socat"

  # A fresh Kanidm has no default admin password, no provisioning file, and no shell in its image to
  # sequence `recover-account` before the server. Its ADMIN UNIX SOCKET is the way in: it speaks one-line
  # JSON and hands out a recovery password. It only works over a named volume, which is why the compose
  # gives /data one (see that file's header).
  kan_wait=0
  while [ "$kan_wait" -lt 45 ]; do
    [ -S "$KANIDM_SOCKET" ] && break
    kan_wait=$((kan_wait + 1))
    sleep 2
  done
  [ "$kan_wait" -lt 45 ] || die "kanidm: the admin socket never appeared at $KANIDM_SOCKET"

  kan_admin_pw="$(printf '%s\n' '{"RecoverAccount":{"name":"idm_admin"}}' \
    | socat -t10 - "UNIX-CONNECT:$KANIDM_SOCKET" 2>/dev/null | jq -r '.RecoverAccount.password // empty' 2>/dev/null || true)"
  [ -n "$kan_admin_pw" ] || die "kanidm: the admin socket returned no recovery password"

  kan_admin="$(kanidm_auth idm_admin "$kan_admin_pw")" || die "kanidm: could not authenticate as idm_admin after recovery"

  # kapi <method> <path> <json> — one admin call, returning a status and leaving the body in /tmp/kan.out,
  # so each call site can be `|| die` with its own reason.
  kapi() {
    kan_code="$(curl -sS -o /tmp/kan.out -w '%{http_code}' -X "$1" "$KANIDM_URL$2" \
      -H "Authorization: Bearer $kan_admin" -H 'Content-Type: application/json' -d "$3" 2>/dev/null || true)"
    case "$kan_code" in
      2*) return 0 ;;
      *) log "kanidm: $1 $2 returned HTTP ${kan_code:-000}: $(head -c 300 /tmp/kan.out 2>/dev/null)"; return 1 ;;
    esac
  }

  # Kanidm's default account policy requires MFA, so a password-only credential cannot be committed
  # (can_commit=false, warnings=["MfaRequired"]). Relaxing it is a deliberate TEST-RIG-ONLY change; a real
  # deployment should leave it alone.
  kapi PUT /v1/group/idm_all_persons/_attr/credential_type_minimum '["any"]' \
    || die "kanidm: could not relax the MFA account policy — password credentials cannot be committed without it"

  # TWO groups, and the split matters. Kanidm's scope map is what grants access to the client at all, so
  # mapping it onto the role group would make Kanidm itself refuse bob with a 403 and the PLUGIN's role gate
  # would never be reached — the negative test would prove nothing. jellyfin-users grants both users access
  # to the client; jellyfin-access is the role the plugin gates on and only alice holds it.
  kapi POST /v1/group '{"attrs":{"name":["jellyfin-access"]}}' || die "kanidm: the jellyfin-access group create failed"
  kapi POST /v1/group '{"attrs":{"name":["jellyfin-users"]}}' || die "kanidm: the jellyfin-users group create failed"

  # The DISPLAY NAME is deliberately UNLIKE the username. Kanidm's `name` claim is the OIDC profile claim
  # and carries the display name, not the account name — so seeding the two equal would make the harness
  # unable to tell them apart, and it would pass just as happily with Jellyfin accounts named after a
  # person's full name. With them distinct, the `Name='alice'` assertion is what proves the plugin took the
  # username and not the display name.
  for kan_person in alice bob; do
    kapi POST /v1/person "$(jq -nc --arg n "$kan_person" --arg d "$kan_person Example" '{attrs:{name:[$n],displayname:[$d]}}')" \
      || die "kanidm: the $kan_person create failed"
  done
  kapi POST /v1/group/jellyfin-users/_attr/member '["alice","bob"]' || die "kanidm: adding the users to jellyfin-users failed"
  kapi POST /v1/group/jellyfin-access/_attr/member '["alice"]' \
    || die "kanidm: granting alice the role failed — she would then be refused for the same reason as bob, making the role gate's positive and negative cases indistinguishable"

  kapi POST /v1/oauth2/_basic "$(jq -nc --arg redir "$JELLYFIN/sso/OID/redirect/$PROVIDER" --arg land "$JELLYFIN" \
    '{attrs:{name:["jellyfin"],displayname:["Jellyfin"],oauth2_rs_origin:[$redir],oauth2_rs_origin_landing:[$land]}}')" \
    || die "kanidm: the OAuth2 client create failed"
  kapi POST /v1/oauth2/jellyfin/_scopemap/jellyfin-users '["openid","profile","email","groups"]' \
    || die "kanidm: the OAuth2 scope map failed — without it no user can authorise at all"
  # Kanidm's preferred_username is the SPN (alice@idm.example.com) unless the resource server opts into the
  # short form. That opt-in is Kanidm's own supported mechanism for it, and it is what makes
  # preferred_username — the plugin's default username claim — the bare account name.
  kapi POST /v1/oauth2/jellyfin/_attr/oauth2_prefer_short_username '["true"]' \
    || die "kanidm: enabling prefer_short_username failed — the Jellyfin account would be named after the SPN"

  CLIENT_ID=jellyfin
  kapi GET /v1/oauth2/jellyfin/_basic_secret '' || die "kanidm: reading the client secret failed"
  CLIENT_SECRET="$(jq -r '. // empty' /tmp/kan.out 2>/dev/null || true)"
  [ -n "$CLIENT_SECRET" ] || die "kanidm: the client secret is empty"

  # Passwords go through a credential-update SESSION. The update body is a TUPLE with the request FIRST and
  # lowercase variant names; a token-first tuple fails with "unknown variant `token`".
  kan_setpw() {
    kapi GET "/v1/person/$1/_credential/_update" '' || die "kanidm: opening $1's credential session failed"
    kan_cu="$(jq -c '.[0]' /tmp/kan.out 2>/dev/null || true)"
    [ -n "$kan_cu" ] || die "kanidm: $1's credential session returned no token"
    kapi POST /v1/credential/_update "$(jq -nc --arg p "$2" --argjson cu "$kan_cu" '[{password:$p},$cu]')" \
      || die "kanidm: setting $1's password failed"
    [ "$(jq -r '.can_commit' /tmp/kan.out 2>/dev/null || echo false)" = "true" ] \
      || die "kanidm: $1's credential is not committable: $(jq -c '.warnings' /tmp/kan.out 2>/dev/null)"
    kapi POST /v1/credential/_commit "$kan_cu" || die "kanidm: committing $1's password failed"
  }
  kan_setpw alice "$PASSWORD_ALICE"
  kan_setpw bob "$PASSWORD_BOB"

  log "Kanidm seeded (client_id=$CLIENT_ID)"
}

seed_pocket_id() {
  log "== Seeding Pocket ID (bootstrap admin, OIDC client, group, users) =="
  apk add --no-cache sqlite >/dev/null 2>&1 || die "pocket-id: could not install sqlite"
  # Wait for Pocket ID to create its schema before writing into it.
  pid_wait=0
  while [ "$pid_wait" -lt 30 ]; do
    [ -s "$POCKETID_DB" ] && sqlite3 "$POCKETID_DB" 'select 1 from users limit 1;' >/dev/null 2>&1 && break
    pid_wait=$((pid_wait + 1))
    sleep 2
  done
  [ "$pid_wait" -lt 30 ] || die "pocket-id: the database at $POCKETID_DB never gained a users table"

  # The one reach past the API: a fresh Pocket ID has no non-interactive way in at all (see the compose
  # header). Everything after this runs through the normal admin API.
  sqlite3 -cmd ".timeout 5000" "$POCKETID_DB" <<SQL || die "pocket-id: could not seed the bootstrap admin"
INSERT INTO users (id, created_at, username, email, first_name, last_name, display_name, is_admin)
 VALUES ('u-e2eadmin', datetime('now'), 'e2eadmin', 'e2eadmin@example.com', 'e', 'admin', 'e2eadmin', 1);
SQL
  pocket_id_mint_token u-e2eadmin BOOTSTRAP
  pid_admin="$(pocket_id_session BOOTSTRAP)" || die "pocket-id: the bootstrap token did not mint a session"

  # padm <curl args…> — one admin-API call as the bootstrap admin.
  padm() { curl -sS -H "Cookie: $pid_admin" -H 'Content-Type: application/json' "$@"; }
  # pstatus <path> <json> — a POST/PUT whose only interesting result is its status.
  pstatus() { padm -o /tmp/pid.out -w '%{http_code}' -X "$1" "$POCKETID_URL$2" -d "$3" 2>/dev/null || true; }

  pid_client="$(padm -X POST "$POCKETID_URL/api/oidc/clients" \
    -d "{\"name\":\"jellyfin\",\"callbackURLs\":[\"$JELLYFIN/sso/OID/redirect/$PROVIDER\"],\"isPublic\":false,\"pkceEnabled\":true}" \
    2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)"
  [ -n "$pid_client" ] || die "pocket-id: the OIDC client create returned no id"
  CLIENT_ID="$pid_client"
  CLIENT_SECRET="$(padm -X POST "$POCKETID_URL/api/oidc/clients/$pid_client/secret" 2>/dev/null | jq -r '.secret // empty' 2>/dev/null || true)"
  [ -n "$CLIENT_SECRET" ] || die "pocket-id: the OIDC client secret create returned no secret"

  pid_group="$(padm -X POST "$POCKETID_URL/api/user-groups" \
    -d '{"name":"jellyfin-access","friendlyName":"jellyfin-access"}' 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)"
  [ -n "$pid_group" ] || die "pocket-id: the user-group create returned no id"

  # displayName is REQUIRED here — omitting it is a 400, not a defaulted field.
  POCKETID_ALICE="$(padm -X POST "$POCKETID_URL/api/users" \
    -d '{"username":"alice","email":"alice@example.com","firstName":"a","lastName":"lice","displayName":"alice","isAdmin":false}' \
    2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)"
  [ -n "$POCKETID_ALICE" ] || die "pocket-id: the alice create returned no id"
  POCKETID_BOB="$(padm -X POST "$POCKETID_URL/api/users" \
    -d '{"username":"bob","email":"bob@example.com","firstName":"b","lastName":"ob","displayName":"bob","isAdmin":false}' \
    2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)"
  [ -n "$POCKETID_BOB" ] || die "pocket-id: the bob create returned no id"

  # alice is in the group, bob is not — the same split every other harness uses. A failure here would make
  # the role gate's positive and negative cases indistinguishable, so it is fatal rather than logged.
  pid_assign="$(pstatus PUT "/api/users/$POCKETID_ALICE/user-groups" "{\"userGroupIds\":[\"$pid_group\"]}")"
  case "$pid_assign" in
    2*) : ;;
    *) die "pocket-id: putting alice in the jellyfin-access group returned HTTP ${pid_assign:-000}: $(head -c 300 /tmp/pid.out 2>/dev/null)" ;;
  esac

  log "Pocket ID seeded (client_id=$CLIENT_ID, group=$pid_group)"
}

idp_seed() {
  case "$IDP_KIND" in
    pocket-id) seed_pocket_id; return 0 ;;
    kanidm)    seed_kanidm; return 0 ;;
    zitadel)   : ;;
    *)         return 0 ;;
  esac

  log "== Seeding Zitadel (project, OIDC app, role, users) =="
  [ -s "$ZITADEL_PAT_PATH" ] || die "zitadel: no personal access token at $ZITADEL_PAT_PATH (the instance never finished its setup migration)"
  zpat="$(cat "$ZITADEL_PAT_PATH")"

  # zapi <method> <path> <json> — one management-API call. It leaves the response body in /tmp/z.out and
  # RETURNS a status rather than printing the body, so every call site can be `|| die`. A helper that
  # died internally would be a lie here: `die` inside a `$(...)` only exits the SUBSHELL, so a failed
  # call whose output nobody read would carry on silently and be misattributed to the plugin later.
  zapi() {
    zout="$(curl -sS -o /tmp/z.out -w '%{http_code}' -X "$1" "$ZITADEL_URL$2" \
      -H "Authorization: Bearer $zpat" -H "Content-Type: application/json" -d "$3" 2>/dev/null || true)"
    case "$zout" in
      2*) return 0 ;;
      *) log "zitadel: $1 $2 returned HTTP ${zout:-000}: $(head -c 300 /tmp/z.out 2>/dev/null)"; return 1 ;;
    esac
  }

  # projectRoleAssertion puts the granted roles into the id_token at all; without it the role claim is
  # simply absent and every role-gated login is refused for the wrong reason. The project and org checks
  # stay OFF so bob can authenticate without a grant — the harness needs him to reach the PLUGIN's role
  # gate, not to be stopped at Zitadel's.
  zapi POST /management/v1/projects '{"name":"jellyfin","projectRoleAssertion":true,"projectRoleCheck":false,"hasProjectCheck":false}' \
    || die "zitadel: the project create failed"
  # Read the id from the CREATE response, never from a project search: Zitadel's own internal ZITADEL
  # project already exists and sorts first, so a search would silently seed the wrong project.
  zproject="$(jq -r '.id // empty' /tmp/z.out 2>/dev/null || true)"
  [ -n "$zproject" ] || die "zitadel: the project create returned no id"

  zapi POST "/management/v1/projects/$zproject/apps/oidc" "$(cat <<JSON
{
  "name": "jellyfin-oidc",
  "redirectUris": ["$JELLYFIN/sso/OID/redirect/$PROVIDER"],
  "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
  "grantTypes": ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"],
  "appType": "OIDC_APP_TYPE_WEB",
  "authMethodType": "OIDC_AUTH_METHOD_TYPE_BASIC",
  "devMode": true,
  "accessTokenRoleAssertion": true,
  "idTokenRoleAssertion": true,
  "idTokenUserinfoAssertion": true
}
JSON
)" || die "zitadel: the OIDC app create failed"
  # devMode allows the plaintext-http redirect URI this stack uses; idTokenRoleAssertion is what actually
  # puts urn:zitadel:iam:org:project:roles into the id_token.
  CLIENT_ID="$(jq -r '.clientId // empty' /tmp/z.out 2>/dev/null || true)"
  CLIENT_SECRET="$(jq -r '.clientSecret // empty' /tmp/z.out 2>/dev/null || true)"
  [ -n "$CLIENT_ID" ] || die "zitadel: the app create returned no client id"
  [ -n "$CLIENT_SECRET" ] || die "zitadel: the app create returned no client secret"

  zapi POST "/management/v1/projects/$zproject/roles" '{"roleKey":"jellyfin-access","displayName":"jellyfin-access"}' \
    || die "zitadel: the role create failed — the role gate would then be untestable, not merely unsatisfied"

  # alice is granted the role, bob is not — the same split every other harness uses.
  zapi POST /management/v1/users/human/_import "$(cat <<JSON
{"userName":"alice","profile":{"firstName":"a","lastName":"lice"},"email":{"email":"alice@example.com","isEmailVerified":true},"password":"$PASSWORD_ALICE","passwordChangeRequired":false}
JSON
)" || die "zitadel: the alice import failed"
  zalice="$(jq -r '.userId // empty' /tmp/z.out 2>/dev/null || true)"
  [ -n "$zalice" ] || die "zitadel: the alice import returned no user id"

  zapi POST "/management/v1/users/$zalice/grants" "{\"projectId\":\"$zproject\",\"roleKeys\":[\"jellyfin-access\"]}" \
    || die "zitadel: granting alice the role failed — she would then be refused for the same reason as bob, making the role gate's positive and negative cases indistinguishable"

  zapi POST /management/v1/users/human/_import "$(cat <<JSON
{"userName":"bob","profile":{"firstName":"b","lastName":"ob"},"email":{"email":"bob@example.com","isEmailVerified":true},"password":"$PASSWORD_BOB","passwordChangeRequired":false}
JSON
)" || die "zitadel: the bob import failed"

  # Zitadel publishes an EMPTY JWKS until its "web key" feature is enabled: it still signs id_tokens, so
  # every login fails with invalid_signature and nothing in the login path says why. Turning the feature on
  # makes it generate and publish an RS256 key.
  zapi PUT /v2beta/features/instance '{"webKey":true}' || die "zitadel: enabling the web-key feature failed"

  # Key generation is asynchronous, so wait for it here rather than letting the shared signing assertion
  # below race it. Failing to appear is fatal: without a published key no login can ever verify.
  zwait=0
  while [ "$zwait" -lt 24 ]; do
    [ "$(curl -fsS "$ZITADEL_URL/oauth/v2/keys" 2>/dev/null | jq -r '.keys | length' 2>/dev/null || echo 0)" -ge 1 ] 2>/dev/null && break
    zwait=$((zwait + 1))
    sleep 5
  done
  [ "$zwait" -lt 24 ] || die "zitadel: the JWKS published no signing key within 2 minutes of enabling the web-key feature"

  log "Zitadel seeded (project=$zproject, client_id=$CLIENT_ID), signing key published"
}
idp_seed


# The id_token must be signed with an ASYMMETRIC, JWKS-verifiable algorithm. An identity provider that falls
# back to symmetric HS256 (authentik silently does this when its provider has no signing key) makes the RP
# reject every login with invalid_signature — an actually-hit failure. Assert the advertised algorithm here so
# the regression names itself instead of surfacing as an opaque callback error mid-login.
DISCOVERY_DOC="$(curl -fsS "$DISCOVERY_URL" 2>/dev/null || true)"
DISCOVERY_ALGS="$(printf '%s' "$DISCOVERY_DOC" | jq -r '.id_token_signing_alg_values_supported // [] | join(",")' 2>/dev/null || true)"
JWKS_URI="$(printf '%s' "$DISCOVERY_DOC" | jq -r '.jwks_uri // empty' 2>/dev/null || true)"
# The advertised algorithm list alone is a capability claim; also require the JWKS to actually publish a key,
# so "RS256 supported" cannot pass while no verifiable key exists.
JWKS_KEYS=0
if [ -n "$JWKS_URI" ]; then
  JWKS_KEYS="$(curl -fsS "$JWKS_URI" 2>/dev/null | jq -r '.keys | length' 2>/dev/null || echo 0)"
fi
# Accept ANY asymmetric family (RS*/ES*/PS*/EdDSA) rather than RS256 alone — a correct provider may sign
# ES256 by default (Kanidm does), and pinning one algorithm would red a correctly-configured harness. The
# security property is unchanged: only a symmetric HS* (or `none`) is refused.
case "$DISCOVERY_ALGS" in
  *RS256* | *RS384* | *RS512* | *ES256* | *ES384* | *ES512* | *PS256* | *PS384* | *PS512* | *EdDSA*)
    if [ "${JWKS_KEYS:-0}" -ge 1 ] 2>/dev/null; then
      pass "provider advertises asymmetric id_token signing ($DISCOVERY_ALGS) and publishes $JWKS_KEYS JWKS key(s)"
    else
      fail "provider advertises asymmetric id_token signing ($DISCOVERY_ALGS) but its JWKS publishes no key — signature validation cannot succeed"
    fi
    ;;
  *) fail "provider advertises no asymmetric id_token signing algorithm (got '${DISCOVERY_ALGS:-<none>}') — a symmetric HS* fallback breaks signature validation" ;;
esac

# --------------------------------------------------------------------------------------------------
# Phase 1 — Jellyfin first-run wizard + admin token
# --------------------------------------------------------------------------------------------------
log "== Completing Jellyfin startup wizard =="
jf() {
  # jf METHOD PATH [json-body]
  method="$1"; path="$2"; body="${3:-}"
  if [ -n "$body" ]; then
    curl -fsS -X "$method" "$JELLYFIN$path" \
      -H "Content-Type: application/json" \
      -H "Authorization: $EMBY_AUTH" \
      -d "$body"
  else
    curl -fsS -X "$method" "$JELLYFIN$path" \
      -H "Content-Type: application/json" \
      -H "Authorization: $EMBY_AUTH"
  fi
}

# If the wizard is already complete (a re-run against a persisted /config), skip it.
WIZARD_DONE="$(curl -fsS "$JELLYFIN/System/Info/Public" | jq -r '.StartupWizardCompleted // false')"
if [ "$WIZARD_DONE" != "true" ]; then
  # Jellyfin answers /System/Info/Public before the startup-wizard controller is fully ready, so poll the
  # wizard config endpoint until it responds — otherwise a fast-booting IdP (e.g. Authelia over TLS) lets
  # the harness race ahead of Jellyfin and the first wizard call fails intermittently (#921).
  w=0
  while [ "$w" -lt 30 ] && ! jf GET "/Startup/Configuration" >/dev/null 2>&1; do
    w=$((w + 1)); sleep 2
  done
  jf GET  "/Startup/Configuration" >/dev/null || die "wizard: get configuration failed"
  jf POST "/Startup/Configuration" '{"UICulture":"en-US","MetadataCountryCode":"US","PreferredMetadataLanguage":"en"}' >/dev/null || die "wizard: set configuration failed"
  jf GET  "/Startup/User" >/dev/null || die "wizard: get user failed"
  jf POST "/Startup/User" "{\"Name\":\"$ADMIN_USER\",\"Password\":\"$ADMIN_PASS\"}" >/dev/null || die "wizard: create admin failed"
  jf POST "/Startup/RemoteAccess" '{"EnableRemoteAccess":true,"EnableAutomaticPortMapping":false}' >/dev/null || die "wizard: remote access failed"
  jf POST "/Startup/Complete" '' >/dev/null || die "wizard: complete failed"
  log "Wizard complete; admin '$ADMIN_USER' created"
else
  log "Wizard already complete; reusing existing server"
fi

log "== Authenticating as admin =="
AUTH_JSON="$(curl -fsS -X POST "$JELLYFIN/Users/AuthenticateByName" \
  -H "Content-Type: application/json" \
  -H "Authorization: $EMBY_AUTH" \
  -d "{\"Username\":\"$ADMIN_USER\",\"Pw\":\"$ADMIN_PASS\"}")" || die "admin authenticate failed"
ADMIN_TOKEN="$(printf '%s' "$AUTH_JSON" | jq -r '.AccessToken')"
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] || die "no admin access token minted"
log "Admin token acquired"

# --------------------------------------------------------------------------------------------------
# Phase 2 — configure the OpenID provider through the plugin admin API
# --------------------------------------------------------------------------------------------------
log "== Configuring OpenID provider '$PROVIDER' =="
# DisableHttps: the containerised Keycloak issuer is plaintext http (a test-IdP quirk); this is the
#   existing per-provider escape hatch, not a production default change.
# DoNotLoadProfile: the id_token is the whole identity (username + realm_access.roles), so no userinfo
#   fetch is needed — mirrors the in-repo OidcRoundTripTests.
# DisablePushedAuthorization: keep the challenge a plain redirect the harness can follow with curl.
# Roles + RoleClaim: the login allow-list. alice carries realm_access.roles=["jellyfin-access"]; bob
#   does not, so bob is refused at the callback.
OID_CONFIG="$(cat <<JSON
{
  "OidEndpoint": "$OID_ENDPOINT",
  "OidClientId": "$CLIENT_ID",
  "OidSecret": "$CLIENT_SECRET",
  "Enabled": true,
  "OidScopes": $OID_SCOPES_JSON,
  "DoNotLoadProfile": $DO_NOT_LOAD_PROFILE,
  "DisablePushedAuthorization": true,
  "DisableHttps": $DISABLE_HTTPS,
  "EnableAuthorization": true,
  "Roles": $OID_ROLES_JSON,
  "AdminRoles": $ADMIN_ROLES_JSON,
  "RoleClaim": "$ROLE_CLAIM",
  "RoleClaimIsObjectMap": $ROLE_CLAIM_IS_OBJECT_MAP,
  "DefaultUsernameClaim": "$USERNAME_CLAIM"
}
JSON
)"
ADD_STATUS="$(curl -sS -o /tmp/add.out -w '%{http_code}' -X POST "$JELLYFIN/sso/OID/Add/$PROVIDER" \
  -H "Content-Type: application/json" \
  -H "Authorization: MediaBrowser Token=\"$ADMIN_TOKEN\"" \
  -d "$OID_CONFIG")" || true
if [ "$ADD_STATUS" != "200" ] && [ "$ADD_STATUS" != "204" ]; then
  log "OID/Add returned HTTP $ADD_STATUS: $(cat /tmp/add.out 2>/dev/null)"
  die "OID/Add failed (is the plugin loaded? a 404 means it is not)"
fi
log "Provider configured"

# --------------------------------------------------------------------------------------------------
# Phase 3 — assert the plugin loaded and the provider is enabled (milestone 1)
# --------------------------------------------------------------------------------------------------
log "== Asserting plugin loaded (GET /sso/OID/GetNames) =="
NAMES="$(curl -fsS "$JELLYFIN/sso/OID/GetNames")" || die "GetNames request failed"
log "GetNames => $NAMES"
if printf '%s' "$NAMES" | jq -e --arg p "$PROVIDER" 'index($p)' >/dev/null 2>&1; then
  pass "plugin loaded and provider '$PROVIDER' is listed by GetNames"
else
  fail "provider '$PROVIDER' not listed by GetNames (plugin may not have loaded)"
fi

# --------------------------------------------------------------------------------------------------
# OIDC browser-role helpers
# --------------------------------------------------------------------------------------------------
# extract_binding <headers_file> : prints the browser-binding cookie value from a /start response's
# Set-Cookie headers.
extract_binding() {
  grep -i '^set-cookie:' "$1" 2>/dev/null | grep -o "$BINDING_COOKIE_NAME=[^;]*" | head -1 | cut -d= -f2-
}

# oid_start <cookiejar> <start_headers_file> : calls the plugin's provider-agnostic OID /start, writes the
# response headers (carrying the browser-binding Set-Cookie) to the headers file, and prints the IdP authorize
# URL it 302s to on stdout. Diagnostics to stderr.
oid_start() {
  jar="$1"; start_hdr="$2"
  start_out="$(curl -sS -D "$start_hdr" -o /dev/null -c "$jar" -b "$jar" -w '%{http_code} %{redirect_url}' "$JELLYFIN/sso/OID/start/$PROVIDER")"
  start_code="${start_out%% *}"; auth_url="${start_out#* }"
  printf 'oid_start: /start -> HTTP %s location=%s\n' "$start_code" "$auth_url" >&2
  if [ -z "$auth_url" ]; then
    printf 'oid_start: /start returned no redirect; body was:\n' >&2
    curl -sS -c "$jar" -b "$jar" "$JELLYFIN/sso/OID/start/$PROVIDER" >&2 || true
    return 1
  fi
  printf '%s' "$auth_url"
}

# authentik_run_flow <jar> <flow_page_url> <user> <pass> : drives ANY authentik flow executor to completion
# and prints the ABSOLUTE completion redirect target. authentik chains flows — a login runs the
# authentication flow and THEN the provider's authorization flow — and uses the same executor for all of
# them, so this is generic over the flow slug and over the interactive (identification/password) and
# non-interactive (implicit consent) stages alike. The executor is STATEFUL: each call advances it, so this
# issues exactly one request per logical step and follows redirects to reach the next stage.
authentik_run_flow() {
  jar="$1"; flow_url="$2"; user="$3"; pass="$4"
  # `sed` leaves its input UNCHANGED when there is no "?", so a non-flow landing would otherwise be fed to
  # the executor as a plausible query.
  case "$flow_url" in
    */if/flow/*/\?*) : ;;
    *) printf 'authentik_run_flow: not a flow page: %s\n' "${flow_url%%\?*}" >&2; return 1 ;;
  esac
  slug="$(printf '%s' "$flow_url" | sed -E 's#.*/if/flow/([^/]+)/.*#\1#')"
  flow_query="$(printf '%s' "$flow_url" | sed 's#[^?]*?##')"
  q_enc="$(printf '%s' "$flow_query" | jq -rR '@uri')"
  exec_url="$AUTHENTIK_URL/api/v3/flows/executor/$slug/?query=$q_enc"
  step=0
  while [ "$step" -lt 8 ]; do
    step=$((step + 1))
    stage="$(curl -sSL -c "$jar" -b "$jar" "$exec_url")" || { printf 'authentik_run_flow[%s]: executor GET failed\n' "$slug" >&2; return 1; }
    comp="$(printf '%s' "$stage" | jq -r '.component // empty' 2>/dev/null)"
    case "$comp" in
      ak-stage-identification)
        # -f: without it curl exits 0 on a 4xx and this guard would be dead code.
        curl -fsS -c "$jar" -b "$jar" -H "Content-Type: application/json" \
          -d "{\"component\":\"ak-stage-identification\",\"uid_field\":\"$user\"}" "$exec_url" >/dev/null \
          || { printf 'authentik_run_flow[%s]: identification POST failed\n' "$slug" >&2; return 1; }
        ;;
      ak-stage-password)
        curl -fsS -c "$jar" -b "$jar" -H "Content-Type: application/json" \
          -d "{\"component\":\"ak-stage-password\",\"password\":\"$pass\"}" "$exec_url" >/dev/null \
          || { printf 'authentik_run_flow[%s]: password POST failed\n' "$slug" >&2; return 1; }
        ;;
      xak-flow-redirect)
        redir_to="$(printf '%s' "$stage" | jq -r '.to // empty' 2>/dev/null)"
        [ -n "$redir_to" ] || { printf 'authentik_run_flow[%s]: redirect stage carried no target\n' "$slug" >&2; return 1; }
        case "$redir_to" in /*) redir_to="$AUTHENTIK_URL$redir_to" ;; esac
        printf '%s' "$redir_to"
        return 0
        ;;
      ak-stage-autosubmit)
        # How authentik delivers a SAML POST-binding response: the stage carries the target `url` and the
        # form fields in `attrs` as JSON rather than rendered HTML. Synthesise the equivalent auto-submit
        # form so the shared, provider-agnostic parser can consume it, and signal that with rc 3 (the body,
        # not a redirect target, is on stdout).
        # jq defines "s" + null == "s", so a missing `url` or a null field would render a plausible-looking
        # but broken form and the guard below would be DEAD code. Force an error on each required piece
        # instead, so a shape drift fails here rather than downstream as an opaque ACS 400.
        printf '%s' "$stage" | jq -r '"<form action=\"" + (.url // error("autosubmit stage carried no url")) + "\">"
          + ((.attrs // error("autosubmit stage carried no attrs")) | to_entries
             | map("<input name=\"" + .key + "\" value=\"" + (.value // error("autosubmit attr \(.key) was null") | tostring) + "\">")
             | join(""))
          + "</form>"' 2>/dev/null \
          || { printf 'authentik_run_flow[%s]: could not render the autosubmit stage\n' "$slug" >&2; return 1; }
        return 3
        ;;
      "")
        printf 'authentik_run_flow[%s]: executor returned no stage (login rejected?)\n' "$slug" >&2
        return 1
        ;;
      *)
        printf 'authentik_run_flow[%s]: unhandled stage %s\n' "$slug" "$comp" >&2
        return 1
        ;;
    esac
  done
  printf 'authentik_run_flow[%s]: flow did not complete within 8 steps\n' "$slug" >&2
  return 1
}

# idp_oidc_login <cookiejar> <start_headers_file> <user> <pass> : drives the full browser-role login at the
# identity provider and prints the plugin CALLBACK url (/sso/OID/redirect/<provider>?code&state) on stdout;
# it writes the /start headers to start_hdr. Dispatches on IDP_KIND — Keycloak renders a server-side HTML
# login form; Authelia is a JSON-API login portal. Returns non-zero on a transport break. Diagnostics to
# stderr so they are not captured by the caller's $(...).
# Reads one query parameter out of the authorize URL the PLUGIN issued. The `[?&]` anchor and the literal
# `=` are what keep a name from matching inside a longer one (code_challenge vs code_challenge_method), in
# either order. Used by the providers whose authorize endpoint is a single-page app rather than something a
# browser role can simply follow, so the request has to be re-issued to their API — from the plugin's own
# parameters, never hand-built ones.
auth_url_param() { printf '%s' "$auth_url" | sed -n "s/.*[?&]$1=\([^&]*\).*/\1/p"; }

idp_oidc_login() {
  jar="$1"; start_hdr="$2"; user="$3"; pass="$4"
  auth_url="$(oid_start "$jar" "$start_hdr")" || return 1
  case "$IDP_KIND" in
    kanidm)
      # Kanidm's authorization endpoint is its consent SPA, so the driver replays the request to the API the
      # SPA uses — the same shape as the Pocket ID arm, and for the same reason.
      kan_token="$(kanidm_auth "$user" "$pass")" || { printf 'idp_oidc_login[kanidm]: %s could not authenticate\n' "$user" >&2; return 1; }

      kan_state="$(auth_url_param state)"
      kan_scope="$(auth_url_param scope | sed 's/%20/ /g')"
      kan_challenge="$(auth_url_param code_challenge)"
      kan_method="$(auth_url_param code_challenge_method)"
      kan_client="$(auth_url_param client_id)"
      kan_redirect="$(auth_url_param redirect_uri)"
      for kan_have in "$kan_state" "$kan_scope" "$kan_challenge" "$kan_method" "$kan_client" "$kan_redirect"; do
        [ -n "$kan_have" ] || { printf 'idp_oidc_login[kanidm]: the plugin authorize URL is missing a parameter this driver needs: %s\n' "$auth_url" >&2; return 1; }
      done
      # Assert the plugin's own redirect_uri, then send it: otherwise both sides of the redirect-URI
      # equality check would be harness-supplied and a challenge-time regression would pass unnoticed.
      kan_expect="$(jq -rn --arg s "$JELLYFIN/sso/OID/redirect/$PROVIDER" '$s|@uri')"
      if [ "$kan_redirect" != "$kan_expect" ]; then
        printf 'idp_oidc_login[kanidm]: the plugin issued redirect_uri=%s, not %s — a real browser login would be refused as an unregistered origin\n' \
          "$kan_redirect" "$kan_expect" >&2
        return 1
      fi

      kan_body="$(jq -nc --arg cid "$kan_client" --arg scope "$kan_scope" --arg redir "$JELLYFIN/sso/OID/redirect/$PROVIDER" \
        --arg state "$kan_state" --arg cc "$kan_challenge" --arg ccm "$kan_method" \
        '{client_id:$cid,response_type:"code",scope:$scope,redirect_uri:$redir,state:$state,code_challenge:$cc,code_challenge_method:$ccm}')"
      # Capture the STATUS, not just the body: the failure this design most needs to name is Kanidm itself
      # refusing a user (403, empty body) because the scope map ended up on the role group — without the
      # status that reads exactly like a wrong password. `-f` is deliberately not used, since a 4xx body is
      # the diagnostic.
      kan_status="$(curl -sS -D /tmp/kan.ah -o /tmp/kan.ab -w '%{http_code}' -H "Authorization: Bearer $kan_token" \
        -H 'Content-Type: application/json' -X POST "$KANIDM_URL/oauth2/authorise" -d "$kan_body" 2>/dev/null || true)"
      case "${kan_status:-000}" in
        2*) : ;;
        403) printf 'idp_oidc_login[kanidm]: Kanidm refused %s at the authorise step (HTTP 403) — the OAuth2 scope map does not cover this user, so the PLUGIN never sees the login\n' "$user" >&2; return 1 ;;
        *)   printf 'idp_oidc_login[kanidm]: authorise returned HTTP %s for %s: %s\n' "${kan_status:-000}" "$user" "$(head -c 200 /tmp/kan.ab)" >&2; return 1 ;;
      esac

      # First login for a user+client asks for consent; afterwards the same call answers "Permitted"
      # outright. Both end with the callback in a Location header.
      kan_consent="$(jq -r '.ConsentRequested.consent_token // empty' /tmp/kan.ab 2>/dev/null || true)"
      if [ -n "$kan_consent" ]; then
        # The permit body is a BARE JSON STRING, not an object — an object is a 422.
        kan_status="$(curl -sS -D /tmp/kan.ah -o /tmp/kan.ab -w '%{http_code}' -H "Authorization: Bearer $kan_token" \
          -H 'Content-Type: application/json' -X POST "$KANIDM_URL/oauth2/authorise/permit" -d "\"$kan_consent\"" 2>/dev/null || true)"
        case "${kan_status:-000}" in
          2*) : ;;
          *) printf 'idp_oidc_login[kanidm]: the consent permit returned HTTP %s: %s\n' "${kan_status:-000}" "$(head -c 200 /tmp/kan.ab)" >&2; return 1 ;;
        esac
      fi

      kan_cb="$(grep -i '^location:' /tmp/kan.ah | sed -e 's/^[Ll]ocation: //' | tr -d '\r\n')"
      if [ -z "$kan_cb" ]; then
        printf 'idp_oidc_login[kanidm]: no callback location for %s; authorise said: %s\n' "$user" "$(head -c 200 /tmp/kan.ab)" >&2
        return 1
      fi
      printf '%s' "$kan_cb"
      ;;

    keycloak | dex)
      # Both render a server-side HTML login form, so they share this path; they differ only in the form's
      # user field name (LOGIN_USER_FIELD) and in whether the action is absolute (Keycloak) or site-relative
      # (Dex). `credentialId` is Keycloak's hidden field; an extra field is ignored by Dex.
      login_page="$(curl -sSL -c "$jar" -b "$jar" -w '\n__HTTP__%{http_code}' "$auth_url")" || { printf 'idp_oidc_login[%s]: login page curl failed\n' "$IDP_KIND" >&2; return 1; }
      page_code="$(printf '%s' "$login_page" | sed -n 's/.*__HTTP__\([0-9]*\)$/\1/p')"
      printf 'idp_oidc_login[%s]: authorize page -> HTTP %s\n' "$IDP_KIND" "$page_code" >&2
      form_action="$(printf '%s' "$login_page" | grep -oE 'action="[^"]*"' | head -1 | sed -e 's/^action="//' -e 's/"$//' -e 's/&amp;/\&/g')"
      if [ -z "$form_action" ]; then
        printf 'idp_oidc_login[%s]: could not parse a form action; first 1200 chars:\n%s\n' "$IDP_KIND" "$(printf '%s' "$login_page" | head -c 1200)" >&2
        return 1
      fi
      # A site-relative action must be resolved against the provider origin, or curl rejects it outright.
      case "$form_action" in
        /*) form_action="$(printf '%s' "$auth_url" | sed -E 's#^(https?://[^/]+).*#\1#')$form_action" ;;
      esac
      printf 'idp_oidc_login[%s]: form action=%s\n' "$IDP_KIND" "${form_action%%\?*}" >&2
      # The provider 302s back to the plugin callback with code + state.
      curl -fsS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' \
        --data-urlencode "$LOGIN_USER_FIELD=$user" \
        --data-urlencode "password=$pass" \
        --data-urlencode "credentialId=" \
        "$form_action"
      ;;
    pocket-id)
      # Pocket ID has NO password login — passkeys only — so there is no form to drive. The browser role is
      # played through the provider's own one-time-access-token flow (the mechanism it ships for a lost
      # passkey): mint the user a token, exchange it for the session cookie a passkey login would have set,
      # then re-drive the authorize carrying that cookie explicitly (it is marked Secure, so curl will not
      # replay it over this stack's plaintext http on its own).
      case "$user" in
        alice) pid_user="$POCKETID_ALICE" ;;
        bob)   pid_user="$POCKETID_BOB" ;;
        *) printf 'idp_oidc_login[pocket-id]: no seeded user id for "%s"\n' "$user" >&2; return 1 ;;
      esac
      [ -n "$pid_user" ] || { printf 'idp_oidc_login[pocket-id]: seeded user id for %s is empty\n' "$user" >&2; return 1; }
      # A distinct token per login: they are one-time, so reusing one would fail the SECOND round-trip only
      # and read as an authentication failure.
      pocket_id_mint_token "$pid_user" "LOGIN$user"
      pid_cookie="$(pocket_id_session "LOGIN$user")" || { printf 'idp_oidc_login[pocket-id]: the one-time token for %s minted no session\n' "$user" >&2; return 1; }

      # Pocket ID's /authorize is its single-page app, not an endpoint — following it just returns HTML. The
      # page posts the authorize request to the API and gets the code back as JSON, so the driver does the
      # same, taking every parameter from the URL the PLUGIN issued (never a hand-built one, or the test
      # would stop exercising what the plugin actually sends).
      pid_state="$(auth_url_param state)"
      pid_scope="$(auth_url_param scope | sed 's/%20/ /g')"
      pid_challenge="$(auth_url_param code_challenge)"
      pid_method="$(auth_url_param code_challenge_method)"
      pid_client="$(auth_url_param client_id)"
      # redirect_uri MUST come from the plugin too, and be the value posted to the provider. Hand-building
      # it would leave BOTH sides of the redirect-URI equality check harness-supplied — the plugin derives
      # its token-exchange redirect_uri from the callback path it is handed — so a regression in the
      # CHALLENGE-time URI (#98's wrong `r`/`redirect` segment, a wrong canonical base) would sail through
      # green here while every other harness reds. Posting the plugin's own value makes Pocket ID's
      # registered-callback check the detector, and the assertion below names a mismatch outright.
      pid_redirect="$(auth_url_param redirect_uri)"
      for pid_have in "$pid_state" "$pid_scope" "$pid_challenge" "$pid_method" "$pid_client" "$pid_redirect"; do
        [ -n "$pid_have" ] || { printf 'idp_oidc_login[pocket-id]: the plugin authorize URL is missing a parameter this driver needs: %s\n' "$auth_url" >&2; return 1; }
      done
      # Compare in the ENCODED form the URL carries: busybox printf's %b has no \xHH, so there is no
      # dependable percent-decoder here, while jq's @uri reproduces the exact encoding the plugin's OIDC
      # client emits. Only after this holds is the decoded literal posted below.
      pid_expect="$(jq -rn --arg s "$JELLYFIN/sso/OID/redirect/$PROVIDER" '$s|@uri')"
      if [ "$pid_redirect" != "$pid_expect" ]; then
        printf 'idp_oidc_login[pocket-id]: the plugin issued redirect_uri=%s, not %s — a real browser login would be refused as an unregistered callback\n' \
          "$pid_redirect" "$pid_expect" >&2
        return 1
      fi

      pid_auth="$(curl -sS -H "Cookie: $pid_cookie" -H 'Content-Type: application/json' -X POST "$POCKETID_URL/api/oidc/authorize" \
        -d "{\"scope\":\"$pid_scope\",\"callbackURL\":\"$JELLYFIN/sso/OID/redirect/$PROVIDER\",\"clientId\":\"$pid_client\",\"codeChallenge\":\"$pid_challenge\",\"codeChallengeMethod\":\"$pid_method\"}" 2>/dev/null || true)"
      pid_code="$(printf '%s' "$pid_auth" | jq -r '.code // empty' 2>/dev/null || true)"
      pid_cb="$(printf '%s' "$pid_auth" | jq -r '.callbackURL // empty' 2>/dev/null || true)"
      # Pocket ID returns the issuer alongside the code precisely because the redirect carries it: the
      # plugin enforces the RFC 9207 mix-up check and refuses an authorization response without a matching
      # `iss`. Dropping it here would refuse every login for a reason that has nothing to do with the test.
      pid_iss="$(printf '%s' "$pid_auth" | jq -r '.issuer // empty' 2>/dev/null || true)"
      if [ -z "$pid_code" ] || [ -z "$pid_cb" ] || [ -z "$pid_iss" ]; then
        printf 'idp_oidc_login[pocket-id]: the authorize call returned no code/callback/issuer: %s\n' "$(printf '%s' "$pid_auth" | head -c 300)" >&2
        return 1
      fi
      # Hand back exactly what the browser would have been redirected to.
      printf '%s?code=%s&state=%s&iss=%s' "$pid_cb" "$pid_code" "$pid_state" "$pid_iss"
      ;;

    zitadel)
      # Zitadel's hosted login is a CHAIN of single-form pages (login name, then password, then a
      # two-factor SETUP prompt this stack has nothing configured for). Each page carries a CSRF token and
      # the auth-request id as hidden fields, so the chain is driven generically: read the one form, post
      # its hidden fields plus the one credential that step asks for, repeat. The step is chosen by the
      # form's action, and an ACTION THIS DRIVER DOES NOT KNOW IS A LOUD FAILURE naming it — never a
      # silent skip, which would let a changed login flow look like an authentication failure.
      curl -sSL -c "$jar" -b "$jar" -o /tmp/z.page "$auth_url" || { printf 'idp_oidc_login[zitadel]: authorize GET failed\n' >&2; return 1; }
      z_hidden() { grep -oE "name=\"$1\" value=\"[^\"]*\"" /tmp/z.page | head -1 | sed -e 's/.*value="//' -e 's/"$//'; }
      z_action() { grep -oE '<form action="[^"]*"' /tmp/z.page | head -1 | sed -e 's/.*action="//' -e 's/"$//'; }
      z_step=0
      z_callback=""
      z_prev=""
      # Bounded: a chain that never leaves Zitadel must end as a failure, not spin.
      while [ "$z_step" -lt 6 ]; do
        z_step=$((z_step + 1))
        z_form="$(z_action)"
        # Re-rendering the SAME form means the step was refused (a wrong password is the common case). Say
        # that, instead of burning the remaining steps and then reporting the useless "never reached the
        # callback" — the authentik driver makes the same no-progress distinction.
        if [ "$z_form" = "$z_prev" ]; then
          printf 'idp_oidc_login[zitadel]: step %s re-rendered %s — the previous step was refused (wrong credentials, or that step needs input this driver does not supply)\n' "$z_step" "$z_form" >&2
          return 1
        fi
        z_prev="$z_form"
        if [ -z "$z_form" ]; then
          printf 'idp_oidc_login[zitadel]: step %s has no form; first 600 chars:\n%s\n' "$z_step" "$(head -c 600 /tmp/z.page)" >&2
          return 1
        fi
        case "$z_form" in
          */loginname) z_field="loginName=$user" ;;
          */password)  z_field="password=$pass" ;;
          */mfa/prompt) z_field="skip=true" ;;
          *)
            printf 'idp_oidc_login[zitadel]: unknown login step "%s" — the hosted login flow changed; teach this driver the step rather than skipping it\n' "$z_form" >&2
            return 1
            ;;
        esac
        z_redirect="$(curl -sS -c "$jar" -b "$jar" -o /tmp/z.next -w '%{redirect_url}' -X POST "$ZITADEL_URL$z_form" \
          --data-urlencode "gorilla.csrf.Token=$(z_hidden 'gorilla.csrf.Token')" \
          --data-urlencode "authRequestID=$(z_hidden authRequestID)" \
          --data-urlencode "$z_field")" || { printf 'idp_oidc_login[zitadel]: POST %s failed\n' "$z_form" >&2; return 1; }
        mv /tmp/z.next /tmp/z.page
        printf 'idp_oidc_login[zitadel]: step %s %s -> %s\n' "$z_step" "$z_form" "${z_redirect:-<rendered next form>}" >&2
        case "$z_redirect" in
          "") : ;;                                   # the next form was rendered in place; keep going
          "$ZITADEL_URL"/oauth/v2/authorize/callback*)
            # Authentication finished: this Zitadel-internal hop resumes the authorize and 302s to the
            # plugin's redirect URI with code + state. Capture that, do NOT follow into the plugin.
            z_callback="$(curl -sS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$z_redirect")"
            break
            ;;
          *)
            printf 'idp_oidc_login[zitadel]: step %s redirected out of the login flow to %s\n' "$z_step" "$z_redirect" >&2
            return 1
            ;;
        esac
      done
      [ -n "$z_callback" ] || { printf 'idp_oidc_login[zitadel]: the login chain never reached the authorize callback\n' >&2; return 1; }
      printf '%s' "$z_callback"
      ;;

    authelia)
      # Prime the Authelia session cookie by following the authorize redirect into the login portal.
      curl -sSL -c "$jar" -b "$jar" -o /dev/null "$auth_url" || { printf 'idp_oidc_login[authelia]: portal GET failed\n' >&2; return 1; }
      # First factor via the JSON API; the session cookie in the jar carries the flow, and targetURL is the
      # original authorize URL so Authelia resumes the OIDC exchange after a successful login.
      ff="$(curl -sS -c "$jar" -b "$jar" -X POST "$AUTHELIA_URL/api/firstfactor" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "{\"username\":\"$user\",\"password\":\"$pass\",\"keepMeLoggedIn\":false,\"targetURL\":\"$auth_url\",\"requestMethod\":\"GET\"}")" || { printf 'idp_oidc_login[authelia]: firstfactor POST failed\n' >&2; return 1; }
      printf 'idp_oidc_login[authelia]: firstfactor => %s\n' "$ff" >&2
      redir="$(printf '%s' "$ff" | jq -r '.data.redirect // empty' 2>/dev/null)"
      if [ -z "$redir" ]; then
        printf 'idp_oidc_login[authelia]: firstfactor returned no redirect (status=%s)\n' "$(printf '%s' "$ff" | jq -r '.status // "?"' 2>/dev/null)" >&2
        return 1
      fi
      printf 'idp_oidc_login[authelia]: resuming authorize at %s\n' "${redir%%\?*}?<query>" >&2
      # Resume the authorize with the authenticated session; consent is pre-configured/implicit, so it 302s
      # to the plugin callback with code + state. Capture that callback (do NOT follow into the plugin).
      curl -sS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$redir"
      ;;
    authentik)
      # authentik's login is a STATEFUL multi-stage flow-executor (a JSON API built for its SPA), not a form.
      # Follow the authorize redirect to the flow page — that seats the pending authorization in the session —
      # then drive the shared flow helper and resume the authorize it hands back. `-f` so a 4xx fails here.
      flow_url="$(curl -fsSL -c "$jar" -b "$jar" -o /dev/null -w '%{url_effective}' "$auth_url")" || { printf 'idp_oidc_login[authentik]: authorize follow failed\n' >&2; return 1; }
      redir_to="$(authentik_run_flow "$jar" "$flow_url" "$user" "$pass")" || return 1
      printf 'idp_oidc_login[authentik]: resuming authorize at %s\n' "${redir_to%%\?*}?<query>" >&2
      # Resume the authorize; it 302s to the plugin callback with code + state (do NOT follow into the plugin).
      curl -sS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$redir_to"
      ;;
    *)
      printf 'idp_oidc_login: unknown IDP_KIND=%s\n' "$IDP_KIND" >&2
      return 1
      ;;
  esac
}

# --------------------------------------------------------------------------------------------------
# Phase 4 — full OIDC round-trip for alice (milestone 2)
# --------------------------------------------------------------------------------------------------
log "== OIDC round-trip: alice (expect success) =="
JAR="$(mktemp)"
START_HDR="$(mktemp)"
CB_URL="$(idp_oidc_login "$JAR" "$START_HDR" alice "$PASSWORD_ALICE")" || die "alice: could not complete the IdP login"
BINDING="$(extract_binding "$START_HDR")"
[ -n "$BINDING" ] || die "alice: /start set no browser-binding cookie"
[ -n "$CB_URL" ] || die "alice: the IdP login produced no callback URL"
log "alice callback URL => ${CB_URL%%\?*}?<query>"
case "$CB_URL" in
  "$JELLYFIN"/sso/OID/redirect/*) : ;;
  *) die "alice: unexpected callback URL: $CB_URL" ;;
esac

# Follow the callback WITH the binding cookie (presented explicitly — see BINDING_COOKIE_NAME above) so
# the plugin's browser-binding check passes and it promotes the state to redeemable, and capture the
# intermediate auth page. The page embeds  var data = "<state>";  which is exactly what a real browser
# posts to OID/Auth.
AUTH_PAGE="$(curl -fsS -H "Cookie: $BINDING_COOKIE_NAME=$BINDING" "$CB_URL")" || die "alice: callback did not return the auth page"
STATE="$(printf '%s' "$AUTH_PAGE" | grep -oE 'var data = "[^"]*"' | head -1 | sed -e 's/^var data = "//' -e 's/"$//')"
[ -n "$STATE" ] || die "alice: could not extract state token from the auth page"

# Post to OID/Auth with the binding cookie -> the minted Jellyfin session (AuthenticationResult).
AUTH_RESULT="$(curl -fsS -H "Cookie: $BINDING_COOKIE_NAME=$BINDING" -X POST "$JELLYFIN/sso/OID/Auth/$PROVIDER" \
  -H "Content-Type: application/json" \
  -d "{\"deviceId\":\"$DEVICE_ID\",\"appName\":\"Jellyfin Web\",\"appVersion\":\"10.8.0\",\"deviceName\":\"$DEVICE\",\"data\":\"$STATE\"}")" || die "alice: OID/Auth failed"
JF_TOKEN="$(printf '%s' "$AUTH_RESULT" | jq -r '.AccessToken')"
JF_USER="$(printf '%s' "$AUTH_RESULT" | jq -r '.User.Name')"
if [ -n "$JF_TOKEN" ] && [ "$JF_TOKEN" != "null" ]; then
  pass "alice: Jellyfin session token minted (user='$JF_USER')"
else
  fail "alice: OID/Auth did not mint a session token"
fi

# The minted token must be usable against a real Jellyfin API.
if [ -n "${JF_TOKEN:-}" ] && [ "$JF_TOKEN" != "null" ]; then
  ME="$(curl -fsS "$JELLYFIN/Users/Me" -H "Authorization: MediaBrowser Token=\"$JF_TOKEN\"")" || ME=""
  ME_NAME="$(printf '%s' "$ME" | jq -r '.Name // empty' 2>/dev/null || true)"
  if [ "$ME_NAME" = "alice" ]; then
    pass "alice: session token works against GET /Users/Me (Name='alice')"
  else
    fail "alice: GET /Users/Me did not return the alice user (got '$ME_NAME')"
  fi
  # The account id and policy feed the extended phases (#928 U5): identity-binding compares this id on a
  # second login, and the admin-elevation assert reads the minted policy.
  ALICE_ID="$(printf '%s' "$ME" | jq -r '.Id // empty' 2>/dev/null || true)"
  ALICE_IS_ADMIN="$(printf '%s' "$ME" | jq -r '.Policy.IsAdministrator // false' 2>/dev/null || true)"
fi

# --------------------------------------------------------------------------------------------------
# Phase 5 — role-gate negative: bob is refused (milestone 3)
# --------------------------------------------------------------------------------------------------
# Gated on the SAME value that configures the gate: an empty allow-list means the plugin has no role gate to
# exercise (the only honest setting for a provider that cannot express groups, e.g. Dex's local password DB),
# so asserting one would test nothing. Reading the configured list — rather than a second switch — makes it
# impossible to skip a gate that IS configured, or to assert one that is not.
# `jq -e` as the condition itself, and an explicit `type == "array"`: a bare `jq length` would print 0 (and
# pick the skip branch) for a scalar, and would print the first value of a multi-value stream while
# discarding the parse error — a guard that answers on input it did not actually understand. Here anything
# that is not exactly an empty array — a malformed value, a scalar, a non-empty list — RUNS the gate.
if printf '%s' "$OID_ROLES_JSON" | jq -e 'type == "array" and length == 0' >/dev/null 2>&1; then
  log "== OIDC role-gate phase skipped (empty allow-list: this provider cannot express groups) =="
else
log "== OIDC round-trip: bob (expect role-gate refusal) =="
JAR_BOB="$(mktemp)"
START_HDR_BOB="$(mktemp)"
if CB_URL_BOB="$(idp_oidc_login "$JAR_BOB" "$START_HDR_BOB" bob "$PASSWORD_BOB")"; then
  BINDING_BOB="$(extract_binding "$START_HDR_BOB")"
  if [ -z "$CB_URL_BOB" ]; then
    fail "bob: the IdP did not redirect back (authentication itself failed unexpectedly)"
  elif [ -z "$BINDING_BOB" ]; then
    # Without the binding cookie a later refusal would be the BINDING gate, not the ROLE gate — that would
    # silently test the wrong control, so a missing cookie is a broken negative test, not a pass.
    fail "bob: /start set no browser-binding cookie (cannot isolate the role gate)"
  else
    case "$CB_URL_BOB" in
      "$JELLYFIN"/sso/OID/redirect/*) : ;;
      *) fail "bob: unexpected callback URL (not the plugin callback): $CB_URL_BOB"; CB_URL_BOB="" ;;
    esac
    if [ -n "$CB_URL_BOB" ]; then
      # bob authenticated at the IdP but carries no jellyfin-access role, so the plugin denies him at the
      # callback. Read the ACTUAL HTTP status (binding cookie presented, so this isolates the ROLE gate):
      # a genuine plugin-side refusal is a reached-plugin non-2xx. A 2xx means the role gate let a role-less
      # user in; an unreachable plugin (HTTP 000) is a broken test, never a refusal. This mirrors the
      # hardened SAML dave negative so a transport break can never masquerade as a role-gate PASS.
      CB_STATUS_BOB="$(curl -sS -o /dev/null -w '%{http_code}' -H "Cookie: $BINDING_COOKIE_NAME=$BINDING_BOB" "$CB_URL_BOB" 2>/dev/null || true)"
      [ -n "$CB_STATUS_BOB" ] || CB_STATUS_BOB="000"
      # The plugin's ROLE denial is a SPECIFIC outcome: HTTP 401. Accepting "any non-2xx" would let a token
      # exchange failure, an invalid-state rejection or an unhandled 500 read as "role gate holds" — mutating
      # the deny branch to a 400/500 would survive — so pin the exact status the role gate returns.
      if [ "$CB_STATUS_BOB" = "000" ]; then
        fail "bob: could not reach the plugin callback (HTTP 000) — cannot prove a role-gate refusal (broken negative test)"
      elif [ "$CB_STATUS_BOB" -ge 200 ] && [ "$CB_STATUS_BOB" -lt 300 ]; then
        fail "bob: callback returned $CB_STATUS_BOB — the role gate did NOT refuse a role-less user"
      elif [ "$CB_STATUS_BOB" != "401" ]; then
        fail "bob: callback returned $CB_STATUS_BOB, not the role gate's 401 — refused for the WRONG reason (broken negative test)"
      else
        pass "bob: callback refused the role-less user at the plugin (HTTP 401, role gate holds)"
      fi
    fi
  fi
else
  fail "bob: could not complete the IdP login"
fi
fi # role-gate phase

# --------------------------------------------------------------------------------------------------
# Phase 6 — fail-closed negative: a replayed one-time state is refused
# --------------------------------------------------------------------------------------------------
log "== Fail-closed negative: replayed state (expect refusal) =="
if [ -n "${STATE:-}" ]; then
  # alice's STATE was already redeemed once in Phase 4; replaying it must be rejected. Read the ACTUAL
  # status rather than "curl -f said non-zero": -f is non-zero for a connection failure, a timeout, a 429
  # throttle or an unhandled 500 too, so accepting any failure would let a broken leg print "one-time-use
  # holds". The redeem miss is a SPECIFIC outcome — 400 "Invalid or expired state" (PublicReason.InvalidState,
  # LoginStatusMapper) — so pin it, the same standard the bob/dave role-gate negatives hold.
  REPLAY_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' -H "Cookie: $BINDING_COOKIE_NAME=$BINDING" -X POST "$JELLYFIN/sso/OID/Auth/$PROVIDER" \
      -H "Content-Type: application/json" \
      -d "{\"deviceId\":\"$DEVICE_ID\",\"appName\":\"Jellyfin Web\",\"appVersion\":\"10.8.0\",\"deviceName\":\"$DEVICE\",\"data\":\"$STATE\"}" 2>/dev/null || true)"
  [ -n "$REPLAY_STATUS" ] || REPLAY_STATUS="000"
  if [ "$REPLAY_STATUS" = "000" ]; then
    fail "replay check could not reach Jellyfin (HTTP 000) — cannot prove one-time-use (broken negative test)"
  elif [ "$REPLAY_STATUS" -ge 200 ] && [ "$REPLAY_STATUS" -lt 300 ]; then
    fail "replayed state was accepted (HTTP $REPLAY_STATUS) — one-time-use is NOT enforced"
  elif [ "$REPLAY_STATUS" != "400" ]; then
    fail "replayed state returned $REPLAY_STATUS, not the redeem miss's 400 — refused for the WRONG reason (broken negative test)"
  else
    pass "replayed state refused (HTTP 400, one-time-use holds)"
  fi
else
  fail "replay check skipped: no state captured from the alice round-trip"
fi

# ==================================================================================================
# SAML
# ==================================================================================================
# Gated: only a provider that speaks SAML (Keycloak) runs these phases. An OIDC-only provider (Authelia)
# sets RUN_SAML=false, and the SAML phases below are skipped.
if [ "$RUN_SAML" = "true" ]; then
# The SAML browser-binding cookie (#415) — like the OpenID one, always Secure, so presented explicitly
# over plaintext http. It is checked at the same-origin SAML/Auth mint leg (the cross-site ACS POST does
# not carry it).
SAML_BINDING_COOKIE_NAME="__Host-sso_saml_state_binding"

# saml_start <jar> <start_hdr> : calls the plugin's provider-agnostic SAML /start, writes the response
# headers (carrying the SAML binding Set-Cookie) to start_hdr, and prints the IdP SSO URL it 302s to.
saml_start() {
  jar="$1"; start_hdr="$2"
  start_out="$(curl -sS -D "$start_hdr" -o /dev/null -c "$jar" -b "$jar" -w '%{http_code} %{redirect_url}' "$JELLYFIN/sso/SAML/start/$PROVIDER")"
  code="${start_out%% *}"; auth_url="${start_out#* }"
  printf 'saml_start: /start -> HTTP %s location=%s\n' "$code" "${auth_url%%\?*}?<SAMLRequest>" >&2
  if [ -z "$auth_url" ]; then
    printf 'saml_start: /start returned no redirect; body was:\n' >&2
    curl -sS -c "$jar" -b "$jar" "$JELLYFIN/sso/SAML/start/$PROVIDER" >&2 || true
    return 1
  fi
  printf '%s' "$auth_url"
}

# idp_saml_login <jar> <start_hdr> <user> <pass> : drives the browser-role SAML login at the identity provider
# and prints the page carrying the SAML POST-binding auto-submit form. Dispatches on IDP_KIND exactly as the
# OIDC path does — Keycloak renders a server-side HTML form, authentik runs the same stateful flow-executor
# it uses for OpenID. Returns NON-ZERO on any transport break: a broken leg must RED the caller, never look
# like a refusal.
idp_saml_login() {
  jar="$1"; start_hdr="$2"; user="$3"; pass="$4"
  auth_url="$(saml_start "$jar" "$start_hdr")" || return 1
  case "$IDP_KIND" in
    keycloak)
      login_page="$(curl -sSL -c "$jar" -b "$jar" "$auth_url")" || { printf 'idp_saml_login[keycloak]: login page curl failed\n' >&2; return 1; }
      form_action="$(printf '%s' "$login_page" | grep -oE 'action="[^"]*"' | head -1 | sed -e 's/^action="//' -e 's/"$//' -e 's/&amp;/\&/g')"
      if [ -z "$form_action" ]; then
        printf 'idp_saml_login[keycloak]: could not parse a form action; first 800 chars:\n%s\n' "$(printf '%s' "$login_page" | head -c 800)" >&2
        return 1
      fi
      curl -sSL -c "$jar" -b "$jar" \
        --data-urlencode "username=$user" \
        --data-urlencode "password=$pass" \
        --data-urlencode "credentialId=" \
        "$form_action" || { printf 'idp_saml_login[keycloak]: credential POST failed\n' >&2; return 1; }
      ;;
    authentik)
      flow_url="$(curl -fsSL -c "$jar" -b "$jar" -o /dev/null -w '%{url_effective}' "$auth_url")" || { printf 'idp_saml_login[authentik]: SSO follow failed\n' >&2; return 1; }
      # authentik CHAINS flows for a SAML login: the authentication flow, then the provider's authorization
      # flow. Run whichever flow we land on, follow its completion target, and stop as soon as the response is
      # the SAML POST-binding auto-submit form.
      hop=0
      while [ "$hop" -lt 4 ]; do
        hop=$((hop + 1))
        # `rc=0; out=$(f) || rc=$?` rather than `out=$(f); rc=$?`: the latter only survives `set -e` on
        # ash/bash (the runtime is alpine's ash), while this form is portable and equally exact.
        flow_rc=0
        redir_to="$(authentik_run_flow "$jar" "$flow_url" "$user" "$pass")" || flow_rc=$?
        if [ "$flow_rc" -eq 3 ]; then
          # The flow ended in an autosubmit stage: what it printed IS the SAML POST-binding form. Verify that
          # before accepting it, symmetric with the redirect branch below — a rendered form that carries no
          # SAMLResponse must RED here, not downstream as an unparseable page.
          case "$redir_to" in
            *'name="SAMLResponse"'*)
              printf 'idp_saml_login[authentik]: SAML response delivered by an autosubmit stage after %s flow(s)\n' "$hop" >&2
              printf '%s' "$redir_to"
              return 0
              ;;
            *)
              printf 'idp_saml_login[authentik]: autosubmit stage carried no SAMLResponse field\n' >&2
              return 1
              ;;
          esac
        fi
        [ "$flow_rc" -eq 0 ] || return 1
        saml_body="$(mktemp)"
        saml_meta="$(curl -sSL -c "$jar" -b "$jar" -o "$saml_body" -w '%{http_code} %{url_effective}' "$redir_to")" \
          || { printf 'idp_saml_login[authentik]: SSO resume failed\n' >&2; rm -f "$saml_body"; return 1; }
        saml_final="${saml_meta#* }"
        if grep -q 'name="SAMLResponse"' "$saml_body" 2>/dev/null; then
          printf 'idp_saml_login[authentik]: reached the SAMLResponse form after %s flow(s)\n' "$hop" >&2
          cat "$saml_body"
          rm -f "$saml_body"
          return 0
        fi
        rm -f "$saml_body"
        case "$saml_final" in
          */if/flow/*/\?*)
            # Require PROGRESS: landing back on the same flow means it did not advance, and re-driving it
            # would burn further credential attempts and then report a misleading "did not reach the form".
            if [ "$saml_final" = "$flow_url" ]; then
              printf 'idp_saml_login[authentik]: flow did not advance (still %s) — not retrying\n' "${saml_final%%\?*}" >&2
              return 1
            fi
            printf 'idp_saml_login[authentik]: chained into %s\n' "${saml_final%%\?*}" >&2
            flow_url="$saml_final"
            ;;
          *)
            printf 'idp_saml_login[authentik]: landed on %s (HTTP %s) without a SAMLResponse form\n' "${saml_final%%\?*}" "${saml_meta%% *}" >&2
            return 1
            ;;
        esac
      done
      printf 'idp_saml_login[authentik]: did not reach the SAMLResponse form within 4 flows\n' >&2
      return 1
      ;;
    *)
      printf 'idp_saml_login: unknown IDP_KIND=%s\n' "$IDP_KIND" >&2
      return 1
      ;;
  esac
}

# post_saml_response <jar> <post_page> : parses the SAML POST-binding auto-submit form out of the page and
# posts SAMLResponse to the plugin's ACS. Prints the ACS response body with a trailing __ACSHTTP__<code>
# marker carrying the ACS HTTP status (so a caller can tell an actual plugin-side deny — a reached-ACS
# non-2xx — from a token-less body a broken leg would also produce); diagnostics go to stderr. Returns
# NON-ZERO if the form cannot be parsed or the ACS cannot be reached.
post_saml_response() {
  jar="$1"; post_page="$2"
  acs_url="$(printf '%s' "$post_page" | grep -oE 'form[^>]*action="[^"]*"' | head -1 | sed -E 's/.*action="//; s/".*//; s/&amp;/\&/g')"
  saml_resp="$(printf '%s' "$post_page" | grep -oE 'name="SAMLResponse"[^>]*value="[^"]*"' | head -1 | sed -E 's/.*value="//; s/".*//')"
  relay="$(printf '%s' "$post_page" | grep -oE 'name="RelayState"[^>]*value="[^"]*"' | head -1 | sed -E 's/.*value="//; s/".*//')"
  if [ -z "$acs_url" ] || [ -z "$saml_resp" ]; then
    printf 'post_saml_response: could not parse SAMLResponse form (acs=%s, resp_len=%s); first 800 chars:\n%s\n' "$acs_url" "${#saml_resp}" "$(printf '%s' "$post_page" | head -c 800)" >&2
    return 1
  fi
  printf 'post_saml_response: posting SAMLResponse to %s\n' "$acs_url" >&2
  # NO -f, so a non-2xx deny still returns the body+marker (a role-gate refusal is an expected outcome here,
  # not a transport error). A real connection failure to the ACS still exits non-zero and reds the caller.
  if [ -n "$relay" ]; then
    curl -sS -w '\n__ACSHTTP__%{http_code}' -X POST "$acs_url" --data-urlencode "SAMLResponse=$saml_resp" --data-urlencode "RelayState=$relay"
  else
    curl -sS -w '\n__ACSHTTP__%{http_code}' -X POST "$acs_url" --data-urlencode "SAMLResponse=$saml_resp"
  fi
}

# --------------------------------------------------------------------------------------------------
# Extended phases (#928 U5) — gated by EXTENDED_PHASES (the canonical Keycloak stack turns them on).
# --------------------------------------------------------------------------------------------------
if [ "$EXTENDED_PHASES" = "true" ]; then

  # jf_auth_status USERNAME PASSWORD -> the HTTP status of a password login attempt. Uses the same
  # X-Emby-Authorization idiom as the admin authenticate in phase 1; -o keeps the body out of the way.
  jf_auth_status() {
    curl -sS -o /tmp/authbyname.out -w '%{http_code}' -X POST "$JELLYFIN/Users/AuthenticateByName" \
      -H "Content-Type: application/json" \
      -H "Authorization: $EMBY_AUTH" \
      -d "{\"Username\":\"$1\",\"Pw\":\"$2\"}"
  }

  # oidc_relogin_me VARPREFIX — drives a full second OIDC login for alice and echoes /Users/Me JSON.
  oidc_relogin_me() {
    r_jar="$(mktemp)"; r_hdr="$(mktemp)"
    r_cb="$(idp_oidc_login "$r_jar" "$r_hdr" alice "$PASSWORD_ALICE")" || return 1
    r_binding="$(extract_binding "$r_hdr")"
    [ -n "$r_binding" ] && [ -n "$r_cb" ] || return 1
    r_page="$(curl -fsS -H "Cookie: $BINDING_COOKIE_NAME=$r_binding" "$r_cb")" || return 1
    r_state="$(printf '%s' "$r_page" | grep -oE 'var data = "[^"]*"' | head -1 | sed -e 's/^var data = "//' -e 's/"$//')"
    [ -n "$r_state" ] || return 1
    r_auth="$(curl -fsS -H "Cookie: $BINDING_COOKIE_NAME=$r_binding" -X POST "$JELLYFIN/sso/OID/Auth/$PROVIDER" \
      -H "Content-Type: application/json" \
      -d "{\"deviceId\":\"$DEVICE_ID-relogin\",\"appName\":\"Jellyfin Web\",\"appVersion\":\"10.8.0\",\"deviceName\":\"$DEVICE\",\"data\":\"$r_state\"}")" || return 1
    r_token="$(printf '%s' "$r_auth" | jq -r '.AccessToken // empty')"
    [ -n "$r_token" ] || return 1
    curl -fsS "$JELLYFIN/Users/Me" -H "Authorization: MediaBrowser Token=\"$r_token\""
  }

  # ------------------------------------------------------------------------------------------------
  # Phase 6b — second login: stable identity binding (the sub-keyed link reuses the SAME account).
  # A rename-at-the-IdP or a broken canonical link would mint a fresh account here and pass every
  # earlier phase — this is the end-to-end pin that it cannot.
  # ------------------------------------------------------------------------------------------------
  log "== Extended: second OIDC login for alice (expect the SAME Jellyfin account) =="
  [ -n "${ALICE_ID:-}" ] || die "extended: phase 4 captured no alice account id"
  ME2="$(oidc_relogin_me)" || die "extended: alice's second IdP login failed"
  ALICE_ID_2="$(printf '%s' "$ME2" | jq -r '.Id // empty')"
  if [ -n "$ALICE_ID_2" ] && [ "$ALICE_ID_2" = "$ALICE_ID" ]; then
    pass "alice: second login reuses the same Jellyfin account (stable sub->account binding)"
  else
    fail "alice: second login minted a DIFFERENT account ('$ALICE_ID_2' vs '$ALICE_ID') — the canonical link did not hold"
  fi

  # ------------------------------------------------------------------------------------------------
  # Phase 6c — admin elevation from the IdP role claim, asserted on the minted policy.
  # alice carries the admin-mapped role (the stack seeds it and sets ADMIN_ROLES_JSON); the policy on
  # the REAL minted user must say administrator — the RBAC assert beyond the login allow-list that no
  # phase covered before (#928 audit, G4).
  # ------------------------------------------------------------------------------------------------
  log "== Extended: admin-elevation policy assert =="
  if [ "$ADMIN_ROLES_JSON" = "[]" ]; then
    die "extended: EXTENDED_PHASES is on but ADMIN_ROLES_JSON is empty — the stack must seed an admin role"
  fi
  if [ "${ALICE_IS_ADMIN:-false}" = "true" ]; then
    pass "alice: minted policy carries IsAdministrator=true from the IdP role claim"
  else
    fail "alice: minted policy is NOT administrator although the admin role is granted and configured"
  fi

  # ------------------------------------------------------------------------------------------------
  # Phase 6d — SSO-only login round-trip: enable with the break-glass admin, prove the lockout is
  # scoped (non-exempt password login refused, break-glass survives, SSO still mints), then disable
  # and prove restoration. The feature's whole safety claim was in-process-only before (#928 audit).
  # ------------------------------------------------------------------------------------------------
  log "== Extended: SSO-only login round-trip =="
  PW_USER="pwuser"; PW_PASS="Pw-e2e-1!"
  NEWU="$(curl -fsS -X POST "$JELLYFIN/Users/New" \
    -H "Content-Type: application/json" \
    -H "Authorization: MediaBrowser Token=\"$ADMIN_TOKEN\"" \
    -d "{\"Name\":\"$PW_USER\",\"Password\":\"$PW_PASS\"}")" || die "extended: creating the password user failed"
  [ -n "$(printf '%s' "$NEWU" | jq -r '.Id // empty')" ] || die "extended: /Users/New returned no user id"

  [ "$(jf_auth_status "$PW_USER" "$PW_PASS")" = "200" ] || die "extended: the fresh password user cannot log in even before SSO-only"

  EN_STATUS="$(curl -sS -o /tmp/ssoonly.out -w '%{http_code}' -X POST "$JELLYFIN/sso/SSO-Only/Enable" \
    -H "Content-Type: application/json" \
    -H "Authorization: MediaBrowser Token=\"$ADMIN_TOKEN\"" \
    -d "\"$ADMIN_USER\"")"
  [ "$EN_STATUS" = "200" ] || die "extended: SSO-Only/Enable returned HTTP $EN_STATUS: $(cat /tmp/ssoonly.out 2>/dev/null)"

  PW_LOCKED="$(jf_auth_status "$PW_USER" "$PW_PASS")"
  if [ "$PW_LOCKED" != "200" ]; then
    pass "SSO-only: non-exempt password login refused (HTTP $PW_LOCKED)"
  else
    fail "SSO-only: the non-exempt password user can STILL log in with a password"
  fi

  if [ "$(jf_auth_status "$ADMIN_USER" "$ADMIN_PASS")" = "200" ]; then
    pass "SSO-only: the break-glass admin's password door survives"
  else
    fail "SSO-only: the break-glass admin was locked out — the fail-safe failed"
  fi

  ME3="$(oidc_relogin_me)" || ME3=""
  if [ "$(printf '%s' "$ME3" | jq -r '.Name // empty')" = "alice" ]; then
    pass "SSO-only: the SSO login path still mints sessions while the mode is on"
  else
    fail "SSO-only: alice's SSO login broke while the mode is on"
  fi

  # Re-authenticate for a FRESH admin token: enabling SSO-only revokes existing sessions (the
  # break-glass admin keeps its password DOOR, but the token minted in phase 1 is gone), so the
  # disable call must use a token minted after the enable — via that surviving break-glass door.
  [ "$(jf_auth_status "$ADMIN_USER" "$ADMIN_PASS")" = "200" ] || die "extended: break-glass re-authenticate before disable failed"
  ADMIN_TOKEN="$(jq -r '.AccessToken' /tmp/authbyname.out)"
  [ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] || die "extended: no fresh admin token from the break-glass login"

  DIS_STATUS="$(curl -sS -o /tmp/ssoonly.out -w '%{http_code}' -X POST "$JELLYFIN/sso/SSO-Only/Disable" \
    -H "Content-Type: application/json" \
    -H "Authorization: MediaBrowser Token=\"$ADMIN_TOKEN\"" \
    -d '""')"
  [ "$DIS_STATUS" = "200" ] || die "extended: SSO-Only/Disable returned HTTP $DIS_STATUS: $(cat /tmp/ssoonly.out 2>/dev/null)"

  if [ "$(jf_auth_status "$PW_USER" "$PW_PASS")" = "200" ]; then
    pass "SSO-only: disable restores the password user's native login (no hash was reset)"
  else
    fail "SSO-only: the password user stayed locked out after disable — restoration failed"
  fi

fi

# --------------------------------------------------------------------------------------------------
# Phase 7 — configure the SAML provider (IdP signing cert fetched from Keycloak's SAML descriptor)
# --------------------------------------------------------------------------------------------------
log "== Configuring SAML provider '$PROVIDER' =="
# -L: authentik serves its provider metadata through a redirect, Keycloak serves it directly.
DESCRIPTOR="$(curl -fsSL "$SAML_DESCRIPTOR_URL")" || die "SAML: descriptor fetch failed"
IDP_CERT="$(printf '%s' "$DESCRIPTOR" | tr -d '\n\r' | grep -oiE '<[a-z0-9]*:?X509Certificate>[^<]*' | head -1 | sed -E 's/.*X509Certificate>//' | tr -d ' \t')"
[ -n "$IDP_CERT" ] || die "SAML: could not extract the IdP signing certificate from the descriptor"
log "SAML IdP signing certificate captured (${#IDP_CERT} base64 chars)"

SAML_CONFIG="$(cat <<JSON
{
  "SamlEndpoint": "$SAML_ENDPOINT",
  "SamlClientId": "$SAML_CLIENT_ID",
  "BaseUrlOverride": "$SAML_BASE_URL_OVERRIDE",
  "SamlCertificate": "$IDP_CERT",
  "Enabled": true,
  "EnableAuthorization": true,
  "Roles": ["jellyfin-access"]
}
JSON
)"
SADD_STATUS="$(curl -sS -o /tmp/samladd.out -w '%{http_code}' -X POST "$JELLYFIN/sso/SAML/Add/$PROVIDER" \
  -H "Content-Type: application/json" \
  -H "Authorization: MediaBrowser Token=\"$ADMIN_TOKEN\"" \
  -d "$SAML_CONFIG")" || true
if [ "$SADD_STATUS" != "200" ] && [ "$SADD_STATUS" != "204" ]; then
  log "SAML/Add returned HTTP $SADD_STATUS: $(cat /tmp/samladd.out 2>/dev/null)"
  die "SAML/Add failed"
fi
SNAMES="$(curl -fsS "$JELLYFIN/sso/SAML/GetNames")" || die "SAML GetNames failed"
log "SAML GetNames => $SNAMES"
if printf '%s' "$SNAMES" | jq -e --arg p "$PROVIDER" 'index($p)' >/dev/null 2>&1; then
  pass "SAML provider '$PROVIDER' is listed by SAML/GetNames"
else
  fail "SAML provider '$PROVIDER' not listed by SAML/GetNames"
fi

# --------------------------------------------------------------------------------------------------
# Phase 8 — full SAML round-trip for carol (milestone 4)
# --------------------------------------------------------------------------------------------------
log "== SAML round-trip: carol (expect success) =="
JAR_S="$(mktemp)"
SHDR="$(mktemp)"
SPAGE="$(idp_saml_login "$JAR_S" "$SHDR" "carol" "carol")" || die "carol: could not complete the IdP SAML login"
SBIND="$(grep -i '^set-cookie:' "$SHDR" 2>/dev/null | grep -o "$SAML_BINDING_COOKIE_NAME=[^;]*" | head -1 | cut -d= -f2-)"
[ -n "$SBIND" ] || die "carol: /start set no SAML browser-binding cookie"

ACS_PAGE="$(post_saml_response "$JAR_S" "$SPAGE")" || die "carol: SAML ACS leg failed"
STOKEN="$(printf '%s' "$ACS_PAGE" | grep -oE 'var data = "[^"]*"' | head -1 | sed -e 's/^var data = "//' -e 's/"$//')"
if [ -z "$STOKEN" ]; then
  log "carol: ACS response carried no login token; first 600 chars: $(printf '%s' "$ACS_PAGE" | head -c 600)"
  die "carol: the ACS callback did not mint a login-outcome token (signature/audience/role gate?)"
fi

# Redeem the token at the same-origin SAML/Auth mint leg, presenting the SAML binding cookie explicitly.
SAUTH="$(curl -fsS -H "Cookie: $SAML_BINDING_COOKIE_NAME=$SBIND" -X POST "$JELLYFIN/sso/SAML/Auth/$PROVIDER" \
  -H "Content-Type: application/json" \
  -d "{\"deviceId\":\"$DEVICE_ID\",\"appName\":\"Jellyfin Web\",\"appVersion\":\"10.8.0\",\"deviceName\":\"$DEVICE\",\"data\":\"$STOKEN\"}")" || die "carol: SAML/Auth failed"
S_JF_TOKEN="$(printf '%s' "$SAUTH" | jq -r '.AccessToken')"
S_JF_USER="$(printf '%s' "$SAUTH" | jq -r '.User.Name')"
if [ -n "$S_JF_TOKEN" ] && [ "$S_JF_TOKEN" != "null" ]; then
  pass "carol: Jellyfin session token minted via SAML (user='$S_JF_USER')"
else
  fail "carol: SAML/Auth did not mint a session token"
fi

if [ -n "${S_JF_TOKEN:-}" ] && [ "$S_JF_TOKEN" != "null" ]; then
  SME="$(curl -fsS "$JELLYFIN/Users/Me" -H "Authorization: MediaBrowser Token=\"$S_JF_TOKEN\"")" || SME=""
  SME_NAME="$(printf '%s' "$SME" | jq -r '.Name // empty' 2>/dev/null || true)"
  if [ "$SME_NAME" = "carol" ]; then
    pass "carol: SAML session token works against GET /Users/Me (Name='carol')"
  else
    fail "carol: GET /Users/Me did not return the carol user (got '$SME_NAME')"
  fi
  # The non-admin negative to phase 6c's positive (#928 U5): carol carries only the access role, so
  # her minted policy must NOT be administrator — pins that admin elevation needs the mapped role,
  # not merely a successful SSO login.
  if [ "$EXTENDED_PHASES" = "true" ]; then
    if [ "$(printf '%s' "$SME" | jq -r '.Policy.IsAdministrator // false')" = "false" ]; then
      pass "carol: minted policy is NOT administrator (no admin role granted)"
    else
      fail "carol: minted policy claims administrator although carol has no admin role"
    fi
  fi
fi

# --------------------------------------------------------------------------------------------------
# Phase 9 — SAML role-gate negative: dave is refused
# --------------------------------------------------------------------------------------------------
log "== SAML round-trip: dave (expect role-gate refusal) =="
JAR_SD="$(mktemp)"
SHDR_D="$(mktemp)"
# dave must run the SAME real round-trip carol does — reach the Keycloak SAML login form, authenticate,
# and drive a genuine SAMLResponse POST to the plugin's ACS — and ONLY THEN be refused by the plugin. A
# broken transport leg (no login form, failed Keycloak login, unparseable SAMLResponse, or an
# unreachable ACS) must RED the run, not masquerade as a role-gate refusal: a token-less body from a
# broken leg is indistinguishable from a deny unless we first prove the round-trip actually happened.
SPAGE_D="$(idp_saml_login "$JAR_SD" "$SHDR_D" "dave" "dave")" || die "dave: could not complete the IdP SAML login (broken negative test)"
# post_saml_response returns non-zero only when the form is unparseable or the ACS is unreachable at all;
# a reached-ACS (any HTTP status, including the expected deny) returns 0 with the body + status marker.
ACS_PAGE_D="$(post_saml_response "$JAR_SD" "$SPAGE_D")" || die "dave: could not reach the SAML ACS (broken negative test)"
ACS_STATUS_D="$(printf '%s' "$ACS_PAGE_D" | sed -n 's/.*__ACSHTTP__\([0-9][0-9]*\)$/\1/p')"
DTOKEN="$(printf '%s' "$ACS_PAGE_D" | grep -oE 'var data = "[^"]*"' | head -1 | sed -e 's/^var data = "//' -e 's/"$//')"
log "dave: reached the SAML ACS; it returned HTTP ${ACS_STATUS_D:-<none>}"
# The refusal must be an ACTUAL plugin-side deny after a real ACS round-trip: a non-2xx status AND no
# login-outcome token minted. A minted token is a role-gate failure; a 2xx (or an unreadable status) is
# a broken test, not a proven refusal.
if [ -n "$DTOKEN" ]; then
  fail "dave: the ACS callback minted a login-outcome token — the SAML role gate did NOT refuse a role-less user"
elif [ -z "$ACS_STATUS_D" ]; then
  fail "dave: could not read the ACS HTTP status — cannot prove a plugin-side refusal (broken negative test)"
elif [ "$ACS_STATUS_D" -ge 200 ] && [ "$ACS_STATUS_D" -lt 300 ]; then
  fail "dave: the ACS returned $ACS_STATUS_D with no token — expected a non-2xx plugin refusal, not an ambiguous empty body"
elif [ "$ACS_STATUS_D" != "401" ]; then
  # The plugin's ROLE denial is a SPECIFIC outcome: 401. Every other refusal on this endpoint is a different
  # status (400 malformed/invalid signature/audience, 403 link-forbidden/unverified-email, 429 throttle, 500
  # unmapped), so accepting "any non-2xx" would let a broken leg print "role gate holds" — the exact pin the
  # OIDC bob negative already carries.
  fail "dave: the ACS returned $ACS_STATUS_D, not the role gate's 401 — refused for the WRONG reason (broken negative test)"
else
  pass "dave: SAML ACS refused the role-less user at the plugin (HTTP $ACS_STATUS_D, no token minted — role gate holds)"
fi

# --------------------------------------------------------------------------------------------------
# Phase 10 — SAML fail-closed negative: a replayed one-time login-outcome token is refused
# --------------------------------------------------------------------------------------------------
log "== SAML fail-closed negative: replayed token (expect refusal) =="
if [ -n "${STOKEN:-}" ]; then
  # carol's STOKEN was already redeemed once in Phase 8; replaying it must be rejected. Status-pinned for the
  # same reason as the OIDC replay above: a transport break or a 500 must never read as "one-time-use holds".
  SREPLAY_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' -H "Cookie: $SAML_BINDING_COOKIE_NAME=$SBIND" -X POST "$JELLYFIN/sso/SAML/Auth/$PROVIDER" \
      -H "Content-Type: application/json" \
      -d "{\"deviceId\":\"$DEVICE_ID\",\"appName\":\"Jellyfin Web\",\"appVersion\":\"10.8.0\",\"deviceName\":\"$DEVICE\",\"data\":\"$STOKEN\"}" 2>/dev/null || true)"
  [ -n "$SREPLAY_STATUS" ] || SREPLAY_STATUS="000"
  if [ "$SREPLAY_STATUS" = "000" ]; then
    fail "SAML replay check could not reach Jellyfin (HTTP 000) — cannot prove one-time-use (broken negative test)"
  elif [ "$SREPLAY_STATUS" -ge 200 ] && [ "$SREPLAY_STATUS" -lt 300 ]; then
    fail "SAML: replayed login-outcome token was accepted (HTTP $SREPLAY_STATUS) — one-time-use is NOT enforced"
  elif [ "$SREPLAY_STATUS" != "400" ]; then
    fail "SAML: replayed token returned $SREPLAY_STATUS, not the redeem miss's 400 — refused for the WRONG reason (broken negative test)"
  else
    pass "SAML: replayed login-outcome token refused (HTTP 400, one-time-use holds)"
  fi
else
  fail "SAML replay check skipped: no token captured from the carol round-trip"
fi

else
  log "== SAML phases skipped (RUN_SAML=$RUN_SAML) =="
fi

# --------------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------------
log ""
if [ "$FAILURES" -eq 0 ]; then
  log "ALL E2E CHECKS PASSED"
  exit 0
fi
log "E2E CHECKS FAILED: $FAILURES assertion(s) did not hold"
exit 1
