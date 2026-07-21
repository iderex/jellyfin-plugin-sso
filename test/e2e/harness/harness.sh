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
die()  { printf 'FATAL: %s\n' "$*"; exit 1; }

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
wait_for "Keycloak realm discovery" "$KEYCLOAK/realms/$REALM/.well-known/openid-configuration"
wait_for "Jellyfin" "$JELLYFIN/System/Info/Public"

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
  "OidEndpoint": "$KEYCLOAK/realms/$REALM",
  "OidClientId": "$CLIENT_ID",
  "OidSecret": "$CLIENT_SECRET",
  "Enabled": true,
  "OidScopes": ["email"],
  "DoNotLoadProfile": true,
  "DisablePushedAuthorization": true,
  "DisableHttps": true,
  "EnableAuthorization": true,
  "Roles": ["jellyfin-access"],
  "RoleClaim": "realm_access.roles"
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

# oidc_authorize <cookiejar> <start_headers_file> : drives start -> keycloak login page, prints the login
# form action URL on stdout and writes the /start response headers (carrying the binding Set-Cookie) to the
# headers file. ALL diagnostics go to stderr so they are not captured by the caller's $(...) and are
# visible in the container log.
oidc_authorize() {
  jar="$1"; start_hdr="$2"
  # /start must 302 to the IdP authorize endpoint.
  start_out="$(curl -sS -D "$start_hdr" -o /dev/null -c "$jar" -b "$jar" -w '%{http_code} %{redirect_url}' "$JELLYFIN/sso/OID/start/$PROVIDER")"
  start_code="${start_out%% *}"
  auth_url="${start_out#* }"
  printf 'oidc_authorize: /start -> HTTP %s location=%s\n' "$start_code" "$auth_url" >&2
  if [ -z "$auth_url" ]; then
    printf 'oidc_authorize: /start returned no redirect; body was:\n' >&2
    curl -sS -c "$jar" -b "$jar" "$JELLYFIN/sso/OID/start/$PROVIDER" >&2 || true
    return 1
  fi
  # Fetch the Keycloak login page (following any Keycloak-internal redirect), keeping the HTTP code.
  login_page="$(curl -sSL -c "$jar" -b "$jar" -w '\n__HTTP__%{http_code}' "$auth_url")" || { printf 'oidc_authorize: login page curl failed\n' >&2; return 1; }
  page_code="$(printf '%s' "$login_page" | sed -n 's/.*__HTTP__\([0-9]*\)$/\1/p')"
  printf 'oidc_authorize: keycloak authorize page -> HTTP %s\n' "$page_code" >&2
  form_action="$(printf '%s' "$login_page" | grep -oE 'action="[^"]*"' | head -1 | sed -e 's/^action="//' -e 's/"$//' -e 's/&amp;/\&/g')"
  if [ -z "$form_action" ]; then
    printf 'oidc_authorize: could not parse a form action from the authorize page; first 1200 chars:\n%s\n' "$(printf '%s' "$login_page" | head -c 1200)" >&2
    return 1
  fi
  printf 'oidc_authorize: form action=%s\n' "$form_action" >&2
  printf '%s' "$form_action"
}

# --------------------------------------------------------------------------------------------------
# Phase 4 — full OIDC round-trip for alice (milestone 2)
# --------------------------------------------------------------------------------------------------
log "== OIDC round-trip: alice (expect success) =="
JAR="$(mktemp)"
START_HDR="$(mktemp)"
FORM_ACTION="$(oidc_authorize "$JAR" "$START_HDR")" || die "alice: could not reach keycloak login form"
BINDING="$(extract_binding "$START_HDR")"
[ -n "$BINDING" ] || die "alice: /start set no browser-binding cookie"

# Post alice's credentials; Keycloak 302s back to the plugin callback with code + state.
CB_URL="$(curl -fsS -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "username=alice" \
  --data-urlencode "password=alice" \
  --data-urlencode "credentialId=" \
  "$FORM_ACTION")" || die "alice: credential POST failed"
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
fi

# --------------------------------------------------------------------------------------------------
# Phase 5 — role-gate negative: bob is refused (milestone 3)
# --------------------------------------------------------------------------------------------------
log "== OIDC round-trip: bob (expect role-gate refusal) =="
JAR_BOB="$(mktemp)"
START_HDR_BOB="$(mktemp)"
if FORM_ACTION_BOB="$(oidc_authorize "$JAR_BOB" "$START_HDR_BOB")"; then
  BINDING_BOB="$(extract_binding "$START_HDR_BOB")"
  CB_URL_BOB="$(curl -fsS -c "$JAR_BOB" -b "$JAR_BOB" -o /dev/null -w '%{redirect_url}' \
    --data-urlencode "username=bob" \
    --data-urlencode "password=bob" \
    --data-urlencode "credentialId=" \
    "$FORM_ACTION_BOB" || true)"
  if [ -z "$CB_URL_BOB" ]; then
    fail "bob: Keycloak did not redirect back (authentication itself failed unexpectedly)"
  else
    # The callback must NOT return the success auth page: bob authenticates at Keycloak, but the role
    # gate denies him, so the plugin returns a non-2xx error page (curl -f makes a 4xx a non-zero exit).
    # The binding cookie is presented, so this isolates the ROLE gate — a refusal here is the role gate,
    # not a binding miss.
    if curl -fsS -o /dev/null -H "Cookie: $BINDING_COOKIE_NAME=$BINDING_BOB" "$CB_URL_BOB" 2>/dev/null; then
      fail "bob: callback returned success — the role gate did NOT refuse a role-less user"
    else
      pass "bob: callback refused the role-less user (role gate holds)"
    fi
  fi
else
  fail "bob: could not reach the Keycloak login form"
fi

# --------------------------------------------------------------------------------------------------
# Phase 6 — fail-closed negative: a replayed one-time state is refused
# --------------------------------------------------------------------------------------------------
log "== Fail-closed negative: replayed state (expect refusal) =="
if [ -n "${STATE:-}" ]; then
  # alice's STATE was already redeemed once in Phase 4; replaying it must be rejected.
  if curl -fsS -o /dev/null -H "Cookie: $BINDING_COOKIE_NAME=$BINDING" -X POST "$JELLYFIN/sso/OID/Auth/$PROVIDER" \
      -H "Content-Type: application/json" \
      -d "{\"deviceId\":\"$DEVICE_ID\",\"appName\":\"Jellyfin Web\",\"appVersion\":\"10.8.0\",\"deviceName\":\"$DEVICE\",\"data\":\"$STATE\"}" 2>/dev/null; then
    fail "replayed state was accepted — one-time-use is NOT enforced"
  else
    pass "replayed state refused (one-time-use holds)"
  fi
else
  fail "replay check skipped: no state captured from the alice round-trip"
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
