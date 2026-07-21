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
curl -fsS -X POST "$JELLYFIN/sso/OID/Add/$PROVIDER" \
  -H "Content-Type: application/json" \
  -H "Authorization: MediaBrowser Token=\"$ADMIN_TOKEN\"" \
  -d "$OID_CONFIG" >/dev/null || die "OID/Add failed"
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
# oidc_authorize <cookiejar> : drives start -> keycloak login page, prints the login form action URL.
oidc_authorize() {
  jar="$1"
  auth_url="$(curl -fsS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$JELLYFIN/sso/OID/start/$PROVIDER")"
  [ -n "$auth_url" ] || { log "no authorize redirect from /start"; return 1; }
  login_page="$(curl -fsSL -c "$jar" -b "$jar" "$auth_url")" || { log "keycloak login page fetch failed"; return 1; }
  form_action="$(printf '%s' "$login_page" | grep -oE 'action="[^"]*"' | head -1 | sed -e 's/^action="//' -e 's/"$//' -e 's/&amp;/\&/g')"
  [ -n "$form_action" ] || { log "could not parse keycloak login form action"; return 1; }
  printf '%s' "$form_action"
}

# --------------------------------------------------------------------------------------------------
# Phase 4 — full OIDC round-trip for alice (milestone 2)
# --------------------------------------------------------------------------------------------------
log "== OIDC round-trip: alice (expect success) =="
JAR="$(mktemp)"
FORM_ACTION="$(oidc_authorize "$JAR")" || die "alice: could not reach keycloak login form"

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

# Follow the callback WITH the binding cookie so the plugin promotes the state to redeemable, and
# capture the intermediate auth page. The page embeds  var data = "<state>";  which is exactly what
# a real browser posts to OID/Auth.
AUTH_PAGE="$(curl -fsS -c "$JAR" -b "$JAR" "$CB_URL")" || die "alice: callback did not return the auth page"
STATE="$(printf '%s' "$AUTH_PAGE" | grep -oE 'var data = "[^"]*"' | head -1 | sed -e 's/^var data = "//' -e 's/"$//')"
[ -n "$STATE" ] || die "alice: could not extract state token from the auth page"

# Post to OID/Auth with the binding cookie -> the minted Jellyfin session (AuthenticationResult).
AUTH_RESULT="$(curl -fsS -c "$JAR" -b "$JAR" -X POST "$JELLYFIN/sso/OID/Auth/$PROVIDER" \
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
if FORM_ACTION_BOB="$(oidc_authorize "$JAR_BOB")"; then
  CB_URL_BOB="$(curl -fsS -c "$JAR_BOB" -b "$JAR_BOB" -o /dev/null -w '%{redirect_url}' \
    --data-urlencode "username=bob" \
    --data-urlencode "password=bob" \
    --data-urlencode "credentialId=" \
    "$FORM_ACTION_BOB" || true)"
  if [ -z "$CB_URL_BOB" ]; then
    fail "bob: Keycloak did not redirect back (authentication itself failed unexpectedly)"
  else
    # The callback must NOT return the success auth page: the role gate denies bob, so the plugin
    # returns a non-2xx error page. curl -f makes a 4xx a non-zero exit.
    if curl -fsS -o /dev/null -c "$JAR_BOB" -b "$JAR_BOB" "$CB_URL_BOB" 2>/dev/null; then
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
  if curl -fsS -o /dev/null -c "$JAR" -b "$JAR" -X POST "$JELLYFIN/sso/OID/Auth/$PROVIDER" \
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
