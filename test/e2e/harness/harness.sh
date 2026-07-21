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
# sequence in idp_oidc_login (Keycloak renders a server-side HTML form; Authelia is a JSON-API login portal).
IDP_KIND="${IDP_KIND:-keycloak}"
RUN_SAML="${RUN_SAML:-true}"
OID_ENDPOINT="${OID_ENDPOINT:-$KEYCLOAK/realms/$REALM}"
DISCOVERY_URL="${DISCOVERY_URL:-$KEYCLOAK/realms/$REALM/.well-known/openid-configuration}"
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
wait_for "OIDC discovery" "$DISCOVERY_URL"
wait_for "Jellyfin" "$JELLYFIN/System/Info/Public"

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
  "Roles": ["jellyfin-access"],
  "RoleClaim": "$ROLE_CLAIM"
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
idp_oidc_login() {
  jar="$1"; start_hdr="$2"; user="$3"; pass="$4"
  auth_url="$(oid_start "$jar" "$start_hdr")" || return 1
  case "$IDP_KIND" in
    keycloak)
      login_page="$(curl -sSL -c "$jar" -b "$jar" -w '\n__HTTP__%{http_code}' "$auth_url")" || { printf 'idp_oidc_login[keycloak]: login page curl failed\n' >&2; return 1; }
      page_code="$(printf '%s' "$login_page" | sed -n 's/.*__HTTP__\([0-9]*\)$/\1/p')"
      printf 'idp_oidc_login[keycloak]: authorize page -> HTTP %s\n' "$page_code" >&2
      form_action="$(printf '%s' "$login_page" | grep -oE 'action="[^"]*"' | head -1 | sed -e 's/^action="//' -e 's/"$//' -e 's/&amp;/\&/g')"
      if [ -z "$form_action" ]; then
        printf 'idp_oidc_login[keycloak]: could not parse a form action; first 1200 chars:\n%s\n' "$(printf '%s' "$login_page" | head -c 1200)" >&2
        return 1
      fi
      printf 'idp_oidc_login[keycloak]: form action=%s\n' "$form_action" >&2
      # Keycloak 302s back to the plugin callback with code + state.
      curl -fsS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' \
        --data-urlencode "username=$user" \
        --data-urlencode "password=$pass" \
        --data-urlencode "credentialId=" \
        "$form_action"
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
CB_URL="$(idp_oidc_login "$JAR" "$START_HDR" alice alice)" || die "alice: could not complete the IdP login"
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
fi

# --------------------------------------------------------------------------------------------------
# Phase 5 — role-gate negative: bob is refused (milestone 3)
# --------------------------------------------------------------------------------------------------
log "== OIDC round-trip: bob (expect role-gate refusal) =="
JAR_BOB="$(mktemp)"
START_HDR_BOB="$(mktemp)"
if CB_URL_BOB="$(idp_oidc_login "$JAR_BOB" "$START_HDR_BOB" bob bob)"; then
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
  # carol's STOKEN was already redeemed once in Phase 8; replaying it must be rejected.
  if curl -fsS -o /dev/null -H "Cookie: $SAML_BINDING_COOKIE_NAME=$SBIND" -X POST "$JELLYFIN/sso/SAML/Auth/$PROVIDER" \
      -H "Content-Type: application/json" \
      -d "{\"deviceId\":\"$DEVICE_ID\",\"appName\":\"Jellyfin Web\",\"appVersion\":\"10.8.0\",\"deviceName\":\"$DEVICE\",\"data\":\"$STOKEN\"}" 2>/dev/null; then
    fail "SAML: replayed login-outcome token was accepted — one-time-use is NOT enforced"
  else
    pass "SAML: replayed login-outcome token refused (one-time-use holds)"
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
