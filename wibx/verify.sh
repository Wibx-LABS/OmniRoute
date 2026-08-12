#!/usr/bin/env bash
# Verify a running OmniRoute instance matches the Wibx-LABS deployment rules.
# Run from the fork checkout, after `docker compose ... up -d`.
#
#   ./verify.sh
#
# Exits non-zero if any hard rule is violated. Safe to re-run; read-only.
# Rules and rationale: wibx/README.md

set -uo pipefail

CONTAINER="${CONTAINER:-omniroute-prod}"
DASH_PORT="${PROD_DASHBOARD_PORT:-20130}"
API_PORT="${PROD_API_PORT:-20131}"

fail=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=1; }
info() { printf '  ----  %s\n' "$1"; }

echo "OmniRoute deployment verification — container: $CONTAINER"
echo

# ── 1. Image flavor ──────────────────────────────────────────────────────────
echo "[1] Image flavor"
if docker exec "$CONTAINER" sh -c 'command -v docker' >/dev/null 2>&1; then
  bad "docker CLI present in container — this is runner-cli, not runner-base"
else
  pass "no docker CLI in container (not runner-cli)"
fi

# playwright-core itself is ALWAYS present: Next's standalone tracing pulls it
# into runner-base whatever the target, so testing for the module is a permanent
# false FAIL. What separates runner-base from runner-web is the browser BINARY —
# without it browserType.launch() throws and no web-cookie provider can drive a
# session. Verified against a real runner-base image 2026-08-12.
if docker exec "$CONTAINER" sh -c \
     'ls ~/.cache/ms-playwright/*/chrome-linux*/chrome ~/.cache/ms-playwright/*/chrome-headless-shell-linux*/chrome-headless-shell' \
     >/dev/null 2>&1; then
  bad "a Playwright browser binary is installed — this is runner-web; web-cookie providers can run"
else
  pass "no Playwright browser binary (web-cookie providers cannot launch a session)"
fi

for pkg in @anthropic-ai/claude-code @openai/codex openclaw droid; do
  if docker exec "$CONTAINER" sh -c "ls /usr/local/lib/node_modules/$pkg" >/dev/null 2>&1; then
    bad "global coding agent installed in container: $pkg"
  fi
done
pass "no globally-installed coding agents"

# The builder stage hard-fails if tls-client-node's native binary is missing, so
# the impersonation library is a mandatory BUILD dependency regardless of flavor.
# runner-base does not copy it explicitly, but Next's standalone tracing may pull
# it in. Informational: green-only means we never invoke it, not that it is absent.
if docker exec "$CONTAINER" sh -c \
     'find . -maxdepth 4 -name "tls-client-node" -o -maxdepth 4 -name "wreq-js" 2>/dev/null | head -3' \
     2>/dev/null | grep -q .; then
  info "TLS-impersonation libs present in the runtime image (shipped, not used)"
else
  info "no tls-client-node / wreq-js found in the runtime image"
fi

# ── 2. Port bindings ─────────────────────────────────────────────────────────
echo
echo "[2] Port bindings — nothing may listen on 0.0.0.0"
# Previously parsed the JSON with an inline python3 heredoc whose escaped quotes
# were mangled by the surrounding shell quoting: it raised SyntaxError, printed
# nothing, and the emptiness was read as "no wide bindings" — a silent PASS on a
# check that never ran. A Go template has no quoting to get wrong.
bindings=$(docker inspect "$CONTAINER" \
  --format '{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostIp}} {{.HostPort}} {{$p}}
{{end}}{{end}}' 2>/dev/null)

if [ -z "$bindings" ]; then
  bad "could not read port bindings for $CONTAINER"
else
  wide=$(printf '%s\n' "$bindings" | awk 'NF && ($1 == "" || $1 == "0.0.0.0" || $1 == "::")')
  if [ -n "$wide" ]; then
    bad "published on all interfaces:"
    printf '%s\n' "$wide" | sed 's/^/          /'
  else
    pass "all published ports bound to a specific host IP"
  fi
  printf '%s\n' "$bindings" | awk 'NF {printf "        %s:%s -> %s\n", $1, $2, $3}'
fi

# ── 3. Auth ──────────────────────────────────────────────────────────────────
echo
echo "[3] Authentication"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  "http://127.0.0.1:${DASH_PORT}/api/settings" 2>/dev/null)
case "$code" in
  401|403) pass "unauthenticated /api/settings -> $code" ;;
  200)     bad  "unauthenticated /api/settings -> 200; requireLogin is OFF or bootstrap is open" ;;
  000)     info "dashboard not reachable on 127.0.0.1:${DASH_PORT} (still starting?)" ;;
  *)       info "unauthenticated /api/settings -> $code (check manually)" ;;
esac

# The management routes above are a different gate from the PROXY routes below.
# REQUIRE_API_KEY defaults to false upstream, which leaves /v1/* open to anyone
# who can reach the port — the exact thing the endpoint hand-out model relies on
# being closed. Check the flag AND the behaviour: a flag can be set and still not
# take effect.
req=$(docker exec "$CONTAINER" printenv REQUIRE_API_KEY 2>/dev/null)
if [ "$req" = "true" ]; then
  pass "REQUIRE_API_KEY=true"
else
  bad "REQUIRE_API_KEY is '${req:-unset}' — /v1/* answers callers with no key at all"
fi

proxy_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -X POST "http://127.0.0.1:${API_PORT}/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"probe/probe","messages":[{"role":"user","content":"probe"}]}' 2>/dev/null)
case "$proxy_code" in
  401|403) pass "unauthenticated POST /v1/chat/completions -> $proxy_code" ;;
  000)     info "API port not reachable on 127.0.0.1:${API_PORT} (still starting?)" ;;
  *)       bad  "unauthenticated POST /v1/chat/completions -> $proxy_code; the proxy is NOT requiring a key" ;;
esac

# ── 4. Secrets ───────────────────────────────────────────────────────────────
echo
echo "[4] Secrets"
for var in JWT_SECRET API_KEY_SECRET STORAGE_ENCRYPTION_KEY INITIAL_PASSWORD; do
  val=$(docker exec "$CONTAINER" printenv "$var" 2>/dev/null)
  if [ -z "$val" ]; then
    bad "$var is unset in the container"
  elif [ "$val" = "CHANGEME" ]; then
    bad "$var is still the shipped default CHANGEME"
  else
    pass "$var set (${#val} chars)"
  fi
done

if [ -n "$(docker exec "$CONTAINER" printenv STORAGE_ENCRYPTION_OPTOUT 2>/dev/null)" ]; then
  bad "STORAGE_ENCRYPTION_OPTOUT is set — credentials will be stored in plaintext"
else
  pass "STORAGE_ENCRYPTION_OPTOUT not set (encryption fails closed)"
fi

# ── 5. Anti-detection must stay off ──────────────────────────────────────────
echo
echo "[5] Anti-detection flags"
compat=$(docker exec "$CONTAINER" sh -c 'printenv | grep "^CLI_COMPAT_" || true' 2>/dev/null)
if [ -n "$compat" ]; then
  bad "CLI_COMPAT_* set — impersonation of official CLI signatures is ON:"
  printf '%s\n' "$compat" | sed 's/^/          /'
else
  pass "no CLI_COMPAT_* set"
fi

tls=$(docker exec "$CONTAINER" printenv INSPECTOR_TLS_INTERCEPT 2>/dev/null)
[ "$tls" = "true" ] && bad "INSPECTOR_TLS_INTERCEPT=true" || pass "TLS interception off"

# ── 6. Keyless (no-auth) providers ───────────────────────────────────────────
# Upstream ships an opt-out blocklist that is empty on a fresh install, so an
# unpatched build routes to all nine keyless providers on day one. OmniRoute#3
# inverts that default; these two checks confirm the patched code is what got
# deployed, and that nobody opened a provider back up.
echo
echo "[6] Keyless providers"

if docker exec "$CONTAINER" sh -c \
     'grep -rl OMNIROUTE_ALLOW_NOAUTH .build 2>/dev/null | head -1 | grep -q .' 2>/dev/null; then
  pass "fail-closed no-auth guard present in the deployed build"
else
  bad "OMNIROUTE_ALLOW_NOAUTH not found in the image — built from an UNPATCHED checkout (needs OmniRoute#3)"
fi

allow=$(docker exec "$CONTAINER" printenv OMNIROUTE_ALLOW_NOAUTH 2>/dev/null)
if [ -n "$allow" ]; then
  bad "OMNIROUTE_ALLOW_NOAUTH set — these keyless providers are OPEN: $allow"
else
  pass "OMNIROUTE_ALLOW_NOAUTH unset (every keyless provider blocked)"
fi

# ── 7. Amber / red providers ─────────────────────────────────────────────────
# PR #5 refuses both classes in code. Check the guard shipped in this build, and
# that the amber escape hatch is closed. Red has no hatch by design.
echo
echo "[7] Amber / red providers"

if docker exec "$CONTAINER" sh -c \
     'grep -rl OMNIROUTE_ALLOW_SUBSCRIPTION .build 2>/dev/null | head -1 | grep -q .' 2>/dev/null; then
  pass "green-only policy guard present in the deployed build"
else
  bad "OMNIROUTE_ALLOW_SUBSCRIPTION not found in the image — built from an UNPATCHED checkout (needs OmniRoute#5)"
fi

sub=$(docker exec "$CONTAINER" printenv OMNIROUTE_ALLOW_SUBSCRIPTION 2>/dev/null)
if [ -n "$sub" ]; then
  bad "OMNIROUTE_ALLOW_SUBSCRIPTION set — first-party subscription providers are OPEN: $sub"
else
  pass "OMNIROUTE_ALLOW_SUBSCRIPTION unset (amber blocked; red has no hatch)"
fi

echo
if [ "$fail" -eq 0 ]; then
  printf '\033[32mAll deployment rules hold.\033[0m\n'
else
  printf '\033[31mDeployment rules VIOLATED — see FAIL lines above.\033[0m\n'
fi
echo
echo "Not checked here (needs the dashboard UI):"
echo "  - requireLogin is a DB setting with no env var; confirm it is ON"
exit "$fail"
