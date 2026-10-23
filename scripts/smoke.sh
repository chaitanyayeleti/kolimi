#!/usr/bin/env bash
# End-to-end smoke test against a real server process.
#
# Unit tests call handlers directly; this exercises the same HTTP surface a
# browser uses — cookies, CSRF, WebDAV — including the flows that broke in
# 0.1.30–0.1.32 (sign-out, root uploads, encryption inheritance). Run it
# before every release:
#
#   scripts/smoke.sh
#
# Exits non-zero on the first failure and prints what failed.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${SMOKE_PORT:-18080}"
BASE="http://localhost:$PORT"
DATA="$(mktemp -d)"
JAR="$(mktemp)"
LOG="$(mktemp)"
SERVER_PID=""

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$DATA" "$JAR" "$LOG"
}
trap cleanup EXIT

fail() { printf '\nFAIL: %s\n' "$*" >&2; tail -40 "$LOG" >&2; exit 1; }
ok() { printf '  ok  %s\n' "$*"; }

say() { printf '\n== %s\n' "$*"; }

# --- build & start -------------------------------------------------------
say "building server"
cargo build --quiet -p kolimi-server

say "starting server on $BASE"
KOLIMI_DATA="$DATA" KOLIMI_ORIGIN="$BASE" KOLIMI_SECURE_COOKIES=false \
    ./target/debug/kolimi-server serve --bind "127.0.0.1:$PORT" >"$LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 100); do
    if curl -fsS -m 2 "$BASE/healthz" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
curl -fsS -m 2 "$BASE/healthz" >/dev/null || fail "server did not come up"

say "creating user"
printf 'smoke-password\n' | KOLIMI_DATA="$DATA" \
    ./target/debug/kolimi-server user add smoke --password-stdin >/dev/null

csrf() { grep -i 'kolimi_csrf' "$JAR" | awk '{print $NF}'; }
# curl wrapper: cookie jar + CSRF header, prints the status code.
req() {
    local method="$1" url="$2"; shift 2
    curl -sS -m 30 -b "$JAR" -c "$JAR" -H "X-CSRF-Token: $(csrf)" \
        -X "$method" "$BASE$url" -o /dev/null -w '%{http_code}' "$@"
}

say "login"
code=$(curl -sS -m 10 -c "$JAR" -H 'Content-Type: application/json' \
    -d '{"username":"smoke","password":"smoke-password"}' \
    "$BASE/api/session" -o /dev/null -w '%{http_code}')
[ "$code" = 200 ] || fail "login returned $code"
ok "login"

code=$(curl -sS -m 10 -b "$JAR" "$BASE/api/me" -o /dev/null -w '%{http_code}')
[ "$code" = 200 ] || fail "/api/me returned $code"
ok "session works"

say "browser Basic credentials cannot bypass the session"
# If /api/me accepted Basic, a browser that was once challenged would sign
# itself in without a cookie and sign-out could never revoke it. It must
# answer 401 and must NOT re-challenge (a challenge is what caches the
# password in the browser in the first place).
probe=$(curl -sS -m 10 -D - -o /dev/null -u smoke:smoke-password "$BASE/api/me" | tr -d '\r')
code=$(printf '%s' "$probe" | head -1 | awk '{print $2}')
[ "$code" = 401 ] || fail "/api/me with Basic returned $code (expected 401)"
printf '%s' "$probe" | grep -qi '^www-authenticate:' && fail "/api/me sent a Basic challenge"
ok "session probe ignores Basic and sends no challenge"

# WebDAV clients cannot hold cookies or send CSRF headers, so they keep Basic.
code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -u smoke:smoke-password \
    -X PROPFIND -H 'Depth: 0' "$BASE/dav/")
[ "$code" = 207 ] || fail "WebDAV Basic auth returned $code (expected 207)"
ok "WebDAV Basic auth still works"

# Scripts using `curl -u` keep working on the rest of the API.
code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -u smoke:smoke-password "$BASE/api/me/usage")
[ "$code" = 200 ] || fail "API Basic auth returned $code (expected 200)"
ok "API Basic auth still works"

say "default folders"
body=$(curl -sS -m 10 -b "$JAR" "$BASE/api/browse?path=/")
for folder in Photos Videos Images Vault; do
    echo "$body" | grep -q "\"name\":\"$folder\"" || fail "missing default folder $folder"
done
ok "Photos, Videos, Images, Vault exist"

vault=$(curl -sS -m 10 -b "$JAR" "$BASE/api/files/info?path=/Vault")
echo "$vault" | grep -q '"encrypted":true' || fail "Vault is not encrypted"
ok "Vault is encrypted"

say "plaintext upload to root"
code=$(req PUT /dav/root.txt --data-binary 'hello root' -H 'Content-Type: text/plain')
[ "$code" = 201 ] || fail "root upload returned $code"
got=$(curl -sS -m 10 -b "$JAR" "$BASE/dav/root.txt")
[ "$got" = "hello root" ] || fail "root download mismatch"
ok "upload + download at /"

say "folder inside Vault inherits encryption"
code=$(req MKCOL /dav/Vault/sub)
[ "$code" = 201 ] || fail "MKCOL /Vault/sub returned $code"
info=$(curl -sS -m 10 -b "$JAR" "$BASE/api/files/info?path=/Vault/sub")
echo "$info" | grep -q '"encrypted":true' || fail "/Vault/sub is not reported encrypted"
ok "nested folder reports encrypted"

say "plaintext cannot be written into Vault"
code=$(req PUT /dav/Vault/leak.txt --data-binary 'plaintext' -H 'Content-Type: text/plain')
[ "$code" = 403 ] || fail "plaintext PUT into Vault returned $code (expected 403)"
ok "plaintext write refused (403)"

say "encrypted commit requires a key"
manifest='{"version":1,"size":4,"chunks":[{"hash":"0000000000000000000000000000000000000000000000000000000000000000","len":4}]}'
code=$(req PUT '/api/files?path=/Vault/sub/x.bin' -H 'Content-Type: application/json' --data-binary "$manifest")
[ "$code" = 409 ] || fail "keyless commit returned $code (expected 409)"
ok "keyless commit refused (409)"

say "public link"
code=$(req POST /api/shares -H 'Content-Type: application/json' \
    --data-binary '{"path":"/root.txt","kind":"link","password":""}')
[ "$code" = 201 ] || fail "link creation returned $code"
ok "public link created"

say "sign out by navigation"
code=$(curl -sS -m 10 -b "$JAR" -c "$JAR" "$BASE/logout" -o /dev/null -w '%{http_code}')
[ "$code" = 200 ] || [ "$code" = 303 ] || fail "/logout returned $code"
code=$(curl -sS -m 10 -b "$JAR" "$BASE/api/me" -o /dev/null -w '%{http_code}')
[ "$code" = 401 ] || fail "session survived logout (/api/me = $code)"
ok "session revoked and cookies cleared"

printf '\nAll smoke checks passed.\n'
