#!/usr/bin/env bash
# Deterministic server fixture for the Playwright suite.
#
# Users: alice (owner) and bob. Alice has an E2EE keyring, an encrypted
# `Private/Team` folder, and one legacy v1 folder share with bob so the
# browser test can exercise the migration UI. Bob has published an MLS key
# package so the migration can add him to the group.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${KOLIMI_E2E_PORT:-18085}"
BASE="http://localhost:$PORT"
PASS="browser-e2e-pass-123"
E2EE_PASS="browser-e2ee-pass-123"
DATA="$(mktemp -d)"
WORK="$(mktemp -d)"
LOG="$WORK/server.log"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$DATA" "$WORK"
}
trap cleanup EXIT INT TERM

fail() {
    printf 'browser-e2e server: %s\n' "$*" >&2
    if [ -f "$LOG" ]; then
        tail -80 "$LOG" >&2 || true
    fi
    exit 1
}

SERVER=./target/debug/kolimi-server
SYNC=./target/debug/kolimi-sync
[ -x "$SERVER" ] || fail "missing $SERVER (run: cargo build -p kolimi-server -p kolimi-sync)"
[ -x "$SYNC" ] || fail "missing $SYNC (run: cargo build -p kolimi-server -p kolimi-sync)"

KOLIMI_DATA="$DATA" KOLIMI_ORIGIN="$BASE" KOLIMI_SECURE_COOKIES=false \
    "$SERVER" serve --bind "127.0.0.1:$PORT" >"$LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 200); do
    if curl -fsS -m 2 "$BASE/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
curl -fsS -m 2 "$BASE/healthz" >/dev/null || fail "server did not start"

KOLIMI_DATA="$DATA" "$SERVER" user add alice --password "$PASS" >/dev/null
KOLIMI_DATA="$DATA" "$SERVER" user add bob --password "$PASS" >/dev/null

mkdir -p "$WORK/alice" "$WORK/bob"

sync() {
    local user="$1" dir="$2"
    shift 2
    KOLIMI_E2EE_PASSPHRASE="$E2EE_PASS" "$SYNC" \
        --server "$BASE" --user "$user" --password "$PASS" --local "$dir" "$@"
}

sync alice "$WORK/alice" --e2ee-setup >/dev/null
sync bob "$WORK/bob" --e2ee-setup >/dev/null

mkdir -p "$WORK/alice/Private/Team"
printf 'legacy encrypted folder\n' >"$WORK/alice/Private/Team/note.txt"
sync alice "$WORK/alice" --e2ee-root Private >/dev/null
sync bob "$WORK/bob" --e2ee-root Private --mls >/dev/null

# Legacy v1 share; the browser test upgrades it to MLS through Settings.
sync alice "$WORK/alice" --e2ee-root Private --share Private/Team --with bob >/dev/null

printf 'browser-e2e server ready at %s\n' "$BASE"
wait "$SERVER_PID"
