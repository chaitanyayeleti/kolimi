#!/usr/bin/env bash
# Runs the litmus WebDAV compliance suites against a freshly started
# kolimi-server. Builds neon + litmus from source into a work directory.
#
# Usage: scripts/litmus.sh
# Env:   LITMUS_WORK (default /tmp/kolimi-litmus-build), LITMUS_PORT (18099)
set -euo pipefail

NEON_VERSION="0.29.6"
LITMUS_VERSION="0.13"
WORK="${LITMUS_WORK:-/tmp/kolimi-litmus-build}"
PORT="${LITMUS_PORT:-18099}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="$(mktemp -d)"
trap 'rm -rf "$DATA"' EXIT
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$DATA"
}
trap cleanup EXIT

mkdir -p "$WORK"
cd "$WORK"

# --- neon (HTTP only; litmus tests run over plain HTTP) ---
if [ ! -f "$WORK/neon/.installed" ]; then
    rm -rf "$WORK/neon-src" "$WORK/neon"
    mkdir -p "$WORK/neon-src"
    curl -fsSL "http://www.webdav.org/neon/neon-$NEON_VERSION.tar.gz" \
        | tar xz -C "$WORK/neon-src"
    (
        cd "$WORK/neon-src/neon-$NEON_VERSION"
        CFLAGS="-O2 -Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion" \
            ./configure --prefix="$WORK/neon" --without-ssl --disable-shared --enable-static
        make -j"$(nproc)"
        make install
    )
    touch "$WORK/neon/.installed"
fi

# --- litmus ---
if [ ! -x "$WORK/litmus-$LITMUS_VERSION/basic" ]; then
    curl -fsSL "http://www.webdav.org/neon/litmus/litmus-$LITMUS_VERSION.tar.gz" \
        | tar xz -C "$WORK"
    (
        cd "$WORK/litmus-$LITMUS_VERSION"
        ./configure --with-neon="$WORK/neon"
        make -j"$(nproc)"
    )
fi

# --- server ---
cd "$ROOT"
cargo build -p kolimi-server
LITMUS_PASSWORD="litmus pass"
echo "$LITMUS_PASSWORD" | KOLIMI_DATA="$DATA" "$ROOT/target/debug/kolimi-server" user add alice >/dev/null
"$ROOT/target/debug/kolimi-server" serve --bind "127.0.0.1:$PORT" --data "$DATA" \
    >"$DATA/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

# --- suites ---
URL="http://127.0.0.1:$PORT/dav/"
STATUS=0
cd "$WORK/litmus-$LITMUS_VERSION"
for suite in basic copymove props http locks; do
    OUTPUT="$("./$suite" "$URL" alice "$LITMUS_PASSWORD" 2>&1 || true)"
    SUMMARY="$(echo "$OUTPUT" | grep -E "summary" | tail -1)"
    echo "$suite: $SUMMARY"
    if ! echo "$SUMMARY" | grep -q "0 failed"; then
        STATUS=1
        echo "$OUTPUT" | grep -E "FAIL" || true
    fi
done

if [ "$STATUS" -ne 0 ]; then
    echo "litmus: FAILED"
    exit 1
fi
echo "litmus: all suites passed"
