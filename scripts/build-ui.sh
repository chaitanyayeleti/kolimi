#!/usr/bin/env bash
# Builds the Leptos web UI to WebAssembly and stages it for embedding.
#
# Output: crates/kolimi-server/assets/ui/{index.html,style.css,app.js,app_bg.wasm}
# The server embeds these (rust-embed) and serves them under /app.
set -euo pipefail

cd "$(dirname "$0")/.."

OUT="crates/kolimi-server/assets/ui"
TARGET="wasm32-unknown-unknown"

if ! rustup target list --installed | grep -q "$TARGET"; then
    rustup target add "$TARGET"
fi

echo "building kolimi-ui for $TARGET (release)"
cargo build -p kolimi-ui --target "$TARGET" --release

# wasm-bindgen CLI must match the wasm-bindgen crate version exactly.
WB_VERSION=$(awk '/name = "wasm-bindgen"/{found=1; next} found && /^version = /{gsub(/"/, "", $3); print $3; exit}' Cargo.lock)
if [[ -z "$WB_VERSION" ]]; then
    echo "error: could not determine wasm-bindgen version from Cargo.lock" >&2
    exit 1
fi

if ! command -v wasm-bindgen >/dev/null 2>&1 \
    || ! wasm-bindgen --version 2>/dev/null | grep -q " $WB_VERSION$"; then
    echo "installing wasm-bindgen-cli $WB_VERSION"
    cargo install wasm-bindgen-cli --version "$WB_VERSION" --locked
fi

mkdir -p "$OUT"
wasm-bindgen \
    --target web \
    --no-typescript \
    --out-dir "$OUT" \
    --out-name app \
    "target/$TARGET/release/kolimi_ui.wasm"
cp crates/kolimi-ui/index.html crates/kolimi-ui/style.css crates/kolimi-ui/bootstrap.js "$OUT/"

# Argon2id runs in a Web Worker so unlocking never freezes the tab. Build it
# as a second, tiny wasm module plus the worker glue.
echo "building kolimi-kdf for $TARGET (release)"
cargo build -p kolimi-kdf --target "$TARGET" --release
wasm-bindgen \
    --target web \
    --no-typescript \
    --out-dir "$OUT" \
    --out-name kdf \
    "target/$TARGET/release/kolimi_kdf.wasm"
cp crates/kolimi-kdf/worker.js "$OUT/kdf-worker.js"
cp crates/kolimi-ui/favicon.svg crates/kolimi-ui/favicon-32.png crates/kolimi-ui/apple-touch-icon.png "$OUT/"

# Optional size pass. wasm-bindgen output is valid on its own; if binaryen is
# unavailable or rejects a module, keep the original bytes.
if command -v wasm-opt >/dev/null 2>&1; then
    for wasm in app_bg.wasm kdf_bg.wasm; do
        if wasm-opt -Oz --strip-debug -o "$OUT/$wasm.opt" "$OUT/$wasm" 2>/dev/null; then
            mv "$OUT/$wasm.opt" "$OUT/$wasm"
        else
            rm -f "$OUT/$wasm.opt"
            printf 'wasm-opt skipped %s (module uses unsupported features)\n' "$wasm" >&2
        fi
    done
fi

# Precompress the assets the browser fetches on first paint. The server
# negotiates Accept-Encoding and falls back to the raw file.
rm -f "$OUT"/*.br "$OUT"/*.gz
for asset in app.js app_bg.wasm style.css kdf.js kdf_bg.wasm; do
    [ -f "$OUT/$asset" ] || continue
    if command -v brotli >/dev/null 2>&1; then
        brotli -q 11 -f -o "$OUT/$asset.br" "$OUT/$asset"
    fi
    gzip -9 -n -c "$OUT/$asset" >"$OUT/$asset.gz"
done

# Keep the first-load cost honest. The raw bundle is allowed to grow a little
# with features; the Brotli representation is the number users actually pay.
raw_wasm=$(wc -c <"$OUT/app_bg.wasm")
if [ "$raw_wasm" -gt 5600000 ]; then
    printf 'error: app_bg.wasm is %s bytes (budget 5.6 MB)\n' "$raw_wasm" >&2
    exit 1
fi
if [ -f "$OUT/app_bg.wasm.br" ]; then
    br_wasm=$(wc -c <"$OUT/app_bg.wasm.br")
    if [ "$br_wasm" -gt 1300000 ]; then
        printf 'error: app_bg.wasm.br is %s bytes (budget 1.3 MB)\n' "$br_wasm" >&2
        exit 1
    fi
    printf 'app_bg.wasm: %s raw, %s brotli\n' "$raw_wasm" "$br_wasm"
fi

echo "UI staged in $OUT"
if [ "${VERBOSE:-0}" = 1 ]; then
    ls -lh "$OUT"
fi
