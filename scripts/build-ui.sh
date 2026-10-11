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
WB_VERSION=$(sed -n '/name = "wasm-bindgen"/{n;s/^version = "\(.*\)"/\1/p;}' Cargo.lock | head -1)
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

echo "UI staged in $OUT"
ls -lh "$OUT"
