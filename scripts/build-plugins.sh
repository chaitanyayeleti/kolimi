#!/usr/bin/env bash
# Rebuilds the plugin fixtures used by the host tests.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v cargo-component >/dev/null 2>&1; then
    echo "cargo-component is required: cargo install cargo-component --locked" >&2
    exit 1
fi

for example in hello-plugin spin-plugin; do
    (cd "examples/$example" && cargo component build --release)
done
cp examples/hello-plugin/target/wasm32-wasip1/release/hello_plugin.wasm \
    crates/kolimi-plugins/tests/fixtures/hello.wasm
cp examples/spin-plugin/target/wasm32-wasip1/release/spin_plugin.wasm \
    crates/kolimi-plugins/tests/fixtures/spin.wasm
echo "fixtures updated"
