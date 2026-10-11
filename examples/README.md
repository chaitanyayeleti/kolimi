# Example Kolimi plugins

Plugins are WebAssembly **components** built against the WIT world in
`crates/kolimi-plugins/wit/plugin.wit`. They run inside wasmtime with a
capability-scoped sandbox: the only host functions are logging, a
plugin-private key-value store, and the clock. WASI is linked with an
empty context (no directories, no sockets, no environment), every call
has a fuel budget and a 16 MiB memory cap, and traps are contained.

## Build

```sh
cargo install cargo-component --locked   # one-time
cd examples/hello-plugin
cargo component build --release
# → target/wasm32-wasip1/release/hello_plugin.wasm
```

## Install

Copy the component plus a metadata file into the server's plugin
directory (`<data-dir>/plugins/`, e.g. `/var/lib/kolimi/plugins`):

```sh
cp target/wasm32-wasip1/release/hello_plugin.wasm /var/lib/kolimi/plugins/hello.wasm
cat > /var/lib/kolimi/plugins/hello.json <<'JSON'
{ "name": "hello", "version": "0.1.0", "description": "example", "enabled": true }
JSON
```

Restart the server; the plugin answers at `/plugins/hello/…` for any
signed-in user, and appears in `GET /api/plugins`.

## Fixtures

`crates/kolimi-plugins/tests/fixtures/{hello,spin}.wasm` are the
compiled `hello-plugin` and `spin-plugin` (a runaway-loop test).
Rebuild them with `scripts/build-plugins.sh` after changing the WIT.
