# AGENTS.md

Kolimi is a single-binary, Rust-first Nextcloud alternative. One Cargo
workspace holds the server, domain crates, sync client, FFI and WASM UI;
`apps/kolimi-desktop` (Tauri) and `fuzz` are separate workspaces with their
own lockfiles. Rust 2024, MSRV 1.96, stable toolchain (nightly only for fuzz).

## Hard constraints

- Workspace lints deny `unsafe_code`, `clippy::unwrap_used`,
  `clippy::expect_used` and `clippy::panic` (`Cargo.toml`). Production code
  returns errors; tests opt out with a crate-level `#![allow(...)]` — don't
  remove those allows or add unwraps outside tests.
- Preserve the dependency direction in `docs/architecture.md`: the server is
  the composition root; business logic stays in domain crates. `kolimi-auth`
  must not depend on `kolimi-db`. The doc's claim that the server does not
  link `kolimi-crypto` is stale: it is a direct dependency used only for
  public-key validation in `api_e2ee.rs`; don't move decryption or file-key
  logic into the server.
- All file/share authorization is enforced inside `kolimi-vfs` (its internal
  `authz` module), including WebDAV, the JSON API and public links. Don't add
  route-local permission checks.
- Migrations are forward-only: never edit an applied file under
  `crates/kolimi-db/migrations/`; add the next `NNNN_*.sql`. They are
  embedded with `sqlx::migrate!`. Tests always start from a fresh DB, so
  upgrade paths are not covered — back up before deploying.
- MLS (RFC 9420) is **not externally audited**. Read
  `docs/audit/mls-delta.md` and `docs/rfc/0012-mls-groups.md` before touching
  groups, keyrings, epochs, membership or device state. Keep legacy v1
  per-file wraps readable; don't describe MLS as audited.
- Production is deployed outside this checkout. Releases are tag-driven in
  GitHub Actions; don't attempt to deploy from here.

## Verify (CI is the source of truth)

```sh
cargo test --workspace --all-features
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy -p kolimi-ui --target wasm32-unknown-unknown -- -D warnings
cargo clippy -p kolimi-kdf --target wasm32-unknown-unknown -- -D warnings
cargo deny check
cargo audit
cargo vet --locked
```

- Focused test: `cargo test -p kolimi-server --test mls_sync`, or
  `cargo test -p <crate> <name>`.
- WASM unit tests: set
  `CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner`, then
  run `cargo test -p kolimi-ui --target wasm32-unknown-unknown`.
- `scripts/smoke.sh` builds a debug server, starts it on port 18080 with temp
  data, and exercises real HTTP, cookies, CSRF and WebDAV. Override with
  `SMOKE_PORT`.
- `scripts/litmus.sh` is the WebDAV compliance suite; it downloads and builds
  neon (network + C deps), so run it only for DAV changes. Port 18099.
- Perf gates are `#[ignore]`d:
  `cargo test --release -p kolimi-server --test load -- --ignored`.
- Docs: `scripts/check-docs.sh` checks relative links, the RFC index and
  known stale claims (also a CI job).
- `cargo vet --locked` fails on a new dependency until it has an audit or
  exemption in `supply-chain/`. There are 724 exemptions, 89 of them the
  temporary openmls tree — none are audits.

## Separate workspaces

- Desktop: `cargo test --locked --manifest-path apps/kolimi-desktop/Cargo.toml`;
  package from that directory with `cargo tauri build --bundles deb` (needs
  `tauri-cli`, `libwebkit2gtk-4.1-dev`, appindicator, librsvg and patchelf).
  It has its own `Cargo.lock`; check it with
  `cargo metadata --locked --manifest-path apps/kolimi-desktop/Cargo.toml`.
  The native window loads the server's `/app/` UI; the bundled `ui/` is the
  Accounts & Sync window, not the file browser.
- Fuzz: nightly, from `fuzz/` (`cd fuzz && cargo fuzz run <target>`). Targets
  are `chunk_roundtrip`, `preview_image`, `e2ee_decrypt` and `mls_keyring`;
  CI only runs the first three, so run `mls_keyring` yourself for keyring work.

## Web UI

- `scripts/build-ui.sh` compiles `kolimi-ui` and `kolimi-kdf` to wasm and
  stages assets in `crates/kolimi-server/assets/ui/` (gitignored; only
  `not-built.html` is committed). It installs the exactly-matching
  `wasm-bindgen` CLI when needed.
- Debug builds read staged assets from disk; release builds embed them. Run
  the script before a release build, and rebuild `kolimi-server` after UI
  changes. If a release binary still serves the old/placeholder UI, force a
  recompile (e.g. `touch crates/kolimi-server/src/ui.rs`).
- `wasm32-unknown-unknown` is required. `.cargo/config.toml` sets getrandom's
  `wasm_js` backend for that target — don't remove it.

## Server basics

- `KOLIMI_DATA` picks the data dir (default `./kolimi-data`);
  `KOLIMI_ORIGIN` must match the URL browsers use or passkeys fail;
  `KOLIMI_SECURE_COOKIES=false` is for local HTTP (as `smoke.sh` does).
- `serve` is the default subcommand; `user`, `group`, `backup`, `verify` and
  `audit` are the maintenance commands.
- Integration tests build the axum app in-process with temp dirs; no Docker,
  Postgres or external service is needed.

## Cost / disk

- 739 locked packages (several hundred built on Linux), 15 crates and 31
  integration test files. Full debug test/clippy matrices can push
  `target/debug` into the hundreds of GB. Batch edits, use
  `cargo check --tests` while iterating, run the full matrix once, and clean
  target dirs after release-verification passes.

## Docs and release

- Read `docs/README.md`, `docs/architecture.md`, `docs/reference.md`,
  `docs/rfc/README.md`, `docs/audit/README.md` and
  `docs/plans/releases.md`.
- `docs/rfc/README.md` is the design/implementation status table; update it
  when an RFC ships. `scripts/check-docs.sh` guards links and stale claims.
- Releases: `vX.Y.Z` triggers the server/CLI/container/Helm/AUR release;
  `desktop-vX.Y.Z` triggers the desktop bundles. Push both tags for a paired
  release.
- Before tagging: `main` green, `CHANGELOG.md` entry, version bumped in
  `[workspace.package]`, every `version =` in `[workspace.dependencies]`
  (including `crates/kolimi-store`'s `kolimi-chunk`), the desktop manifests
  (`Cargo.toml`, `tauri.conf.json`) and `packaging/`; regenerate the root,
  desktop and fuzz lockfiles.
- Accepted RustSec warnings are documented in `docs/known-advisories.md` with
  revisit conditions; don't add new ignores silently.
