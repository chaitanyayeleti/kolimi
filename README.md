# Kolimi (కొలిమి)

**A pure-Rust, single-binary alternative to Nextcloud.** Fast, private, reliable — not bulky.

> *kolimi (కొలిమి)* — Telugu for **forge**: where raw iron is shaped into something durable.
> Rust is iron oxide; here, your data is forged into something that stays yours.

- One static binary — no PHP, nginx, Redis, or MySQL stack
- Rustls-only TLS, passkeys by default, zero telemetry
- Standard WebDAV / CalDAV / CardDAV — existing clients work on day one
- Content-addressed storage: dedup, delta sync, cheap versions, self-healing

See [ROADMAP.md](ROADMAP.md) for the full plan.

## Layout

| Path | Contents |
|---|---|
| `crates/kolimi-chunk` | Content-defined chunking (FastCDC) + BLAKE3 content-addressed manifests |
| `crates/kolimi-server` | The single binary (axum); WebDAV, auth, storage land in M1/M2 |
| `docs/rfc/` | Design docs: RFC 0001 (storage engine), RFC 0002 (sync protocol) |
| `docs/threat-model.md` | Assets, adversaries, trust boundaries, review checklist |
| `fuzz/` | cargo-fuzz targets for chunking + manifest invariants |

## Development

```sh
cargo test --workspace           # unit tests
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p kolimi-server       # http://127.0.0.1:8080/healthz
```

Fuzzing (nightly + cargo-fuzz):

```sh
cargo install cargo-fuzz
cd fuzz && cargo fuzz run chunk_roundtrip
```

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).

**Status:** M0 — scaffolding (workspace, CI, chunk primitives, RFCs).
