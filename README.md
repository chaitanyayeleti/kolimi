# Kolimi (కొలిమి)

**A single-binary, Rust-first alternative to Nextcloud.** Files, WebDAV,
Calendars and contacts, delta sync and end-to-end encryption — one
long-running process, SQLite and the filesystem, with no PHP, nginx, Redis
or MySQL to operate.

[Install](docs/install.md) · [Operate](docs/operations.md) ·
[Architecture](docs/architecture.md) · [Reference](docs/reference.md) ·
[Security & audit](docs/audit/README.md) · [Roadmap](ROADMAP.md)

## Why Kolimi

- **One binary, one data directory.** The HTTP/WebDAV server, SQLite
  database, blob store and WASM web UI all ship in `kolimi-server`.
- **Protocol-first.** WebDAV with class-2 locking, CalDAV/CardDAV with
  `sync-collection`, and a native chunked delta protocol for first-party
  clients.
- **Delta sync.** FastCDC + BLAKE3 content-addressed storage gives
  chunk-level transfers, deduplication, versions, trash, and a desktop tray
  app / `kolimi-sync` CLI.
- **End-to-end encryption.** Per-file keys for v1/v2 shares, MLS group
  shares for encrypted folders, encrypted names, and browser, desktop and
  CLI clients that keep keys off the server.
- **Auth without extra services.** Passkeys, passwordless accounts, TOTP
  with recovery codes, CSRF-protected sessions, per-source rate limits and
  lockout.
- **Operable by default.** Prometheus `/metrics`, a hash-chained audit log,
  online backup/verify, systemd hardening, distroless containers, Helm,
  AUR, `.deb` and AppImage packages.

## Quick start

### Docker

```sh
docker run -d --name kolimi \
  -p 127.0.0.1:8080:8080 \
  -v kolimi-data:/data \
  -e KOLIMI_ORIGIN=http://localhost:8080 \
  ghcr.io/chaitanyayeleti/kolimi:latest

docker exec kolimi kolimi-server user add admin
```

Open <http://localhost:8080/app/> and sign in. Set `KOLIMI_ORIGIN` to the
public URL (scheme + host + port) or passkeys will not work.

### One-command install (systemd host)

```sh
curl -fsSL https://raw.githubusercontent.com/chaitanyayeleti/kolimi/main/scripts/install.sh | sh
```

The installer verifies the release (checksum and, when `cosign` is
installed, the signature), installs `kolimi-server` + `kolimi-sync`, creates
the admin account and prints the generated password once. See
[install.md](docs/install.md) for flags, the systemd unit and upgrades.

### From source

```sh
git clone https://github.com/chaitanyayeleti/kolimi
cd kolimi
./scripts/build-ui.sh
cargo build --release --locked -p kolimi-server -p kolimi-sync
./target/release/kolimi-server user add admin
KOLIMI_DATA=./kolimi-data ./target/release/kolimi-server serve \
  --bind 127.0.0.1:8080
```

`build-ui.sh` stages the WASM UI before the server is compiled; without it
the release binary serves a placeholder page. See [install.md](docs/install.md)
for Docker Compose, Helm, AUR, `.deb` and TLS.

## Security status

E2EE is **alpha**. The v1/v2 per-file design and the MLS group design are
implemented and covered by tests, but **MLS has not had an external crypto
audit**. The openmls tree currently carries temporary `cargo-vet`
exemptions; they are not audits. Do not treat MLS as reviewed for
high-risk data until the review in
[`docs/audit/mls-delta.md`](docs/audit/mls-delta.md) is complete.

The server stores ciphertext and opaque key material; it never receives
plaintext file keys. Encrypted names are supported, while sizes,
timestamps, structure and access patterns remain visible to the operator —
documented in [RFC 0007](docs/rfc/0007-e2ee.md) and the
[threat model](docs/threat-model.md).

## Documentation

| Start here | What it covers |
| --- | --- |
| [docs/install.md](docs/install.md) | Every installation path, TLS/reverse proxies, first run, upgrades |
| [docs/operations.md](docs/operations.md) | Users, groups, backup/restore, audit, metrics, E2EE, desktop clients, troubleshooting |
| [docs/reference.md](docs/reference.md) | CLI commands, environment variables, HTTP API, data layout |
| [docs/architecture.md](docs/architecture.md) | Crate map, dependency rules, runtime shape |
| [docs/README.md](docs/README.md) | Full docs map and status conventions |
| [docs/audit/README.md](docs/audit/README.md) | External crypto audit package |
| [docs/rfc/README.md](docs/rfc/README.md) | Design specs and implementation status |
| [ROADMAP.md](ROADMAP.md) | Current state, next work, non-goals |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Development

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
scripts/smoke.sh          # real server + HTTP/cookies/CSRF
scripts/build-ui.sh       # wasm UI; needed before a release build
```

`apps/kolimi-desktop` and `fuzz` are separate workspaces with their own
lockfiles. See [AGENTS.md](AGENTS.md) for the full verification matrix,
workspace boundaries and release checklist.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).
