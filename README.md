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
| `crates/kolimi-store` | Per-user content-addressed blob store: atomic writes, verify-on-read |
| `crates/kolimi-db` | SQLite persistence (users, sessions, file tree) with migrations |
| `crates/kolimi-auth` | Argon2id passwords, session tokens, brute-force lockout, credential cache |
| `crates/kolimi-vfs` | Path-safe virtual filesystem over DB + blobs; single permission engine |
| `crates/kolimi-webdav` | WebDAV surface: OPTIONS, GET/HEAD, PUT, DELETE, MKCOL, PROPFIND, COPY, MOVE |
| `crates/kolimi-server` | The single binary: session API, auth middleware, CLI, TLS |
| `docs/rfc/` | Design docs: RFC 0001 (storage engine), RFC 0002 (sync protocol) |
| `docs/threat-model.md` | Assets, adversaries, trust boundaries, review checklist |
| `fuzz/` | cargo-fuzz targets for chunking + manifest invariants |

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Fuzzing (nightly + cargo-fuzz):

```sh
cargo install cargo-fuzz
cd fuzz && cargo fuzz run chunk_roundtrip
```

## Run

```sh
# create a user (first user becomes admin)
cargo run -p kolimi-server -- user add alice

# serve (add --tls-cert cert.pem --tls-key key.pem for TLS;
# set --origin to the public URL so passkeys work in browsers)
cargo run -p kolimi-server -- serve --bind 127.0.0.1:8080 --data ./kolimi-data \
    --origin https://cloud.example.com
```

Use it with any WebDAV client (rclone, davfs2, Finder, Windows Explorer):

```sh
curl -u alice:PASSWORD -X PUT --data-binary @report.txt http://127.0.0.1:8080/dav/report.txt
curl -u alice:PASSWORD http://127.0.0.1:8080/dav/report.txt
curl -u alice:PASSWORD -X PROPFIND -H "Depth: 1" http://127.0.0.1:8080/dav/
```

Session API for first-party clients: `POST /api/session` (login, sets
`kolimi_session` + `kolimi_csrf` cookies), `GET /api/me`, `DELETE /api/session`.

Passkeys (WebAuthn): `POST /api/passkeys/register/begin|finish` (authenticated),
`GET /api/passkeys`, `DELETE /api/passkeys/{id}`, and passwordless login via
`POST /api/passkeys/login/begin|finish`. Duplicate registrations are excluded
per user and challenges are single-use, user-bound, and expire after 5 minutes.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).

**Status:** M1 complete — password + passkey auth, per-user blob storage,
WebDAV core, TLS. Validated with rclone (upload/download/move/delete,
byte-identical trees) and 115 tests incl. a full passkey ceremony with a
soft authenticator. Next: litmus run, then M2 chunked CAS storage
(versions, trash, delta sync).
