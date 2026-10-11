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
| `crates/kolimi-store` | Chunked content-addressed storage: FastCDC + BLAKE3, atomic writes, verify-on-read, GC |
| `crates/kolimi-db` | SQLite persistence (users, sessions, file tree) with migrations |
| `crates/kolimi-auth` | Argon2id passwords, session tokens, brute-force lockout, credential cache |
| `crates/kolimi-vfs` | Path-safe virtual filesystem over DB + blobs; single permission engine |
| `crates/kolimi-webdav` | WebDAV surface: OPTIONS, GET/HEAD, PUT, DELETE, MKCOL, PROPFIND, COPY, MOVE + CalDAV/CardDAV and REPORT |
| `crates/kolimi-search` | tantivy full-text index fed from the change feed, per-user isolation |
| `crates/kolimi-preview` | Preview decoding in a landlock+seccomp+rlimits worker process |
| `crates/kolimi-ui` | Leptos (WASM) web UI, embedded into the server binary |
| `crates/kolimi-server` | The single binary: session API, auth middleware, CLI, TLS |
| `docs/rfc/` | Design docs: RFC 0001 (storage), RFC 0002 (sync), RFC 0003 (sharing), RFC 0004 (CalDAV/CardDAV), RFC 0005 (search/previews) |
| `docs/threat-model.md` | Assets, adversaries, trust boundaries, review checklist |
| `fuzz/` | cargo-fuzz targets for chunking + manifest invariants |

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# build the web UI (wasm32 + wasm-bindgen; assets are embedded on rebuild)
scripts/build-ui.sh
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

Native sync API (delta transfers, RFC 0002):

| Endpoint | Purpose |
|---|---|
| `GET /api/sync/changes?since=&limit=` | Per-user change feed (`upsert`/`delete`/`move`) |
| `GET /api/sync/tree?after_id=&limit=` | Paginated namespace snapshot with paths + etags |
| `GET /api/sync/events?since=` | SSE wake-up channel (`{"seq": N}` pings) |
| `GET /api/files/manifest?path=` | Current manifest of a file |
| `GET /api/manifests/{content_id}` | Manifest by content id |
| `GET /api/chunks/{hash}` / `PUT /api/chunks/{hash}` | Chunk download / idempotent upload |
| `PUT /api/files?path=&if_content_id=` | Commit a client-built manifest (409 on conflict) |
| `GET /api/trash`, `POST /api/trash/{id}/restore`, `DELETE /api/trash/{id}` | Trash lifecycle |
| `GET /api/versions?path=`, `POST /api/versions/{id}/restore` | Version history |
| `GET /api/browse?path=` | Directory listing (own tree + received shares) for the UI |
| `GET /api/search?q=&limit=` | Full-text search over names, paths, and text content |
| `GET /api/preview?path=&size=` | Sandboxed thumbnails (images) and text heads |

Sharing (RFC 0003): received shares mount at `/Shared with me/<name>` in
WebDAV and the API; `POST /api/shares` creates user, group, or link shares;
`GET /api/shares?path=`, `GET /api/shares/received`, `GET /api/shares/owned`,
`PATCH /api/shares/{id}`, `DELETE /api/shares/{id}` manage them;
`GET /api/shareable` lists recipients. Public links are served anonymously
under `/public/{token}` (metadata, listing, `download`, `unlock`), and the
shareable page lives at `/s/{token}`. Public links get a generated password
and a 30-day expiry unless explicitly overridden, and unlock attempts are
rate-limited.

Groups are managed with the CLI (or `/api/admin`-style ops later):

```sh
kolimi-server group add team
kolimi-server group add-member team alice
kolimi-server group list
```

## Calendars & contacts (CalDAV / CardDAV)

Point Thunderbird, iOS, macOS, or DAVx⁵ at the server; discovery runs
through `/.well-known/caldav|carddav` → `/dav/` → principal → homes:

```
/dav/principals/{user}/         calendar-home-set + addressbook-home-set
/dav/calendars/{user}/{cal}/    MKCALENDAR, PROPFIND, REPORT, PROPPATCH
/dav/addressbooks/{user}/{ab}/  extended MKCOL (addressbook resourcetype)
```

Object resources support GET/PUT/DELETE/PROPFIND with ETag preconditions;
REPORT supports `calendar-query`/`addressbook-query` (filters advisory),
`*-multiget`, and `sync-collection` (RFC 6578) — including on the file
tree. iCalendar payloads are validated (one UID per resource) and vCards
structurally (3.0 and 4.0 accepted); both are stored byte-for-byte so
VALARMs and X-properties survive exactly. See RFC 0004 for deviations.

## Web UI

The Leptos (WASM) app is served from the binary at `/app/` (public share
pages at `/s/{token}`). Assets are built with `scripts/build-ui.sh` and
embedded on the next server build; without them the binary serves a
placeholder page.

## Maintenance CLI

```sh
# consistent snapshot (SQLite VACUUM INTO + blob copy) — safe while running
kolimi-server backup --data ./kolimi-data --to ./backups/2026-10-11
# verify every chunk of every file and version (BLAKE3)
kolimi-server verify --data ./kolimi-data
```

## WebDAV compliance

`scripts/litmus.sh` builds neon + litmus and runs the full suite against a
live server: **basic 16/16, copymove 13/13, props 30/30, http 4/4** (locks
suite skips cleanly: Kolimi advertises Class 1; LOCK/UNLOCK are not
implemented yet).

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).

**Status:** M5 server side complete — tantivy full-text search fed from
the change feed (per-user isolation, snippet excerpts, UI search box) and
sandboxed previews: decoding happens in a re-executed worker under
landlock + seccomp + rlimits with wall-clock kills, so a hostile image
can never take the server down (tested, plus a cargo-fuzz decode target).
226 tests; litmus 100%; rclone byte-identical. In progress: desktop sync
client alpha, mobile background upload (M5 clients).
