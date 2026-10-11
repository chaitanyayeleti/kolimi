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
| `crates/kolimi-sync` | Desktop sync core + `kolimi-sync` CLI: bidirectional delta sync |
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

## End-to-end encryption (alpha)

Files under a configured `--e2ee-root` are encrypted on the client
before they are chunked and uploaded; the server stores ciphertext,
wrapped per-file keys, and a keyring it cannot decrypt. Chunks use
deterministic AEAD so delta sync and CAS dedup keep working within a
file's history, and the manifest hashes ciphertext chunks (structure
leaks, content does not — RFC 0007 documents this honestly).

```sh
# one-time setup (prints a recovery code once)
kolimi-sync --server https://cloud.example.com --user alice \
    --local ~/Kolimi --e2ee-setup

# sync with the "Private/" subtree encrypted
KOLIMI_E2EE_PASSPHRASE=... kolimi-sync --server ... --user alice \
    --local ~/Kolimi --e2ee-root Private
```

Sharing encrypted files with named users:

```sh
# the recipient must have set up E2EE once (--e2ee-setup)
kolimi-sync --server ... --user alice --password ... --local ~/Kolimi \
    --e2ee-root Private --share Private/doc.txt --with bob
```

The owner's client wraps the file keys for bob (X25519); bob's next
sync pulls the file decrypted into `Shared with me/` (read-only).
`--unshare` revokes it. Groups work too (`--group team`): keys are
wrapped for every member, and removing a member revokes their keys so
their next sync drops the local copy. This is per-member wrapping, not
MLS — RFC 9420 group messaging remains the roadmap item. Public links
to encrypted files are refused.

Unlock works with the passphrase, the recovery code, or a passkey PRF
(platform shells supply the PRF output; RFC 0007). The server never indexes or previews encrypted
content, and sharing encrypted files is disabled in v1. Test vectors
are committed (`crates/kolimi-crypto/tests/vectors.json`) for other
implementations; `crates/kolimi-crypto` holds the primitives.

## Desktop tray + mobile core

- **Tray shell** (`apps/kolimi-tray`, Tauri, its own workspace): reads
  `~/.config/kolimi/tray.json`, shows live sync status in the tray,
  syncs on startup, every 5 minutes, and on demand.
- **Mobile core** (`crates/kolimi-ffi`, UniFFI): Kotlin/Swift/Python
  bindings for the sync core + E2EE setup (PRF secrets come from the
  platform ceremony). Background scheduling (WorkManager /
  BGTaskScheduler) is platform code; the FFI boundary is documented for
  it.

## Desktop sync (alpha)

`kolimi-sync` mirrors a local directory against the server over the
native delta protocol: pull downloads only chunks missing from the local
cache, push chunks client-side (FastCDC + BLAKE3, identical to the
server) and commits manifests with conflict detection. Conflicts keep the
server version and preserve local edits as `name.conflict-<timestamp>`;
deletions propagate both ways; state and chunk cache live in
`<local>/.kolimi/`.

```sh
kolimi-sync --server https://cloud.example.com --user alice \
    --local ~/Kolimi            # password via KOLIMI_PASSWORD
```

Run it from a timer or file watcher; the Tauri/mobile shells will wrap
this core (uniffi bindings are the planned mobile path).

## Install

**One command** (downloads the signed release, installs the systemd
unit, creates the admin account, prints your password once):

```sh
curl -fsSL https://raw.githubusercontent.com/chaitanyayeleti/kolimi/main/scripts/install.sh | sh
```

Other paths:

- **Arch (AUR)**: `packaging/arch/PKGBUILD` — builds from source, ships
  the systemd unit and sysusers/tmpfiles.
- **Debian/Ubuntu**: `.deb` built with `cargo deb -p kolimi-server`
  (postinst creates the `kolimi` user and state dir).
- **Docker**: `docker build -f packaging/docker/Dockerfile -t kolimi .`
  then `docker run -d -p 8080:8080 -v kolimi-data:/data kolimi`
  (distroless, nonroot). Compose example in `packaging/docker/`.
- **Kubernetes**: `helm install kolimi packaging/helm/kolimi`
  (PVC, probes, nonroot, ingress values included).
- **systemd**: `packaging/systemd/kolimi.service` with hardening
  (strict filesystem protection, syscall filter, private tmp, umask 077).

Release artifacts are signed with cosign (keyless, GitHub OIDC) and
shipped with a CycloneDX SBOM; `install.sh` verifies checksums and, when
`cosign` is installed, the signature.

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

## Two-factor authentication

TOTP (RFC 6238, 6 digits, 30 s) plus ten one-time recovery codes:

- **Web UI**: sign in, open **Passkeys** in the toolbar, enable
  two-factor — scan the QR with any authenticator app, confirm a code,
  and store the recovery codes shown once.
- **Login**: the sign-in form asks for the code when the account has
  two-factor enabled; a recovery code works in the same field and is
  consumed on use.
- Replays inside the validity window are refused (the consumed time
  step is recorded), and lost devices can be recovered with a recovery
  code or by an administrator: `kolimi-server user totp-disable alice`.

All events (`totp.enable`, `totp.disable`, `auth.totp_required`,
`totp.admin_disable`) land in the audit log.

## Plugins (sandboxed WASM)

Drop a WebAssembly component and a metadata file into
`<data-dir>/plugins/`:

```sh
cp hello_plugin.wasm /var/lib/kolimi/plugins/hello.wasm
echo '{"name":"hello","version":"0.1.0","enabled":true}' \
    > /var/lib/kolimi/plugins/hello.json
```

The plugin serves `/plugins/hello/…` for signed-in users and shows up in
`GET /api/plugins`. The sandbox is the import list: plugins get logging,
a plugin-private key-value store, and the clock — nothing else. WASI is
linked with an empty context (no directories, no sockets, no env), each
call has a fuel budget and a 16 MiB memory cap, and a trapping plugin is
contained and audited (`plugin.error`). Build plugins with
`cargo-component` against `crates/kolimi-plugins/wit/plugin.wit`; see
`examples/` for a working plugin and `scripts/build-plugins.sh` for the
test fixtures.

## Metrics and performance gates

`GET /metrics` exposes Prometheus text metrics: request counts and
latency histograms by route template, file uploads, preview outcomes,
and login failures. Labels never contain paths, file names, or user
identifiers.

Performance gates run in CI on every push (`cargo test --release -p
kolimi-server --test load -- --ignored`): 10k-file tree walk and change
feed each under 5 s, metadata p95 within budget, and the release binary
under 50 MB. Current numbers on a laptop: tree walk ~0.6 s, delta feed
~0.1 s, browse p95 ~12 ms.

## Audit log

Every security-relevant action (logins and failures, logouts, passkey
changes, file writes/deletes/moves, shares, public-link unlocks and
downloads, CLI user/group changes) is appended to a hash-chained audit
log: each entry hashes the previous entry's hash together with its own
fields, so editing, removing, or reordering rows is detectable.

```sh
kolimi-server audit list --limit 50    # JSON lines, newest first
kolimi-server audit verify             # exits 1 and names the first bad entry
```

The log is tamper-evident, not fail-closed: a failed append is logged
but does not fail the audited operation.

## Passkey-only accounts

A user with a registered passkey can drop the password entirely:

```sh
kolimi-server user passkey-only alice  # requires >= 1 registered passkey
```

Password login for such accounts is rejected (and audited); sign-in
goes through the WebAuthn endpoints. In the web UI: sign in once, open
**Passkeys** in the toolbar to register a device, then use *Sign in with
a passkey* on the login page — no password needed afterwards.

## End-to-end encryption (alpha)

Files under a configured `--e2ee-root` are encrypted on the client
before they are chunked and uploaded; the server stores ciphertext,
wrapped per-file keys, and a keyring it cannot decrypt. Chunks use
deterministic AEAD so delta sync and CAS dedup keep working within a
file's history, and the manifest hashes ciphertext chunks (structure
leaks, content does not — RFC 0007 documents this honestly).

```sh
# one-time setup (prints a recovery code once)
kolimi-sync --server https://cloud.example.com --user alice \
    --local ~/Kolimi --e2ee-setup

# sync with the "Private/" subtree encrypted
KOLIMI_E2EE_PASSPHRASE=... kolimi-sync --server ... --user alice \
    --local ~/Kolimi --e2ee-root Private
```

Sharing encrypted files with named users:

```sh
# the recipient must have set up E2EE once (--e2ee-setup)
kolimi-sync --server ... --user alice --password ... --local ~/Kolimi \
    --e2ee-root Private --share Private/doc.txt --with bob
```

The owner's client wraps the file keys for bob (X25519); bob's next
sync pulls the file decrypted into `Shared with me/` (read-only).
`--unshare` revokes it. Groups work too (`--group team`): keys are
wrapped for every member, and removing a member revokes their keys so
their next sync drops the local copy. This is per-member wrapping, not
MLS — RFC 9420 group messaging remains the roadmap item. Public links
to encrypted files are refused.

Unlock works with the passphrase, the recovery code, or a passkey PRF
(platform shells supply the PRF output; RFC 0007). The server never indexes or previews encrypted
content, and sharing encrypted files is disabled in v1. Test vectors
are committed (`crates/kolimi-crypto/tests/vectors.json`) for other
implementations; `crates/kolimi-crypto` holds the primitives.

## Desktop tray + mobile core

- **Tray shell** (`apps/kolimi-tray`, Tauri, its own workspace): reads
  `~/.config/kolimi/tray.json`, shows live sync status in the tray,
  syncs on startup, every 5 minutes, and on demand.
- **Mobile core** (`crates/kolimi-ffi`, UniFFI): Kotlin/Swift/Python
  bindings for the sync core + E2EE setup (PRF secrets come from the
  platform ceremony). Background scheduling (WorkManager /
  BGTaskScheduler) is platform code; the FFI boundary is documented for
  it.

## Desktop sync (alpha)
the change feed (per-user isolation, snippet excerpts, UI search box) and
sandboxed previews: decoding happens in a re-executed worker under
landlock + seccomp + rlimits with wall-clock kills, so a hostile image
can never take the server down (tested, plus a cargo-fuzz decode target).
Desktop sync core alpha landed (bidirectional delta sync CLI with
conflict handling, tested end-to-end against a live server). M6
complete for v1 scope: append-only hash-chained audit log, passkey-only
accounts with browser WebAuthn ceremonies, and client-side E2EE (RFC
0007) with passphrase/recovery/PRF unlock, committed interop vectors,
and an independent decoder test. M5 clients complete: Tauri tray shell
and UniFFI bindings (Kotlin/Swift/Python verified; Python exercised
end-to-end). M2 scrub landed: the janitor re-verifies blobs
incrementally with an audited cursor. Internal crypto review written
(`docs/crypto-review.md`). M7 packaging landed: install script (one
command to a working, password-protected share link), AUR PKGBUILD,
.deb, distroless Docker + compose, hardened systemd unit, Helm chart,
tag-triggered release workflow (gnu + musl tarballs, sha256, cosign
signatures, CycloneDX SBOM), and cargo-vet infrastructure in CI.
External audit, E2EE sharing, and the wasm plugin host remain. 250+
tests; litmus 100%; rclone byte-identical.
