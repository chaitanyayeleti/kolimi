# Architecture

Kolimi ships **one server binary** on purpose — no PHP-FPM, nginx, Redis or
MySQL chain. The workspace has **15 crates** with a strict dependency
direction; `apps/kolimi-desktop` (Tauri) and `fuzz` are separate workspaces
with their own lockfiles.

## Boundaries that matter

- **The server is the composition root.** Route modules (`api_*.rs`), the
  janitor, metrics and the binary live in `kolimi-server`; business logic
  stays in the domain crates. The server crate is large because it wires
  everything together, not because it owns the rules.
- **The server stores ciphertext, not plaintext.** `kolimi-server` links
  `kolimi-crypto` for one narrow purpose: validating public keys in
  `api_e2ee.rs`. It never receives a file key, a master key or an MLS
  secret; E2EE/MLS payloads are opaque blobs to it.
- **`kolimi-auth` does not depend on `kolimi-db`.** The server hands it
  rows, so authentication logic cannot reach into the file tree.
- **One permission engine.** Every file/share lookup for WebDAV, the JSON
  API, public links and the UI is authorized inside `kolimi-vfs` (its
  internal `authz` module). Route handlers must not invent their own
  checks.
- **MLS state belongs to clients.** `kolimi-mls` wraps `openmls`; sync and
  the web UI create/join groups and hold the epoch secrets. The server
  stores key packages, commits, Welcomes and the encrypted keyring, and
  enforces ordering/epoch rules.
- **Third-party code never links into the server.** Previews decode in a
  re-executed worker sandboxed with landlock + seccomp + rlimits.
- **The desktop client is a separate workspace.** The Tauri/WebKit
  dependency tree never touches the server build.

## Crate map

| Crate | Role | Depends on |
| --- | --- | --- |
| `kolimi-chunk` | FastCDC chunking, manifests, content ids | — |
| `kolimi-crypto` | E2EE primitives: keyring, file keys, chunk AEAD, X25519 sharing | — |
| `kolimi-db` | SQLite persistence and migrations (users, tree, shares, DAV, E2EE, MLS, audit) | — |
| `kolimi-store` | Content-addressed blob store, GC, scrub | `chunk` |
| `kolimi-auth` | Passwords, sessions, passkeys, TOTP, lockout | — |
| `kolimi-vfs` | Path-safe filesystem + the single permission engine | `chunk`, `db`, `store` |
| `kolimi-webdav` | WebDAV, CalDAV and CardDAV protocol surfaces | `auth`, `db`, `store`, `vfs` |
| `kolimi-search` | tantivy full-text index fed from the change feed | — |
| `kolimi-preview` | Sandboxed preview decoder | — |
| `kolimi-mls` | MLS (RFC 9420) helpers: devices, key packages, groups, exporter, keyring | — (`openmls`) |
| `kolimi-kdf` | Argon2id Web Worker wasm module | — |
| `kolimi-ui` | Leptos web UI, compiled to wasm and embedded as assets | `chunk`, `crypto`, `mls` (wasm only) |
| `kolimi-sync` | Desktop sync core + `kolimi-sync` CLI | `chunk`, `crypto`, `mls` |
| `kolimi-ffi` | UniFFI bindings for mobile shells | `crypto`, `sync` |
| `kolimi-server` | HTTP routes, `AppState`, janitor, metrics, binary | all workspace crates |
| `apps/kolimi-desktop` | Tauri desktop client (separate workspace) | `sync` + OS keychain |
| `fuzz` | cargo-fuzz targets (separate nightly workspace) | selected crates |

Dependency direction is acyclic and one-way: leaf utilities → domain →
protocols → composition root. The browser build is wasm32-only and must not
pull in the server, database or Tokio.

## Runtime shape

```
                 ┌──────────────────────── kolimi-server ───────────────────────┐
 client ──TLS──▶ │ axum router: /dav /api /public /app /metrics                 │
                 │   auth middleware ─▶ kolimi-auth        (sessions/passkeys) │
                 │   route handlers ─▶ kolimi-vfs::authz ─▶ permission engine  │
                 │                        │                                    │
                 │                        ├─▶ kolimi-db     (SQLite WAL)      │
                 │                        └─▶ kolimi-store  (CAS blobs)      │
                 │   background: janitor (retention, GC, BLAKE3 scrub)         │
                 │   background: search indexer (change feed → tantivy)        │
                 │   on demand: preview worker (landlock/seccomp/rlimits)      │
                 └─────────────────────────────────────────────────────────────┘
```

`/api/mls/*` follows the same path as files: the node ACL is checked, the
payload is stored as an opaque blob, and epochs/order are validated. The
server never has the group secret or the share keyring plaintext.

## Where coupling honestly exists

- **`kolimi-server` route modules** are the busiest files. If they grow
  further, the split is mechanical: extract an API crate and keep the
  binary as the composition root.
- **`kolimi-db` holds many tables** (users, nodes, shares, DAV, search
  state, audit, E2EE keys, MLS state). A Postgres backend would keep the
  same repository API and swap migrations/connection plumbing; it is not
  on the current critical path.
- **Feature flags** are deliberately small: `otel` enables OTLP trace
  export. Search and previews are always built in.
- **MLS is not externally audited.** The code and invariants are in
  `crates/kolimi-mls`, `crates/kolimi-sync/src/mls.rs`,
  `crates/kolimi-ui/src/mls.rs` and `/api/mls/*`; the review package is
  [`docs/audit/mls-delta.md`](audit/mls-delta.md).

## Read next

- [Crate-level design specs](rfc/README.md)
- [Threat model](threat-model.md)
- [E2EE design](rfc/0007-e2ee.md) and [MLS groups](rfc/0012-mls-groups.md)
- [Operations](operations.md) and [reference](reference.md)
