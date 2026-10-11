# Architecture

## The short answer: a deliverable monolith, not a code monolith

Kolimi ships **one server binary** on purpose — that is principle #1
("one static binary; no PHP-FPM, nginx, Redis, MySQL chain"). But the
code is 14 crates with a strict dependency direction, and the
composition root is the only place that knows about all of them.

A few facts that make this concrete:

- The production server **does not link the crypto crate**.
  `kolimi-crypto` is a dev-dependency of `kolimi-server`: the running
  server can only store opaque E2EE blobs, so it physically cannot use
  key material. That boundary is enforced by the compiler.
- `kolimi-auth` does not depend on the database crate: the server hands
  it rows. Auth logic cannot reach into your file tree.
- Third-party code never links into the binary. Plugins are WebAssembly
  components run by `kolimi-plugins` in a wasmtime sandbox whose
  capabilities are the import list.
- The desktop tray is a **separate workspace** (`apps/kolimi-tray`), so
  the Tauri/webkit dependency tree never touches the server build.

## Crate map

| Crate | Role | Depends on |
| --- | --- | --- |
| `kolimi-chunk` | FastCDC chunking, manifests, content ids | — |
| `kolimi-crypto` | E2EE primitives (keyring, file keys, X25519) | — |
| `kolimi-db` | SQLite persistence, migrations, all repositories | — |
| `kolimi-store` | Content-addressed blob store, GC, scrub | `chunk` |
| `kolimi-auth` | Passwords, tokens, passkeys, TOTP, lockout | — |
| `kolimi-vfs` | File tree operations + the single permission engine | `db`, `store` |
| `kolimi-webdav` | WebDAV + CalDAV/CardDAV protocol surfaces | `vfs` |
| `kolimi-search` | tantivy full-text index | — |
| `kolimi-preview` | Sandboxed preview decoder (re-exec worker) | — |
| `kolimi-plugins` | wasmtime component host for plugins | — |
| `kolimi-server` | Composition root: HTTP routes, AppState, janitor, metrics, binary | everything above |
| `kolimi-ui` | Leptos web UI, compiled to wasm and embedded as assets | (wasm only) |
| `kolimi-sync` | Desktop sync core + CLI | `chunk`, `crypto` |
| `kolimi-ffi` | UniFFI bindings for mobile shells | `sync`, `crypto` |
| `apps/kolimi-tray` | Tauri tray shell (own workspace) | `sync` |

Dependency direction is acyclic and points one way: leaf utilities →
domain → protocols → composition root. The server crate is large
because it is the only integration point; it contains route modules
(`api_*.rs`), the janitor loop, and the binary — not business logic,
which lives in the domain crates.

## What the single binary buys

- No service mesh to operate: no database server, cache, or worker
  processes. `install.sh` and systemd are enough.
- Atomic upgrades and one security boundary: authz is evaluated by one
  engine (`kolimi-vfs::authz`) for WebDAV, the JSON API, public links,
  and the UI alike.
- No serialization tax between components: the permission engine, store,
  and DB are function calls, not RPC.
- Predictable resources: ~40 MiB stripped binary, one process, one
  SQLite file, one blob tree.

## Where coupling honestly exists (and the plan)

- **`kolimi-server` route modules** are the busiest files. If they grow
  further, the split is mechanical: extract `api_*` groups into a
  `kolimi-api` crate that the binary wires up.
- **`kolimi-db` holds many tables** (users, nodes, shares, DAV, search
  state, audit, E2EE keys, scrub cursor, plugin KV is file-based).
  Single-file SQLite is the deployment story; the repositories are
  already separated by module and could move behind traits if a
  Postgres backend lands (pending work).
- **Feature flags** are currently compile-time-free: plugins, search,
  and previews are always built in. If binary size or attack surface
  becomes a concern, `--features` gates are straightforward (the
  crates are already optional in principle).

## Runtime shape

```
                 ┌──────────────────────── kolimi-server ───────────────────────┐
 client ──TLS──▶ │ axum router: /dav /api /public /app /plugins /metrics        │
                 │   auth middleware ─▶ kolimi-auth        (sessions/passkeys)  │
                 │   route handlers ─▶ kolimi-vfs::authz ─▶ permission engine   │
                 │                        │                                     │
                 │                        ├─▶ kolimi-db     (SQLite WAL)       │
                 │                        └─▶ kolimi-store  (CAS blobs)       │
                 │   background: janitor (retention, GC, BLAKE3 scrub)          │
                 │   background: search indexer (change feed → tantivy)         │
                 │   sandbox: preview worker (re-exec, landlock+seccomp+rlimits)│
                 │   sandbox: plugin host (wasmtime, fuel+memory caps)          │
                 └──────────────────────────────────────────────────────────────┘
```

Clients (`kolimi-sync`, tray, mobile FFI) speak the delta protocol over
HTTP and never need a shared library with the server.

## See also

- [ROADMAP.md](../ROADMAP.md) — milestones and the pending-work table
- [rfc/0001-storage-engine.md](rfc/0001-storage-engine.md) — why the
  storage engine is content-addressed
- [threat-model.md](threat-model.md) — the security boundaries above
