# Kolimi Roadmap

Current release: **0.3.0** (2026-10-24). This file is the forward-looking
backlog and the honest list of limitations. Shipped history lives in
[CHANGELOG.md](CHANGELOG.md); design details live in [docs/rfc/](docs/rfc/).

## Principles

1. **One static binary.** SQLite, the blob store and the WASM UI are
   embedded; no PHP-FPM, nginx, Redis or MySQL chain.
2. **Protocol-first.** WebDAV, CalDAV/CardDAV and the delta sync protocol
   are the integration surface, not a private-only API.
3. **The server stays blind to E2EE content.** Keys and group state live on
   clients; the server stores ciphertext and opaque protocol messages.
4. **Boring operations.** One process, one data directory, online backup,
   integrity verification, audit log, metrics.
5. **No speculative platform work.** A plugin host or extra backend is
   added only with a concrete use case.

## Current state (0.3.0)

| Area | Status |
| --- | --- |
| Files / WebDAV | Files, ranges, class-2 locking, trash, versions, search, previews; litmus suite in CI |
| CalDAV / CardDAV | Discovery, collections, multiget, filters, `sync-collection` |
| Delta sync | `kolimi-sync` CLI, desktop app, FFI core; chunk-level deltas, conflicts, shared mounts |
| E2EE v1/v2 | Per-file keys, encrypted names, sharing, device enrollment, browser/sync/desktop clients |
| MLS group E2EE | Node-scoped groups, membership add/remove, epoch keyring, write shares, key-package pool, web/desktop/CLI |
| Auth | Passwords, passkeys, passwordless accounts, TOTP, sessions, CSRF, lockout, rate limiting |
| Operations | Backup/verify, hash-chained audit log, Prometheus metrics, OTel traces, quotas, janitor |
| Packaging | Release tarballs (gnu/musl/aarch64), `.deb`, multi-arch GHCR, Helm, AUR, AppImage, desktop `.deb` |

E2EE is **alpha** and MLS is **not externally audited**. That is the main
ship-blocker for calling group E2EE production-grade.

## Next

### 1. External MLS crypto audit (blocker)

The review package is [`docs/audit/mls-delta.md`](docs/audit/mls-delta.md).
The 89 openmls `cargo-vet` exemptions (724 total) are temporary and are
not audits. Freeze the 0.3.0 surface, engage an independent reviewer, land
only fixes during the review, then replace the exemptions with real audit
entries. Do not describe MLS as audited before this completes.

### 2. MLS operational hardening

- **State-loss recovery** beyond “re-add a new device”: document and test
  a recovery flow for a lost IndexedDB/`.kolimi` state, with clear limits.
- **Janitor** for consumed/expired key packages and old MLS messages.
- **Browser E2E** for web rename, delete, revoke and the migration UI
  (read/write/reload is covered today).
- **Single-file write shares**: MLS single-file shares are read-only;
  decide whether to support writers or document the limit permanently.
- **Concurrent committers**: two clients committing at the same epoch can
  fork a group. Add detection/repair or serialize commits server-side.
- **Deployment validation**: upgrade from 0.2.x to 0.3.0 with real data,
  restore drill in CI, and a post-upgrade `verify` run.

### 3. Clients

- **Android / F-Droid** first, then iOS: [docs/plans/android.md](docs/plans/android.md)
  and [docs/plans/clients.md](docs/plans/clients.md). The FFI core exists;
  background scheduling and the Compose/SwiftUI shells remain.
- Desktop Windows/macOS packaging, signing and platform secret-store glue.
- Per-device app passwords for WebDAV/CalDAV clients (today a device uses
  the account password or a passkey session).

### 4. Documentation and release hygiene

- Keep `scripts/check-docs.sh` in CI; update the RFC status table and
  [docs/README.md](docs/README.md) on every release.
- Keep the version-bump checklist in
  [docs/plans/releases.md](docs/plans/releases.md) in sync with the
  workflows.
- Add a docs review to the release checklist so install commands and
  audit status cannot drift again.

## Deferred / non-goals

- **Plugin host.** The old wasmtime/WIT host was removed in 0.1.26; do not
  resurrect it without a concrete hook design and a signature story.
- **Postgres backend.** SQLite is the deployment story. The repository API
  is isolated, but a second backend is demand-driven.
- **HTTP/3 and zero-copy uploads.** Current performance gates pass without
  them.
- **Replication / self-healing.** Single-node is the supported topology;
  object storage is a future design, not a promise.
- **Compression and a global rate limiter.** Per-endpoint limits cover the
  sensitive paths; broader limits are an operational option.
- **Encrypted-content search.** The server cannot index plaintext it never
  sees; encrypted names use a client-side supplement.
- **Deniability.** Not engineered or claimed.

## How work is chosen

- Security and data-loss issues first, then protocol correctness, then
  client reach.
- A change that touches E2EE/MLS needs a test that fails without it and an
  update to the relevant RFC/audit package.
- A change that changes operations needs a docs update and a
  `CHANGELOG.md` entry.
- Performance regressions are gated in CI (10k-file delta, binary size);
  do not trade them away for unmeasured features.
