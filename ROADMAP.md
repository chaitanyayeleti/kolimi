# Kolimi Roadmap

Current release: **0.5.1** (2026-11-15). This file is the forward-looking
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

## Current state (0.5.1)

| Area | Status |
| --- | --- |
| Files / WebDAV | Files, ranges, class-2 locking, trash, versions, search, previews; litmus suite in CI |
| CalDAV / CardDAV | Discovery, collections, multiget, filters, `sync-collection` |
| Delta sync | `kolimi-sync` CLI, desktop app, FFI core; chunk-level deltas, conflicts, shared mounts |
| E2EE v1/v2 | Per-file keys, encrypted names, sharing, device enrollment, browser/sync/desktop clients |
| MLS group E2EE | Node-scoped groups, membership add/remove, epoch keyring, folder + single-file write shares, serialized commits, key-package/message janitor, web/desktop/CLI |
| Auth / accounts | Passwords, passkeys, passwordless accounts, TOTP, sessions, CSRF, lockout, rate limiting; self-service account page; admin users/invites/groups/audit; forced password rotation and session labels; per-device app passwords; mandatory first-login MFA for Admin-created and invited accounts |
| Operations | Backup/verify, hash-chained audit log, Prometheus metrics, OTel traces, quotas, janitor |
| Packaging | Release tarballs (gnu/musl/aarch64), `.deb`, multi-arch GHCR, Helm, AUR, AppImage; desktop `.deb`/AppImage, Windows `.msi`/NSIS and macOS `.dmg` |

E2EE is **alpha** and MLS is **not externally audited**. That is the main
ship-blocker for calling group E2EE production-grade.

## Recently completed

- **0.5.1 — metrics depth**: expanded `/metrics` with transfer, auth,
  storage, SSE, MLS, SQLite, janitor, process, and build metrics; added the
  cached 30-second usage refresh, a read-only `KOLIMI_METRICS_TOKEN`, the
  Grafana dashboard, and browser coverage for the HTML view. See the
  [CHANGELOG](CHANGELOG.md).
- **0.5.0 — auth depth**: per-device app passwords for sync and
  WebDAV/CalDAV, mandatory first-login TOTP-or-passkey setup for Admin-created
  and invited accounts, passkey-only desktop linking, and the
  trash/device row alignment fixes. See the [CHANGELOG](CHANGELOG.md).
- **0.4.9 — UI depth and desktop status**: Phase 1–4 UI work — URL-backed
  navigation, a full Settings page, admin tables, sortable file browser,
  richer file-type icons, a split login layout, shared design tokens, and
  desktop sync status/offline/pause controls with per-folder timestamps. See
  the [CHANGELOG](CHANGELOG.md).
- **0.4.8 — account management**: self-service password/profile/session
  controls and the admin users, invites, groups, and audit pages. See the
  [completed plan](docs/plans/user-management.md) and [CHANGELOG](CHANGELOG.md).
- **0.4.7 — credential hardening**: passkey/keyring re-auth, TOTP and
  recovery hardening, and the internal red-team fixes.
- **0.4.5 — UI refinement**: reusable components, module splits, design
  tokens, and the regrouped Settings panels.

## Next

### 1. External MLS crypto audit (blocker)

The review package is [`docs/audit/mls-delta.md`](docs/audit/mls-delta.md)
and is intentionally frozen at the 0.4.3 surface even though the server is
now 0.5.1. The 89 openmls `cargo-vet` exemptions (724 total) are temporary
and are not audits. Engage an independent reviewer, land only fixes during
the review, then replace the exemptions with real audit entries. Do not
describe MLS as audited before this completes.

### 2. MLS operational hardening

- **Automatic MLS re-join**: done for any lost device once a working device
  on the same account syncs — it publishes a fresh key package and is re-added
  at a new epoch. A scoped sync only refreshes shares under its root. If no
  working member is online, or the lost device was the only owner device, the
  share still needs manual recovery or recreation.
- **Concurrent committers**: commits are serialized server-side, clients
  stage commits locally, and a losing committer discards its pending state
  and replays the winning epoch. A commit and its Welcome are appended
  atomically.
- **MLS device roster caps and revoke**: done — 16 active devices per
  account over a 180-day window, 8 live packages per device, janitor
  pruning, `409` on over-limit uploads, `--mls-devices` /
  `--mls-revoke-device`, a web Settings device list, owner-side recipient
  removal, and per-group revocations so automatic re-add cannot undo a
  revoke. A remote wipe is still impossible by design.
- **MLS message retention tuning**: per-device epoch reports now drive
  pruning (7-day grace, 30-day report freshness); review the thresholds
  with the external auditor.
- **Deployment validation**: upgrade from 0.4.7 (and older 0.3.x data) to
  0.5.1 with real data, a restore drill in CI, and a post-upgrade `verify`
  run.

### 3. Clients

- **Android / F-Droid is parked** until desktop signing and mobile
  resourcing are settled: [docs/plans/android.md](docs/plans/android.md) and
  [docs/plans/clients.md](docs/plans/clients.md). The FFI core exists;
  background scheduling and the Compose/SwiftUI shells remain.
- Desktop Windows/macOS signing/notarization and native autostart glue
  (bundles and OS keychain storage are in place).
- **Browser passkey-PRF key wrap** (issue #16): the CLI already uses the OS
  keystore with a `0600` fallback; the web client still keeps enrollment
  and unlocked state only for the tab session. Needs a WebAuthn PRF
  ceremony, a browser E2E test and review.

### 4. Documentation and release hygiene

- Keep [clients.md](docs/clients.md) current for app passwords,
  WebDAV/CalDAV URLs, desktop pairing, and CLI sync; it is the canonical
  client setup page.
- Keep [how-to.md](docs/how-to.md) as the task-first index; add a recipe
  when a feature needs several steps across pages.
- Keep `scripts/check-docs.sh` in CI. It now checks that release-facing
  docs match the workspace version as well as links and stale claims.
- Keep the version-bump checklist in
  [docs/plans/releases.md](docs/plans/releases.md) in sync with the
  workflows.
- Review install commands and audit status during every release so they
  cannot drift again.

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
