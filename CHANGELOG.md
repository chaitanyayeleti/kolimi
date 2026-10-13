# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Desktop client (phase 1)**: promoted the tray into `apps/kolimi-desktop`
  (Tauri v2, own workspace). A native window loads the server's `/app/` UI
  (Option A), with a **first-run setup window** that writes
  `~/.config/kolimi/desktop.json`, a tray menu (Open / Open folder / Sync now
  / Setup / Quit), and background sync on startup, every 5 minutes, and on
  demand. Decision 0002 approved (Option A, Linux-first, in-repo).
- **Desktop native file integration**: OS **drag-and-drop uploads** work in
  the window (Tauri's file-drop handler is disabled so the web UI's own drop
  logic runs), and **downloads** from the web UI are saved to `~/Downloads`
  with the result shown in the tray (instead of failing silently). Rename,
  move, delete, versions/trash, search, and previews come from the loaded web
  UI, giving feature parity in the desktop shell.
- **Desktop sync polish**: the tray shows **idle/syncing/error/paused**
  states, **desktop notifications** fire on sync failure and on conflicts,
  **XDG autostart** is a "Start on login" toggle (setup checkbox + tray menu),
  and sync can be **paused/resumed** from the tray. Wayland-native via
  GTK/webkit2gtk (`GDK_BACKEND` auto-selects Wayland or X11).

## [0.1.11]

### Added
- **Upload tray**: a floating panel with per-file **progress bars** and
  **retry** on failure (uploads now use `XMLHttpRequest` so progress is
  reported).
- **Multi-select + bulk actions**: ctrl/cmd/shift-click to select, then
  **download**, **move to…**, or **trash** the selection.
- **E2EE recovery-code unlock**: the Encryption dialog can now unlock the
  keyring with the **recovery code** ("Use recovery code"), and the login
  field accepts a **TOTP recovery code** (relabelled "two-factor or recovery
  code"). Added a **Recovery** section to `docs/operations.md` clarifying the
  three secrets (login password, TOTP recovery codes, E2EE recovery code).

## [0.1.10]

### Added
- **Web-UI polish**: a **storage ring** in the sidebar (used/quota donut,
  `GET /api/me/usage`), **right-click context menus**, an image **lightbox**,
  **loading skeletons**, **drag-to-move** onto folders and breadcrumbs, a
  **share-link QR**, and **undo** toasts for trash deletions.

## [0.1.9]

### Added
- **Web-UI multi-device management**: the Encryption dialog now has a
  **Devices** panel — approve pending enrollments, revoke devices, and
  enroll *this browser* as a new device (generating a device key and showing
  an enrollment QR) that unlocks once approved elsewhere (RFC 0008).

## [0.1.8]

### Fixed
- AUR build: set `AWS_LC_SYS_NO_JITTER_ENTROPY=1` in the PKGBUILD so
  `aws-lc-sys` (via rustls) compiles under Arch's hardened `CFLAGS` — its
  `jitterentropy` RNG requires `-O0`, which `makepkg`'s `-O2` overrode.
- **Code-review hardening.** CSRF is now enforced for every cookie-auth
  unsafe method (WebDAV, plugins), not just `/api/*`; passkey lockout is
  keyed on (user, IP); the preview worker fails closed if its sandbox did
  not apply; WebDAV escapes client-supplied property namespaces; the rate
  limiter and lockout recover from a poisoned mutex and the rate-limit map
  is hard-capped; the credential cache is invalidated on account changes.
- **Data-loss fixes.** Garbage collection aborts if a referenced manifest
  cannot be read (previously it could delete a live file's chunks); sync
  rejects a malformed tree response instead of wiping local files; a
  manifest's `size` must match its chunk lengths; quota is checked after
  dedup; moving a node onto its own path is a no-op; CalDAV sync keeps the
  latest change per object; `ingest_stream` cleans up on failure; sync
  conflict copies are never re-uploaded; the device-unlock master key is
  zeroized. Numerous DB errors that were masked as empty/false now surface.

### Changed
- Performance/cleanup: one shared content-id decoder, `HashSet` mount
  dedup (was O(n²)), a per-owner shared-tree path cache, a reusable plugin
  linker (built once, not per call), and a stack-allocated chunk nonce
  (no per-chunk allocation).

## [0.1.7]

### Added
- **Admin storage management**: `GET /api/users` now supports
  `sort`/`order`/`filter` (`used_bytes`, `over_quota`, `disabled`,
  `admin`); near-quota warnings (usage API flags, an
  `X-Kolimi-Quota-Warning` header on commits, a `quota.warn` audit event,
  and admin badges + a user toast); and per-user usage metrics
  (`kolimi_users_by_usage_bucket`, plus opt-in `kolimi_user_used_bytes` via
  `KOLIMI_METRICS_PER_USER=1`).
- **OpenTelemetry traces** (optional): build with `--features otel` and set
  `KOLIMI_OTEL_ENDPOINT` to export OTLP/gRPC spans (request spans come from
  the existing `tracing` instrumentation).
- **Metrics dashboard**: `/metrics` now renders a read-only HTML dashboard
  for browsers (metric families as cards, auto-refresh) while scrapers still
  get the Prometheus text format; `?format=text` forces text.

## [0.1.6]

### Fixed
- WebDAV no longer serves end-to-end encrypted files as ciphertext or lets a
  plaintext `PUT` overwrite one: `GET`/`HEAD`/`PUT`/`COPY`/`MOVE` on an
  encrypted node return `403` (RFC 0010, option A — plaintext-only DAV).

### Changed
- Documented accepted dependency advisories (`paste` unmaintained, `lru`
  unsound) with reasons and revisit conditions (`docs/known-advisories.md`);
  `cargo audit` and `cargo deny` now list them explicitly.

## [0.1.5]

### Added
- **Web-UI E2EE**: unlock the keyring (sidebar → Encryption) and decrypt
  encrypted files in the browser (wasm `kolimi-crypto`); the passphrase is
  never sent to the server.
- **Public links to encrypted files**: the file key and chunk lengths ride in
  the URL fragment (`#k=…&l=…`), so the server stays blind; the public page
  decrypts and downloads the plaintext.
- Multi-arch container image: `linux/amd64` + `linux/arm64`, built on native
  runners and merged into one manifest on GHCR.
- **Account recovery**: `kolimi-server user recover <user>` sets a new
  password, drops the account's sessions, and by default clears TOTP
  (optionally removes passkeys) for a user who lost every credential;
  recorded as `user.recover` in the audit log.
- **Multi-device E2EE (RFC 0008)**: enroll a new device without re-typing
  the passphrase — `kolimi-sync --e2ee-enroll <name>` on the new device and
  `kolimi-sync --e2ee-approve <id>` on an unlocked one. The server relays an
  opaque master key wrapped to the new device's X25519 key
  (`kolimi-crypto::wrap_secret_for`); the device stores `.kolimi/device.json`
  (0600) and unlocks from it. Device list/removal via `/api/e2ee/devices`.

### Fixed
- Storage usage now tracks **referenced** bytes and is refreshed when trash
  is emptied, so the admin panel and quota drop immediately after a file is
  permanently deleted instead of waiting for the grace-period GC and the
  hourly janitor.

## [0.1.4]

### Changed
- Web UI polish: multi-select and drag-and-drop upload, dialog refinements
  (Share, Passkeys, Admin), relative modified times, auto-dismissing toasts,
  a theme toggle on the login screen, and an admin-row overlap fix.

## [0.1.3]

### Added
- Web UI **redesign**: sidebar with a mobile drawer, list/grid file views,
  inline SVG icons, toast notifications, a persisted light/dark toggle, and
  a mobile-first responsive layout.
- WebDAV **mount-grade** features: byte-range requests (`Range`/`206`/
  `Accept-Ranges`) and streamed downloads (one chunk in memory, not the
  whole file), RFC 4918 **class 2** `LOCK`/`UNLOCK` with `If` conditionals
  and `lockdiscovery`/`supportedlock`, and RFC 4331
  `quota-used-bytes`/`quota-available-bytes`. This makes `/dav/` usable as
  a read/write **network drive** (Windows Explorer *Map network drive*, MS
  Office, macOS Finder, GNOME Files, davfs2/gvfs, `rclone mount`) and as a
  **backup target** (rclone/restic/duplicity), including from mobile
  clients (GrapheneOS file managers, DAVx5 for CalDAV/CardDAV).

## [0.1.2]

### Added
- Web UI **admin panel**: per-user storage quota editor, admin role
  changes, enable/disable, delete, and a usage recheck (backed by the
  admin quota/usage API).

## [0.1.1]

### Added
- Release artifacts for **`x86_64-unknown-linux-musl`** (static) and
  **`aarch64-unknown-linux-gnu`** targets, plus automated **AUR** updates.

### Fixed
- SBOM and release-publish steps in the release workflow.

First tagged release. A pure-Rust, single-binary Nextcloud alternative.

### Highlights
- Single static binary (or distroless container) — no PHP/nginx/Redis/MySQL.
- WebDAV (litmus 100%) + CalDAV/CardDAV with RFC 6578 sync-collection.
- Content-addressed storage: FastCDC chunks, BLAKE3, versions, trash,
  delta sync, dedup, scrubber.
- Delta sync client (`kolimi-sync`), Tauri tray, UniFFI bindings.
- End-to-end encryption (RFC 0007): per-file keys, passphrase/recovery/PRF
  unlock, encrypted sharing with users and groups (pre-MLS).
- Passkeys, TOTP + recovery codes, passwordless accounts.
- Append-only hash-chained audit log; Prometheus metrics; sandboxed
  previews (landlock/seccomp); sandboxed WASM plugin host.
- Per-user storage quotas with admin API/CLI (usage counters + reconciliation).
- Security review fixes: constant-time login, per-client rate limiting and
  per-source lockout, per-user quota, SSE caps, HSTS, admin-only metrics.

### Known limitations
- Group E2EE is per-member X25519 wrapping (no forward secrecy); MLS
  (RFC 9420) is planned.
- External crypto audit not yet performed.
