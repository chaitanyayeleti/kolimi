# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Multi-arch container image: `linux/amd64` + `linux/arm64`, built on native
  runners and merged into one manifest on GHCR.
- **Account recovery**: `kolimi-server user recover <user>` sets a new
  password, drops the account's sessions, and by default clears TOTP
  (optionally removes passkeys) for a user who lost every credential;
  recorded as `user.recover` in the audit log.
- **Multi-device E2EE (RFC 0008), server + crypto**: a device-enrollment
  handshake (`/api/e2ee/enrollments`, `/api/e2ee/devices`) lets an unlocked
  device wrap the master key to a new device's X25519 key
  (`kolimi-crypto::wrap_secret_for`); the sync-client commands and UI follow.

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
