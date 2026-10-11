# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
