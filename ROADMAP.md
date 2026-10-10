# Kolimi Roadmap

**A pure-Rust, single-binary alternative to Nextcloud.** Fast, private, reliable — not bulky.

> *kolimi (కొలిమి)* — Telugu for **forge**.
> Rust is iron oxide; here, data is forged into something durable and yours.

---

## 1. Principles (what makes it not-Nextcloud)

- **One static binary.** No PHP-FPM, nginx, Redis, MySQL chain. Embedded SQLite (WAL) by default, optional Postgres. Target: ~50 MB binary, <100 MB idle RSS, <200 ms cold start.
- **Zero telemetry, zero phone-home.** All network egress is opt-in. File content is never logged.
- **No unsandboxed server-side code.** Third-party apps run in a WASM sandbox (wasmtime) with capability-scoped access, not as PHP plugins with full filesystem access.
- **Protocol-first.** Standard WebDAV/CalDAV/CardDAV from day one, so existing clients (rclone, davfs, Thunderbird, iOS, macOS) work immediately. First-party clients get a faster native delta-sync protocol.

## 2. Stack

| Concern | Choice |
|---|---|
| HTTP | axum 0.8 + hyper + tower (rate limit, compression) |
| Runtime / TLS | tokio, rustls only (no OpenSSL), HTTP/2 + HTTP/3 via quinn |
| Database | sqlx — SQLite WAL first, Postgres-ready queries |
| Blob storage | Content-addressed store: FastCDC chunks + BLAKE3, local FS or S3 via opendal |
| WebDAV | `dav-server` crate as fallback; own handler on the CAS engine for ETags + delta |
| Auth | argon2id, `webauthn-rs` passkeys, TOTP, OIDC via `openidconnect` |
| Calendars / Contacts | `icalendar`, `vcard` + own CalDAV/CardDAV REPORT layers |
| Search | tantivy |
| Frontend | Leptos (WASM) + Tailwind — no Node in the critical path |
| Plugins | wasmtime component model, capability-scoped |
| Desktop / Mobile | Rust sync core + Tauri (tray) / `uniffi` bindings |
| Push | UnifiedPush / ntfy (no Google FCM dependency) |
| P2P / LAN (later) | iroh (QUIC, hole punching) for LAN-fast sync |

## 3. Architecture decisions (lock before coding)

1. **Storage = mini-restic for files.** Every file is a manifest of chunk hashes. This gives dedup, delta sync, cheap versions, atomic commits, and background scrubbing/self-heal for free.
2. **One permission engine.** Shares, public links, DAV, and API all evaluate ACLs through a single server-side component. Divergent permission checks are Nextcloud's #1 bug class.
3. **Change feed + ETag/If-None-Match everywhere,** with SSE notifications. Never re-download what didn't change.
4. **E2EE:** per-file key wrapping in v1 (chunks encrypted client-side; server sees ciphertext only; the server-side dedup tradeoff is documented). Group-native E2EE via MLS (`openmls`, RFC 9420) in v2.
5. **Federation out of scope for v1.** ActivityPub-based public sharing only if there is real demand later.
6. **Protocol compatibility over invention.** WebDAV correctness (litmus suite) before any custom protocol.

## 4. Milestones

| # | Scope | Exit criteria |
|---|---|---|
| **M0** (2 wk) | Repo workspace, CI (cargo-deny, cargo-audit, fuzz targets), threat model, storage + sync RFCs | `cargo test` + fuzz green, specs reviewed |
| **M1** (6 wk) | Single binary: users, passkeys + sessions, WebDAV core (GET/PUT/PROPFIND/MOVE/COPY/DELETE), TLS | rclone + davfs + `litmus` test suite pass |
| **M2** (6 wk) | CAS engine, resumable chunked upload, versions, trash, delta sync, SSE notify, scrub, backup/restore CLI | `kill -9` mid-upload leaves zero corruption; restore drill passes |
| **M3** (6 wk) | Sharing (users/groups, public links with password + expiry by default), Leptos web UI MVP | share links work end-to-end, ACL tests exhaustive |
| **M4** (8 wk) | CalDAV/CardDAV + sync-collection REPORT, reminders | Thunderbird + iOS/macOS native clients sync cleanly |
| **M5** (6 wk) | tantivy search, sandboxed preview workers (landlock/seccomp), desktop client alpha, mobile background upload | a preview crash cannot kill the server; memory fuzz clean |
| **M6** (8 wk) | Client-side E2EE, passkey-only mode, append-only audit log | crypto review, E2EE interop tests |
| **M7** | WASM plugin host + SDK, packaging (AUR, .deb, distroless Docker, systemd, Helm) | one-command install to a working share link |

Every milestone gates on: fuzz targets run, benchmark baseline updated, docs written.

## 5. Security ship-blockers

- rustls, TLS 1.3 only, HSTS; strict CSP, SameSite=Strict cookies, CSRF double-submit
- argon2id parameters reviewed; per-device sessions with remote revoke; brute-force lockout
- Passkeys (WebAuthn) as the default, not an add-on; TOTP + recovery codes as fallback
- Uploads and previews processed in a separate process with landlock + seccomp and rlimits
- Signed releases, reproducible builds, SBOM, `cargo-vet`
- Secrets zeroized (`zeroize`/`secrecy`); no plaintext keys on disk
- Append-only audit log (who touched what — never file content)
- Public links: password + expiry on by default, rate-limited, revocable

## 6. Reliability ship-blockers

- Crash-consistency tests: fuzz kill points during upload/commit/delete, assert invariants
- Background scrubber verifying BLAKE3, self-heal from replicas
- Online backup (`VACUUM INTO` + manifest export), automated restore drills in CI
- Prometheus metrics + OpenTelemetry traces, health endpoints
- Load test suite (metadata p95, 10k small files, 100 GB single file)

## 7. Performance targets (regression-gated)

| Metric | Target |
|---|---|
| Idle RSS | < 100 MB (Nextcloud stack: ~500 MB+) |
| API metadata p95 | < 10 ms |
| Sync 10k changed-metadata files | < 5 s (delta only) |
| Upload throughput | line-rate, zero-copy (sendfile / io_uring) |
| Binary size | < 50 MB static |

## 8. Non-goals

Own DB engine, own TLS, chat/Talk, federation in v1, PHP-style plugin model, app-store sprawl.

## 9. Open decisions

| Decision | Proposal |
|---|---|
| DB default | SQLite-first behind a Postgres-capable abstraction |
| E2EE scope | Optional per-file E2EE in v1; MLS groups in v2 |
| Federation | Out of scope for v1 |
| License | AGPL-3.0-or-later — adopted, see [LICENSE](LICENSE) |
| Sync protocol | WebDAV compatibility + native delta protocol for first-party clients |
