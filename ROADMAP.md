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
| ↳ *core landed* | password/session auth, passkeys (WebAuthn, passwordless login, SSO-free), WebDAV (OPTIONS/GET/HEAD/PUT/DELETE/MKCOL/PROPFIND/COPY/MOVE), per-user blob store, TLS, lockout, CSRF, 115 tests | rclone validated (byte-identical upload/download, MOVE, DELETE); litmus run pending |
| **M2** (6 wk) | CAS engine, resumable chunked upload, versions, trash, delta sync, SSE notify, scrub, backup/restore CLI | `kill -9` mid-upload leaves zero corruption; restore drill passes |
| ↳ *landed* | chunked CAS (FastCDC + BLAKE3 manifests), chunk-level delta upload/download API, version history (10/file + 30d), recoverable trash (30d) with restore/purge, change feed + tree snapshot + SSE pings, janitor (retention + grace-period GC + **incremental BLAKE3 scrubber** with a durable cursor and audited corruption), `backup`/`verify` CLI | crash drill passed (no partial visibility, verify clean), backup→verify round-trip passed, rclone byte-identical; scrub batch/corruption tests + janitor audit test |
| **M3** (6 wk) | Sharing (users/groups, public links with password + expiry by default), Leptos web UI MVP | share links work end-to-end, ACL tests exhaustive |
| ↳ *landed* | one permission engine (`kolimi-vfs::authz`) used by WebDAV/API/links/UI; groups + membership; user/group shares mounted at `/Shared with me` (strongest-wins, dedup names, mount-root protection, cross-owner transfer rejected); public links (generated password + 30-day expiry defaults, unlock cookies, rate-limited); Leptos WASM UI embedded in the binary (login, browser, upload/download, rename/delete, share dialog, trash, public pages) | 26 new ACL/HTTP tests incl. full link lifecycle + lockout + traversal; litmus stays 100%; UI assets smoke-tested in CI |
| **M4** (8 wk) | CalDAV/CardDAV + sync-collection REPORT, reminders | Thunderbird + iOS/macOS native clients sync cleanly |
| ↳ *landed* | CalDAV/CardDAV collections + objects in dedicated tables, RFC 6764 discovery (well-known → principal → homes), MKCALENDAR + extended MKCOL, byte-exact iCalendar/vCard storage with UID conflict detection and ETag preconditions, calendar/addressbook query + multiget reports, RFC 6578 sync-collection for calendar, address-book, **and file-tree** collections with per-collection CTags and `valid-sync-token` handling | 10 protocol-level integration tests (discovery, CRUD+VALARM byte-exactness, sync lifecycle, isolation, traversal); litmus stays 100%; live curl walkthrough |
| **M5** (6 wk) | tantivy search, sandboxed preview workers (landlock/seccomp), desktop client alpha, mobile background upload | a preview crash cannot kill the server; memory fuzz clean |
| ↳ *server side landed* | tantivy index fed crash-safely from the change feed (per-user filter, name/path/content, snippets, UI search box); previews decoded in a re-executed worker: rlimits → landlock (input file only) → seccomp allowlist (no network/exec), 10s kill-on-timeout, 4-worker cap, 20 MiB input cap, decoder memory limits; `/api/search` + `/api/preview`; `preview_image` fuzz target in CI | corrupt-image crash isolation tested end-to-end; live binary re-exec verified (64px PNG through the sandbox); 17 new tests |
| ↳ *desktop core landed* | `kolimi-sync` lib + CLI: bidirectional delta sync (pull uses manifest chunk diffs against a local cache; push chunks client-side and commits with `if_content_id`), tombstones for deletions both ways, conflicts keep the server version and preserve local edits as `.conflict-<ts>`, atomic writes, JSON state + chunk cache in `.kolimi/` | roundtrip + conflict + delta-cache tests against a live in-process server |
| ↳ *clients landed* | Tauri tray shell (`apps/kolimi-tray`, own workspace: tray menu with live status, sync on startup/every 5 min/on demand, config file); `kolimi-ffi` UniFFI crate (Kotlin/Swift/Python bindings verified, Python exercised against a live server) exposing sync + E2EE setup with PRF secret input for platform ceremonies; background *scheduling* is platform code (WorkManager/BGTaskScheduler) documented at the FFI boundary | tray builds on webkit2gtk and ran live (synced a file); FFI e2e tests + generated-bindings smoke; CI jobs for both |
| **M6** (8 wk) | Client-side E2EE, passkey-only mode, append-only audit log | crypto review, E2EE interop tests |
| ↳ *audit log + passkey-only landed* | append-only BLAKE3 hash chain over auth, file (via the change feed), share, link, passkey, and CLI events; `audit list`/`audit verify` CLI; passkey-only accounts (password cleared via CLI once a passkey exists, password login rejected + audited) | chain tests (append/verify, tamper + deletion detection), HTTP hook tests incl. CSRF logout, CLI passkey-only flow against the real binary |
| ↳ *E2EE design* | RFC 0007: per-file keys wrapped under a passphrase/passkey-PRF/recovery-code master key, deterministic chunk AEAD that preserves CAS delta + integrity, honest metadata leakage; v1 excludes sharing and content search of encrypted files | implementation next; interop test vectors required by the M6 exit criteria |
| ↳ *E2EE core landed* | `kolimi-crypto`: Argon2id/HKDF keyring (passphrase + recovery wraps), master-key wrapping, per-file keys, deterministic chunk AEAD, committed vectors; server: keyring + wrapped file keys, `encrypted` tree flag, guards (no shares/previews/content-search for encrypted nodes); `kolimi-sync`: encrypted push/pull with `--e2ee-root`, setup CLI, passphrase/recovery/PRF unlock, key cache, conflict handling on ciphertext; `zeroize` on all key material | tests: plaintext never lands in the server data dir (marker scan), passphrase + recovery + PRF roundtrips, encrypted edit/conflict flows, independent raw-HTTP decoder interop test, crypto unit + vector tests |
| ↳ *passkey UI + review* | browser WebAuthn ceremonies in the Leptos UI (passkey sign-in on the login page; a Passkeys panel to register/remove keys), so passkey-only accounts are usable end-to-end; internal crypto review (`docs/crypto-review.md`) with the invariant list, attack analysis, metadata-leakage statement, and known gaps | wasm clippy + UI asset smoke; server ceremonies already covered by the softpasskey full-flow test; external audit still open |
| **M7** | WASM plugin host + SDK, packaging (AUR, .deb, distroless Docker, systemd, Helm) | one-command install to a working share link |
| ↳ *metrics + load gates (ship-blockers)* | Prometheus `/metrics` (request counts/latency by route template, uploads, preview outcomes, login failures; no content labels) via a metrics middleware + app counters; release-mode load gates in CI: 10k changed-metadata files tree walk + delta feed < 5 s, metadata p95 within a CI budget (target 10 ms), release binary < 50 MB | metrics endpoint test; load tests print measured numbers (tree walk ~0.6 s, delta ~0.12 s, p95 ~12 ms on a laptop) and gate CI; perf job added |
| ↳ *TOTP + recovery codes (ship-blocker)* | RFC 6238 TOTP (HMAC-SHA-1, 6 digits, ±1 step, constant-time compare, consumed-step replay guard) with RFC 6238 test vectors; 10 one-time recovery codes (SHA-256 hashed at rest); `/api/totp` status/begin/enable/disable; login accepts code or recovery code; CLI `user totp-disable` escape hatch; UI: code field on login + QR/secret enrollment and one-time recovery display in the security dialog | unit vectors + full server flow test (enroll, two-step login, replay, recovery single-use, disable, CLI, audit) |
| ↳ *packaging landed* | `scripts/install.sh` (download + checksum/cosign verify, systemd, admin bootstrap; `--binary` for local/CI), AUR PKGBUILD, cargo-deb metadata + postinst, distroless Dockerfile (nonroot, volume ownership) + compose, hardened systemd unit + sysusers/tmpfiles, Helm chart (PVC/probes/ingress/nonroot); release workflow on tags: gnu + musl tarballs, sha256, cosign keyless signatures, CycloneDX SBOM; `cargo-vet` initialized (exemptions to burn down) | CI proves install → admin → serve → DAV upload → password-protected link → public download on every push; deb + helm lint in CI; docker build on the release runner |
| ↳ *plugin host pending* | wasmtime component model, capability-scoped WIT, example plugin | next |

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
