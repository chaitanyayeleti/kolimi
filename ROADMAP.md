# Kolimi Roadmap

**A pure-Rust, single-binary alternative to Nextcloud.** Fast, private, reliable — not bulky.

> *kolimi (కొలిమి)* — Telugu for **forge**.
> Rust is iron oxide; here, data is forged into something durable and yours.

---

## 1. Principles (what makes it not-Nextcloud)

- **One static binary.** No PHP-FPM, nginx, Redis, MySQL chain. Embedded SQLite (WAL) by default, optional Postgres. Target: ~50 MB binary, <100 MB idle RSS, <200 ms cold start.
- **Zero telemetry, zero phone-home.** All network egress is opt-in. File content is never logged.
- **No unsandboxed server-side code.** Previews decode in a re-executed, sandboxed worker; there is no PHP-style plugin model.
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
| Plugins | removed in 0.1.26 (was unused; wasmtime dead weight) |
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
| ↳ *core landed* | password/session auth, passkeys (WebAuthn, passwordless login, SSO-free), WebDAV (OPTIONS/GET/HEAD/PUT/DELETE/MKCOL/PROPFIND/COPY/MOVE), per-user blob store, TLS, lockout, CSRF | rclone validated (byte-identical upload/download, MOVE, DELETE); **litmus passes all suites in CI (basic/copymove/props/http/locks, 104/104)** |
| ↳ *mount-grade WebDAV landed* | byte-range + streamed `GET` (RFC 7233; `Accept-Ranges`/`206`/`Content-Range`/`If-Range`, one chunk in memory), RFC 4918 **class 2** `LOCK`/`UNLOCK` (`If` conditionals, `lockdiscovery`/`supportedlock`, lock-null resources, indirect refresh), RFC 4331 `quota-used-bytes`/`quota-available-bytes`; OPTIONS advertises `DAV: 1, 2, sync-collection` | litmus **locks 41/41** (all suites 104/104) in CI; range + lock integration tests; usable as a Windows/Office/Finder/davfs2/rclone mount and backup target |
| **M2** (6 wk) | CAS engine, resumable chunked upload, versions, trash, delta sync, SSE notify, scrub, backup/restore CLI | `kill -9` mid-upload leaves zero corruption; restore drill passes |
| ↳ *landed* | chunked CAS (FastCDC + BLAKE3 manifests), chunk-level delta upload/download API, version history (10/file + 30d), recoverable trash (30d) with restore/purge, change feed + tree snapshot + SSE pings, janitor (retention + grace-period GC + **incremental BLAKE3 scrubber** with a durable cursor and audited corruption), `backup`/`verify` CLI | crash drill passed (no partial visibility, verify clean), backup→verify round-trip passed, rclone byte-identical; scrub batch/corruption tests + janitor audit test |
| **M3** (6 wk) | Sharing (users/groups, public links with password + expiry by default), Leptos web UI MVP | share links work end-to-end, ACL tests exhaustive |
| ↳ *landed* | one permission engine (`kolimi-vfs::authz`) used by WebDAV/API/links/UI; groups + membership; user/group shares mounted at `/Shared with me` (strongest-wins, dedup names, mount-root protection, cross-owner transfer rejected); public links (generated password + 30-day expiry defaults, unlock cookies, rate-limited); Leptos WASM UI embedded in the binary (login, browser, upload/download, rename/delete, share dialog, trash, public pages) | 26 new ACL/HTTP tests incl. full link lifecycle + lockout + traversal; litmus stays 100%; UI assets smoke-tested in CI |
| **M4** (8 wk) | CalDAV/CardDAV + sync-collection REPORT, reminders | Thunderbird + iOS/macOS native clients sync cleanly |
| ↳ *landed* | CalDAV/CardDAV collections + objects in dedicated tables, RFC 6764 discovery (well-known → principal → homes), MKCALENDAR + extended MKCOL, byte-exact iCalendar/vCard storage with UID conflict detection and ETag preconditions, calendar/addressbook query + multiget reports, RFC 6578 sync-collection for calendar, address-book, **and file-tree** collections with per-collection CTags and `valid-sync-token` handling | 10 protocol-level integration tests (discovery, CRUD+VALARM byte-exactness, sync lifecycle, isolation, traversal); litmus stays 100%; live curl walkthrough |
| **M5** (6 wk) | tantivy search, sandboxed preview workers (landlock/seccomp), desktop client alpha, mobile background upload | a preview crash cannot kill the server; memory fuzz clean |
| ↳ *server side landed* | tantivy index fed crash-safely from the change feed (per-user filter, name/path/content, snippets, UI search box); previews decoded in a re-executed worker: rlimits → landlock (input file only) → seccomp allowlist (no network/exec), 10s kill-on-timeout, 4-worker cap, 20 MiB input cap, decoder memory limits; `/api/search` + `/api/preview`; `preview_image` fuzz target in CI | corrupt-image crash isolation tested end-to-end; live binary re-exec verified (64px PNG through the sandbox); 17 new tests |
| ↳ *desktop core landed* | `kolimi-sync` lib + CLI: bidirectional delta sync (pull uses manifest chunk diffs against a local cache; push chunks client-side and commits with `if_content_id`), tombstones for deletions both ways, conflicts keep the server version and preserve local edits as `.conflict-<ts>`, atomic writes, JSON state + chunk cache in `.kolimi/` | roundtrip + conflict + delta-cache tests against a live in-process server |
| ↳ *clients landed* | Tauri **desktop client shell** (`apps/kolimi-desktop`, own workspace: native window loading the server `/app/` UI, first-run setup window, tray menu with live status, sync on startup/every 5 min/on demand; file-management parity, OS keychain, and packaging follow in weeks 2-6 per decision 0002); `kolimi-ffi` UniFFI crate (Kotlin/Swift/Python bindings verified, Python exercised against a live server) exposing sync + E2EE setup with PRF secret input for platform ceremonies; background *scheduling* is platform code (WorkManager/BGTaskScheduler) documented at the FFI boundary | desktop builds on webkit2gtk; FFI e2e tests + generated-bindings smoke; CI jobs for both |
| **M6** (8 wk) | Client-side E2EE, passkey-only mode, append-only audit log | crypto review, E2EE interop tests |
| ↳ *audit log + passkey-only landed* | append-only BLAKE3 hash chain over auth, file (via the change feed), share, link, passkey, and CLI events; `audit list`/`audit verify` CLI; passkey-only accounts (password cleared via CLI once a passkey exists, password login rejected + audited) | chain tests (append/verify, tamper + deletion detection), HTTP hook tests incl. CSRF logout, CLI passkey-only flow against the real binary |
| ↳ *E2EE design* | RFC 0007: per-file keys wrapped under a passphrase/passkey-PRF/recovery-code master key, deterministic chunk AEAD that preserves CAS delta + integrity, honest metadata leakage; v1 excludes sharing and content search of encrypted files | implementation next; interop test vectors required by the M6 exit criteria |
| ↳ *E2EE core landed* | `kolimi-crypto`: Argon2id/HKDF keyring (passphrase + recovery wraps), master-key wrapping, per-file keys, deterministic chunk AEAD, committed vectors; server: keyring + wrapped file keys, `encrypted` tree flag, guards (no shares/previews/content-search for encrypted nodes); `kolimi-sync`: encrypted push/pull with `--e2ee-root`, setup CLI, passphrase/recovery/PRF unlock, key cache, conflict handling on ciphertext; `zeroize` on all key material | tests: plaintext never lands in the server data dir (marker scan), passphrase + recovery + PRF roundtrips, encrypted edit/conflict flows, independent raw-HTTP decoder interop test, crypto unit + vector tests |
| ↳ *E2EE v2: sharing landed* | X25519 identities (private wrapped under the master key, public published), ephemeral ECIES wrapping of per-file keys for named recipients (`e2ee_share_keys`), `kolimi-sync --share/--unshare`, recipient sync into `Shared with me/` (read-only), owner-store chunk reads gated by a path context, share revocation drops wrapped keys, group/link shares of encrypted subtrees refused | crypto unit tests + committed `share_wrap` vector; integration: share → decrypt pull → edit/update → tamper ignored → revoke removes local copy; independent raw-HTTP recipient decoder; mount-aware `manifest_of` fix |
| ↳ *group E2EE (pre-MLS)* | group shares of encrypted files: owner's client wraps file keys per member (`--group`); `GET /api/groups/{name}/members`; membership removal and group deletion delete the wrapped keys (CLI paths included); public links stay refused; RFC 0007 documents the pre-MLS tradeoff (no forward secrecy across membership changes) | integration: two members decrypt, link refused, CLI member removal drops keys and the removed member's local copy, remaining member unaffected; MLS (RFC 9420) remains the roadmap item, flagged in the audit package |
| ↳ *passkey UI + review* | browser WebAuthn ceremonies in the Leptos UI (passkey sign-in on the login page; a Passkeys panel to register/remove keys), so passkey-only accounts are usable end-to-end; internal crypto review (`docs/crypto-review.md`) with the invariant list, attack analysis, metadata-leakage statement, and known gaps | wasm clippy + UI asset smoke; server ceremonies already covered by the softpasskey full-flow test; external audit still open |
| **M7** | WASM plugin host + SDK, packaging (AUR, .deb, distroless Docker, systemd, Helm) | one-command install to a working share link |
| ↳ *metrics + load gates (ship-blockers)* | Prometheus `/metrics` (request counts/latency by route template, uploads, preview outcomes, login failures; no content labels) via a metrics middleware + app counters; release-mode load gates in CI: 10k changed-metadata files tree walk + delta feed < 5 s, metadata p95 within a CI budget (target 10 ms), release binary < 50 MB | metrics endpoint test; load tests print measured numbers (tree walk ~0.6 s, delta ~0.12 s, p95 ~12 ms on a laptop) and gate CI; perf job added |
| ↳ *TOTP + recovery codes (ship-blocker)* | RFC 6238 TOTP (HMAC-SHA-1, 6 digits, ±1 step, constant-time compare, consumed-step replay guard) with RFC 6238 test vectors; 10 one-time recovery codes (SHA-256 hashed at rest); `/api/totp` status/begin/enable/disable; login accepts code or recovery code; CLI `user totp-disable` escape hatch; UI: code field on login + QR/secret enrollment and one-time recovery display in the security dialog | unit vectors + full server flow test (enroll, two-step login, replay, recovery single-use, disable, CLI, audit) |
| ↳ *packaging landed* | `scripts/install.sh` (download + checksum/cosign verify, systemd, admin bootstrap; `--binary` for local/CI), AUR PKGBUILD, cargo-deb metadata + postinst, distroless Dockerfile (nonroot, volume ownership) + compose, hardened systemd unit + sysusers/tmpfiles, Helm chart (PVC/probes/ingress/nonroot); release workflow on tags: gnu + musl + aarch64 tarballs, `.deb`, Helm, sha256, cosign keyless signatures, CycloneDX SBOM, GHCR image, automated AUR; `cargo-vet` initialized (659 exemptions to burn down) | CI proves install → admin → serve → DAV upload → password-protected link → public download on every push; deb + helm lint in CI; docker build on the release runner |
| ↳ *plugin host landed, removed in 0.1.26 as unused* | `kolimi-plugins`: wasmtime component model host with the WIT ABI in `wit/plugin.wit`; capabilities are the import list (logging, plugin-private KV, clock); WASI linked with an empty context (no preopens/sockets/env); fuel budget per call (runaway loops trap), 16 MiB memory cap, broken components skipped at load; routes `/plugins/{name}/{*path}` + `GET /api/plugins`; traps audited; `examples/hello-plugin` + `spin-plugin` with committed fixtures and `scripts/build-plugins.sh` | host tests (greeting/echo/KV, fuel kill, filesystem denial, sandbox surface, reload persistence, broken-plugin skip) + server integration test over HTTP incl. audit |
| **M8** (next week) | MLS group messaging (RFC 9420) for group E2EE | a 3-member group syncs across add/remove; a removed member cannot read new epochs; vectors + audit delta |
| ↳ *plan* | Replace pre-MLS per-member X25519 wrapping (documented tradeoff: no FS/PCS) with `openmls`: Ed25519 credentials, key packages published to the server, group create/add via commit + welcome, epoch exporter derived group key wrapping file keys, re-wrap on membership change; migrate existing group shares by re-sharing under the MLS group. The audit package already flags this as the open item; land it *with* the external review, not before. | exit criteria above; `e2ee_decrypt`-style fuzz for the MLS decoders; vectors committed |

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

## 8. Pending work (tracked)

Everything below is deliberately not done yet, with a plan. Nothing here
is silently skipped.

| Item | Why it matters | Plan |
| --- | --- | --- |
| **MLS groups (RFC 9420)** | Group E2EE today is per-member X25519 wrapping: no forward secrecy or post-compromise security across membership changes | **Client + server slice landed (0.1.40–0.1.43)**: `crates/kolimi-mls` (openmls 0.9, in the workspace) covers key packages, Welcome adds, exporter/epoch rotation and the epoch-bound keyring; `/api/mls/*` stores node-scoped group state, ordered messages, exact epoch advancement and epoch-guarded keyrings. `tests/mls_e2e.rs` proves the full chain, including a writer updating the keyring. Sync/desktop now has sealed `MlsStore` state (device signer + openmls storage, UMK-sealed, 0600) and group reload tests; the share-flow wiring and web IndexedDB client remain, then the external audit. Write shares stay off until then; 89 new vet exemptions are tracked in `docs/audit/mls-delta.md` |
| **External crypto audit** | The v1+v2 crypto is internally reviewed only | Audit package ready (`docs/audit/`); freeze the surface, engage a reviewer; MLS changes land as a reviewed delta |
| **Account recovery** | ✅ **Landed**: `kolimi-server user recover <user>` sets a new password, drops live sessions, clears TOTP by default, and can remove all passkeys; audited as `user.recover` (see [docs/operations.md](docs/operations.md)) | — |
| **Web-UI E2EE** | ✅ **Landed**: unlock the keyring in the browser and decrypt files with wasm `kolimi-crypto` (sidebar → Encryption → Decrypt) | — |
| **Public links to encrypted files** | ✅ **Landed**: key-in-fragment (`#k=…&l=…`) — the browser never sends the fragment, so the server stays blind; the public page decrypts (RFC 0007 open question 3) | — |
| **Group write sharing of encrypted files** | Encrypted shares are read-only today | Per-file UMK wraps cannot represent a writer-created file safely. The MLS share keyring (RFC 0012) is the design: writers encrypt file keys under the current epoch exporter and rotate on membership change. Do it with MLS, not as a one-off |
| **Multi-device E2EE** | ✅ Landed (RFC 0008): enrollment API + `kolimi-crypto::wrap_secret_for`, `kolimi-sync --e2ee-enroll/--e2ee-approve` (device file, `0600`), and a **web-UI Devices panel** (approve/revoke + enroll this browser with a QR) | — |
| **Device-key storage hardening** | ✅ **Landed (CLI)**: `kolimi-sync`'s `keystore` feature stores the device key in the **OS keystore** (`keyring`: Secret Service / Keychain / Credential Manager) and keeps only the non-secret fields in `.kolimi/device.json`; the `0600` file is the fallback (headless, static/musl) and legacy files migrate on first use | Passkey-PRF wrap for the browser remains [RFC 0009](docs/rfc/0009-e2ee-onboarding.md); enabled via `--features kolimi-sync/keystore` (glibc releases, AUR) |
| **E2EE onboarding** | E2EE is opt-in and CLI-only: web-only users can't enable it, and nothing is encrypted by default | Draft [RFC 0009](docs/rfc/0009-e2ee-onboarding.md): first-login **browser** keyring setup (wasm), encrypt-by-default with opt-out folders, passkey unlock; crypto unchanged, passphrase still client-only |
| **E2EE client unlock** | ✅ **Landed (desktop)** — [RFC 0011](docs/rfc/0011-e2ee-client-unlock.md): "locked" is a first-class state, not an error (`SyncError::Locked` + `is_locked()`, tray *locked*, notified once/session); the desktop **Accounts & Sync** window takes the E2EE passphrase (OS keychain) to unlock/forget, and re-signing in preserves it | Keyring *creation* stays RFC 0009 (web wizard / CLI); browser/CLI unlock unchanged |
| **WebDAV / E2EE boundary** | ✅ **Option A landed**: DAV refuses `GET`/`HEAD`/`PUT`/`COPY`/`MOVE` on encrypted nodes (no ciphertext download, no plaintext overwrite). Full marker-based dir-level boundary ([RFC 0010](docs/rfc/0010-webdav-e2ee-boundary.md)) deferred | Add the encrypted-root marker + `dav_roots` allow-list if dir-level enforcement is wanted; local decrypting gateway remains out of scope |
| **Encrypted metadata (names/sizes)** | The server could read file and folder names and exact byte counts even though content was encrypted | ✅ **Landed (0.1.37–0.1.39)**: deterministic `k1_…` name encryption, hierarchical per-folder keys, bucket padding, web + sync codecs, in-place migration, and **share-name envelopes** so recipients see real names without learning sibling names |
| **Argon2 on the UI thread** | Unlocking, setup and rotation blocked the tab while the KDF ran | ✅ **Landed (0.1.38–0.1.40)**: a dedicated Web Worker wasm module derives the KEK for unlock, initial setup and passphrase rotation (in-page fallback). Measured main-thread gaps stay under 30 ms |
| **Encrypted-name search** | The server's search index only sees `k1_…` ciphertext, so encrypted names were unsearchable | ✅ **Landed (0.1.40)**: while unlocked, the web UI supplements server results with a client-side name search over the sync/shared trees. Encrypted content search remains impossible by design |
| **CalDAV/CardDAV filters** | Queries returned the whole collection and clients filtered locally | ✅ **Landed (0.1.38)**: server-side `comp-filter`, `prop-filter`, `text-match` and `time-range`, including all-day events and recurring series bounded by `UNTIL` |
| **Dependency advisories** | ✅ Documented: `paste` (unmaintained, compile-time only) and `lru` (unsound, unreachable path) accepted with reasons + revisit conditions | See [docs/known-advisories.md](docs/known-advisories.md); revisit on Leptos → `pastey` and tantivy → `lru 0.18` |
| **Admin storage management** | ✅ **Landed** (#15): `GET /api/users` `sort`/`order`/`filter`; near-quota warnings (usage API flags, `X-Kolimi-Quota-Warning` on commits, `quota.warn` audit, admin badges + user toast); per-user usage gauges (`kolimi_users_by_usage_bucket`, opt-in `kolimi_user_used_bytes`) | — |
| **Postgres backend** | Stack promises "Postgres-ready queries" | sqlx is already the layer; port migrations + connection plumbing behind the same `Db` API; decide demand-driven |
| **HTTP/3 (quinn), zero-copy uploads** | Stack mentions both; performance targets are met without them | Only if benchmarks show a gap; not on the critical path |
| **Compression + broader rate limiting** | Per-client limits cover auth, passkey, public-unlock and preview endpoints (with `KOLIMI_TRUST_PROXY` for proxies); lockout is scoped per (account, source). Compression and a wider global limiter are still missing | Add `tower-http` compression; consider a broader global request limiter |
| **Release & distribution (remainder)** | The pipeline is live (v0.1.0–v0.1.13): gnu/musl/aarch64 tarballs, `.deb`, Helm, CycloneDX SBOM + cosign, **multi-arch** GHCR image (`{vX.Y.Z, X.Y, latest}`, amd64 + arm64), and automated AUR updates | Optional: a `kolimi-bin` AUR package (prebuilt from the release tarball) |
| **cargo-vet burn-down** | 672 exemptions (0 real audits in `audits.toml`) is a placeholder, not vetting | Prioritize crypto/server crates; replace exemptions with real audits over time |
| **Desktop client (phase 1)** | ✅ **Landed**: native Tauri client (`apps/kolimi-desktop`, own workspace) — window loading the server `/app/` UI (Option A), first-run setup, tray (idle/syncing/error/paused + notifications), XDG autostart, pause/resume, OS keychain (session-keyring + warned file fallback), E2EE surfacing, and `.deb`/AppImage/AUR packaging | builds + `.deb` bundle + unit tests in CI; encrypted sync covered by server integration tests; [decision 0002](docs/decisions/0002-client-stack.md) |
| **First-party mobile apps (Android first → F-Droid)** | The desktop client is done; there is no mobile app yet | Plan: [docs/plans/clients.md](docs/plans/clients.md), issue #11; Phase 2 (weeks 7+), Android first, F-Droid |
| **AUR/deb/AppImage packaging of the desktop client** | ✅ **Landed**: `kolimi-desktop` `.deb` + AppImage + AUR `kolimi-desktop`; Desktop Release workflow on `desktop-v*` tags | — |
| **Mobile background scheduling** | FFI exposes `sync_once`; scheduling is platform code | Kotlin/Swift wrappers (WorkManager / BGTaskScheduler) in the mobile shells; FFI docs already describe the boundary |
| **Self-heal from replicas** | Scrubber detects corruption but single-node has no replica to heal from | Replication is out of v1 scope; document the single-node reality (done) and revisit with object storage |
| **Restore drills in CI** | backup/verify exist; drills are manual | Add a CI job: seed → backup → destroy → restore → verify → byte-compare |
| **Plugin system** | There is **no plugin host today**: the wasmtime component-model host, WIT ABI, `/plugins/*` routes and example plugins landed in M7 and were removed in 0.1.26 as unused dead weight. Third-party integrations use the authenticated API/DAV surfaces | Design real extension hooks and a concrete use case first; only then add a host, SDK, capability list and signature verification. Do not resurrect the old host speculatively |
| **Brand mark refresh** | Current mark = a gradient cloud tile. A bolder "forge" style was suggested (a Flaticon *furnace* icon, ref kept local only). Flaticon free icons require attribution and may **not** be used as a logo/trademark, so third-party art will not be shipped | Design an **original** forge/ember (or keep the cloud) as SVG → re-render the web favicon + sidebar/login logo, the desktop app icon, and the tray icons; no attribution/license obligations |
| **OTel traces** | ✅ **Landed**: OTLP/gRPC trace export behind the `otel` feature flag (`KOLIMI_OTEL_ENDPOINT`); request spans come from the existing `tracing`/`tower-http` instrumentation | — |

### Next (planned)

1. **Desktop client phase 1 (issue #12)** — ✅ done: shell → native sync → OS-keychain credentials → E2EE → packaging → first release (`desktop-v*`).
2. **Mobile client phase 2 (issue #11)** — Android first (F-Droid) per [docs/plans/clients.md](docs/plans/clients.md).
3. **Approve [decision 0001](docs/decisions/0001-e2ee-dav-scope.md)** — E2EE/DAV scope (A done; B/C optional).

## 9. Non-goals

Own DB engine, own TLS, chat/Talk, federation in v1, PHP-style plugin model, app-store sprawl.

## 10. Open decisions

| Decision | Proposal |
|---|---|
| DB default | SQLite-first behind a Postgres-capable abstraction |
| E2EE scope | Optional per-file E2EE in v1; MLS groups in v2 |
| Federation | Out of scope for v1 |
| License | AGPL-3.0-or-later — adopted, see [LICENSE](LICENSE) |
| Sync protocol | WebDAV compatibility + native delta protocol for first-party clients |
