# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.28] - 2026-10-26

### Fixed
- Sign out verifies the session is actually dead before leaving the login
  screen — a failed logout no longer looks like success until the next
  reload logs you back in.
- A fresh account can no longer land on the unlock form: the encryption
  dialog shows an explicit checking state, and a retryable error if the
  server can't be reached, instead of assuming a keyring exists.
- Folder encryption detection only treats a folder as encrypted when every
  file it holds is encrypted (mixed folders stay plaintext).

## [0.1.27] - 2026-10-26

## [0.1.27] - 2026-10-26

### Fixed
- **Uploads into encrypted folders actually encrypt.** `GET
  /api/files/info` now reports a folder as encrypted when every file it
  holds is encrypted (directory nodes never carry keys themselves), so the
  web UI's client-side-encrypt path is reachable; mixed and empty folders
  stay plaintext. Without this the new encrypted-upload flow could never
  trigger.
- Bulk download decrypts encrypted selections instead of fetching raw
  ciphertext URLs that 403.
- Integration coverage for `/api/files/move` + `/api/files/info` on
  encrypted files (move preserves keys, 409 on clash, 404 on missing).

## [0.1.26] - 2026-10-26

## [0.1.26] - 2026-10-26

### Changed
- **Phase 2: encrypted files work in the web UI.** Downloads decrypt
  (grid, list, search, context menu, lightbox); rename/move/bulk-move go
  through a new metadata-only `POST /api/files/move` that works on
  ciphertext; uploads into encrypted folders are encrypted client-side
  (chunk + commit + wrap key, like the sync client) while plaintext
  uploads stream from disk with no WASM-side copy; image and text previews
  decrypt to the lightbox; files shared with you decrypt via the share-key
  flow; sharing an encrypted file wraps its key per recipient (recursive
  for directories); public links carry the `#k=` fragment from a
  session-local map; shared mounts report their `encrypted` state.
  Desktop: account E2EE files propagate to every pair, passwordless
  devices report unlocked, per-account state lives under `~/.config`
  (no more `/tmp` fallback), and the recovery copy is no longer wiped.

### Fixed
- Shared-folder permission gating: Upload/New folder hidden in read-only
  shares; Rename/Delete allowed with write permission; single `Entry`
  `can_edit` gate in grid, list, and context menu.
- Versions UI: per-file version history with one-click restore; text
  previews in the lightbox; images and text files open the lightbox from
  grid and list views.
- Browser device enrollment survives reloads (pending id + secret in
  sessionStorage); toasts (undo, quota) auto-dismiss; passkey removal and
  share revocation surface errors; storage-usage refreshes after
  upload/trash/restore; selection clears on navigation.

### Changed
- **Phase 3 (simplification, I):** the recovery code is a 24-word phrase
  (BIP39 wordlist, checksum-verified; legacy hex still parses); the
  unlock persists for the tab session via sessionStorage; approving a
  device is one click (code comparison moved behind "Verify code");
  desktop auto-approves pending enrollments while unlocked (opt-out,
  with a "wasn't you?" notice).
- **Removed the WebAssembly plugin host** (`kolimi-plugins`, examples,
  `/plugins/*` + `/api/plugins` routes, build script): unused dead
  weight — an entire wasmtime tree for a KV toy with no file/user/event
  hooks. This also drops the wasmtime/cranelift advisory treadmill;
  `cargo vet` is down to 635 exemptions.

## [0.1.25] - 2026-10-23

## [0.1.25] - 2026-10-23

### Fixed
- **Phase 1 hardening.** Basic auth now rejects TOTP-enrolled accounts,
  lockout/cache keys are case-insensitive, `/api/totp/*` is rate-limited and
  `disable` consumes steps with per-account lockout. CSRF covers WebDAV
  mutating methods. WebDAV locks are per-owner with a cap. Group-share revoke
  is owner-only (members leave instead of revoking for all) with scoped key
  cleanup. Trash/restore are recursive, copies skip trashed nodes and preserve
  file keys. Sync fixes rooted E2EE paths, create-create protection,
  conflict pre-checks, manifest verification, downgrade refusal, symlink
  guards, key-cache retry, and a sync lockfile. Quota enforced on logical
  manifest size, chunk races use random temp files + fsync + mtime touch,
  public downloads stream, search snippets are UTF-8 safe, parent ETags bump,
  and DAV compat fixes (well-known, sync-token, href slashes, If-Match,
  vCard, lock lifecycle).


## [0.1.24] - 2026-10-17

### Changed
- **The web UI explains failures instead of dumping them.** A missing folder
  (404) falls back to your files rather than a bare *"Could not list folder"*;
  a denied folder (403), a server error, and a lost connection each say what
  happened and are retryable. The sign-in screen now states that the **account
  password** and the **encryption passphrase** are different things, shows
  plain-language errors (*incorrect username or password*, *too many attempts —
  wait a minute*), and tells you when a session expired instead of silently
  showing the login form again.

## [0.1.23] - 2026-10-17

### Added
- **E2EE can now be set up from the UI** (first slice of RFC 0009), in both the
  web app and the desktop's *Accounts & Sync*: when an account has no keyring,
  the Encryption section offers *Set up encryption* (choose a passphrase),
  uploads the keyring, publishes your identity, and shows the recovery code
  once.
- **Desktop: encrypted folders are configurable from the UI.** The add/edit
  folder forms take a comma-separated list of relative folders to encrypt, so
  E2EE no longer requires hand-editing `desktop.json`.
- **Desktop: E2EE status** (`none` / `locked` / `unlocked`) drives the
  Encryption section, and *Devices & keys* says to set up encryption first when
  there is none.

### Changed
- Desktop *Unlock* now **verifies** the passphrase against the keyring before
  storing it, so "unlocked" is never a lie.
- `kolimi-sync`: `setup_keyring`, `keyring_exists`, and `verify_unlock` helpers.

### Notes
- Encrypt-by-default, opt-out folders, and the WebDAV carve-out (the rest of
  RFC 0009) remain deferred per decision 0001.

## [0.1.22] - 2026-10-17

### Fixed
- **Desktop: the encryption passphrase box is now always shown**, not only for
  accounts with encrypted sync folders. Approving a device needs the master
  key, so an account with no encrypted folders had no way to unlock and every
  approve failed with a "locked" error. The *Devices & keys* section now also
  prompts you to unlock first, and the locked error for approve reads
  *"approving a device needs your encryption passphrase — unlock encryption
  first"*.

## [0.1.21] - 2026-10-17

### Added
- **Enrollment approval code in the desktop and web UIs.** The web's *Add this
  browser as a device* flow now shows the key-committing code (also encoded in
  the QR), and *Approve* requires the operator to type the code shown on the
  new device, refusing a mismatch. The desktop's **Accounts & Sync** gains a
  *Devices & keys* section: enroll this machine (code + fingerprint, then wait
  for approval), approve pending enrollments (code required), and review the
  **pinned recipient keys**.

### Fixed
- **Web: a keyring integrity failure no longer reads as "Wrong passphrase"** —
  a tampered or spliced keyring is reported as such.
- **Web: keyring anti-rollback.** The browser remembers the highest keyring
  epoch it accepted (in `localStorage`) and refuses a replayed or downgraded
  keyring, closing the gap noted for 0.1.19.
- Desktop: a pre-existing `clippy::collapsible_if` in `delete_secrets`.

## [0.1.20] - 2026-10-17

### Fixed
- **The desktop AUR package failed to build.** `apps/kolimi-desktop` is a
  separate Cargo workspace with its own `Cargo.lock`, which was not updated for
  0.1.19 (still 0.1.18 + rustls 0.23.45). The desktop PKGBUILD builds with
  `cargo build --release --locked`, so `makepkg` aborted with *"cannot update
  the lock file … because `--locked` was passed"*. The lockfile is synced, and
  the CI desktop job and the desktop release now build with `--locked` (and
  check the lockfile), so a stale lockfile cannot reach a release again.

## [0.1.19] - 2026-10-17

### Added
- **Bearer-token auth for mobile clients.** `SyncConfig` gains an optional
  `token`; the HTTP client sends `Authorization: Bearer` when it is set (else
  HTTP Basic), so a client can log in once (password + TOTP) and sync with the
  session token without retaining the password. The FFI exposes
  `FfiSyncConfig.token` and a dedicated `Locked` error class.
- **E2EE hardening: three server-trust gaps closed.**
  - **Device enrollment approval code** (RFC 0008). The new device and the
    approving device each derive a short code that commits to the device's
    public key and the enrollment id
    (`BLAKE3("kolimi-enroll-code-v1" ‖ device_public_key ‖ id)`).
    `--e2ee-enroll` prints it; `--e2ee-approve` shows the server's key
    fingerprint and requires the operator to confirm the code, refusing a
    mismatch. Previously the approving device wrapped the master key for
    whatever public key the server returned, so a malicious server could
    substitute its own key and receive the user master key.
  - **Recipient-key pinning (trust on first use).** `share_path` pins each
    recipient's published X25519 key in `.kolimi/known_keys.json` and refuses
    to wrap file keys for a key that changed, printing both fingerprints
    (`--e2ee-fingerprints` lists the pins). This stops a server substituting a
    recipient key to receive shared file keys.
  - **Keyring integrity tag and anti-rollback.** Keyrings now carry a monotonic
    `epoch` and an integrity tag keyed by a UMK-derived key, so the server
    cannot splice wraps across keyrings or forge a higher epoch; a client that
    has seen a tagged keyring refuses an untagged one and refuses an `epoch`
    lower than the highest it has accepted, so a rotated-away passphrase or
    recovery code cannot be resurrected.

### Changed
- **Device enrollment is two-phase** in `kolimi-sync`
  (`start_enrollment` / `finish_enrollment`) so the code can be shown before
  approval; `approve_device` now takes the confirmed code. The FFI mirrors it
  (`start_enrollment`, `finish_enrollment`, `pending_enrollment`,
  `approve_device`), and the CLI gains `--e2ee-code` and
  `--e2ee-fingerprints`.

### Security
- **Dependency advisories cleared.** Bumped `rustls` 0.23.45 → 0.23.46 and the
  `wasmtime` family 49.0.2 → 49.0.3, clearing 17 RUSTSEC advisories published
  since 0.1.18 (four in rustls; thirteen in `wasmtime`/`wasmtime-wasi`, which
  matter here because plugins run untrusted code inside wasmtime). This raises
  the minimum supported Rust version to **1.96** (wasmtime 49.0.3's
  requirement); `cargo-vet` exemptions are refreshed.

## [0.1.18] - 2026-10-14

### Added
- **Delta push**: `POST /api/chunks/exist` reports which chunk hashes the
  server already holds, and `kolimi-sync` now consults it before uploading —
  a one-chunk edit no longer re-uploads the whole file (#17).
- **CLI device key in the OS keystore**: `kolimi-sync`'s `keystore` feature
  stores the device key via `keyring` (Secret Service / Keychain / Credential
  Manager), keeping only non-secret fields in `.kolimi/device.json`. The
  `0600` file remains the fallback (headless, static/musl) and legacy files
  migrate on first use (#16).

### Changed
- **Received-share mounts are cached** and invalidated by a database
  `shares_epoch`, so `/Shared with me` resolution no longer re-reads every
  share on each call (#25).
- **Plugins link a sockets-free WASI surface**: the linker now omits
  `wasi:sockets/*` entirely, so a component that imports it cannot
  instantiate — not merely rejected at load (#25).

## [0.1.17] - 2026-10-14

### Fixed
- **Sessions survive the CSRF hardening (regression in 0.1.16).** After
  upgrading a server, session cookies issued before the upgrade had no bound
  CSRF hash, and the session-bound check rejected them — so every
  cookie-authenticated mutation (upload, delete, trash purge) returned **403**,
  which the UI surfaced as *"Delete failed"*. A session without a bound hash
  now accepts its double-submit token and is bound to it on first use; a wrong
  or missing token is still rejected.

## [0.1.16] - 2026-10-14

Correctness/security hardening across the whole workspace, from an
independent review (#17–#25).

### Security
- **CSRF is bound to the session**: the session stores a hash of its CSRF
  token (migration 0016) and the check compares against it, not just the
  double-submit cookie.
- **Passkey sign counter fails closed**: if the counter cannot be persisted,
  login is refused (no session with a stale counter).
- **Passkey challenge store** evicts the single oldest entry instead of
  wiping every in-flight challenge.
- **E2EE**: reject low-order/non-contributory X25519 recipient keys (RFC 7748);
  validate published identity keys; cap Argon2 `m_cost`/work so a tampered
  keyring can't force a huge allocation; reject an empty passphrase in the FFI.
- **Plugins**: refuse components that import `wasi:sockets` at load, keeping
  the network surface unused.
- **Crypto**: decrypted plaintext and KDF buffers are zeroized; the
  deterministic (fixed-nonce) wrap helpers are `#[doc(hidden)]`.
- **Scripts**: `install.sh` passes the admin password via stdin (never in the
  process list); `litmus.sh` verifies pinned sha256 for its downloaded sources.

### Fixed
- **Sync**: reject server-controlled `..`/absolute paths before writing outside
  the root; never follow symlinks when collecting files; add connect/request
  timeouts; verify each chunk against the manifest; never re-push local-only
  `.conflict-*` copies (nested paths included); skip a single bad file instead
  of aborting the whole pass; roll back a just-created node/share when their key
  upload fails; redact secrets in `Debug`.
- **DB**: `record_change` writes the change row and its audit entry in one
  transaction; atomic first-admin election and device registration (unique
  key + upsert); transactions for `clear_totp`/`delete_group`/`remove_group_member`;
  added missing indexes (migration 0015). `users.credentials_version`
  (migration 0017) invalidates the credential cache after an out-of-process
  password reset.
- **Server**: share of a deleted node returns `410 Gone`; listing users returns
  `has_more` and rejects cursors on non-id sorts; preview scratch files are
  removed on panic; `is_encrypted` fails safe to `true`; `write_chunk` checks
  quota before writing; a scrub audit failure no longer aborts the pass.
- **UI**: a 401 (and a periodic check) returns to the login view; a request
  sequence guards the loading state; the upload tray stores per-item signals
  (O(1) rows, pruned on completion, `File` handles released); toast timers only
  clear their own message; bulk trash/move surface failures.
- **Desktop**: settings accesses recover from mutex poisoning; the settings and
  autostart files are written atomically.

### Added
- **`wasm` UI tests** (`wasm-bindgen-test`) for the pure helpers, run in CI.

## [0.1.15] - 2026-10-13

### Added
- **In-app "Sync folders" button**: the desktop window now has a *Sync folders*
  button that opens the **Accounts & Sync** window, so synced folders are
  reachable without the tray. When the server UI's toolbar is present it is
  placed there (aligned with the other controls); otherwise it falls back to a
  floating pill at the bottom-center. It works by intercepting a sentinel
  navigation, so the remote server origin is **not** granted any Tauri IPC.
- **Inline editing of synced folders**: each directory in **Accounts & Sync**
  can be edited in place (change the local path and/or remote subfolder)
  instead of removing and re-adding it.

### Changed
- **UI polish / alignment**: the desktop tray menu is grouped with separators;
  the **Accounts & Sync** window aligns its edit rows and the encryption
  section; and the web UI moves **toasts to the top-right** so they no longer
  collide with the bottom-right upload tray. Duplicate modal/CSS rules removed.
- **Encryption is "locked", not "error"** (RFC 0011). A configured encrypted
  folder with no usable passphrase/recovery/device key — or an account with no
  keyring yet — is now a distinct **locked** state: the tray shows *locked*
  (not red), the status line says to unlock, and a notification fires **once
  per session** instead of every poll. `kolimi_sync::SyncError` gains a
  `Locked` variant (`is_locked()`); genuine policy/data E2EE errors remain
  `E2ee`. The desktop **Accounts & Sync** window now also takes the E2EE
  passphrase (stored in the OS keychain) to **unlock or forget** it, and
  re-signing in no longer drops a stored passphrase.

## [0.1.14] - 2026-10-13

### Fixed
- **Desktop single instance**: launching the client again (e.g. re-launching
  after an update) now focuses the running instance instead of starting a
  second process and a **second tray icon**. The second process exits.

## [0.1.13] - 2026-10-13

### Fixed
- **Web-UI upload progress** now moves. The upload tray's keyed list reused the
  row DOM, so the bar (and percentage) stayed frozen at 0% even though the file
  uploaded; progress/status are now read reactively.
- **Faster remote→local sync**: the desktop poll interval is now **60s** (was
  5 min) and **opening the window triggers a sync**, so changes made on the web
  land on disk promptly.

## [0.1.12] - 2026-10-13

### Added
- **Brand logo**: a gradient cloud mark, used as the web-UI favicon and
  sidebar/login logo, the desktop app icon (`.deb`/AppImage/AUR), and the tray
  icon (idle / syncing / error).
- **Desktop closes to tray**: closing the window hides it (the tray and the
  background sync loop keep running; use the tray's *Quit* to exit). Autostart
  launches the client with `--hidden`, so login starts it silently in the tray.
- **Desktop Accounts & Sync**: the desktop client now supports **multiple
  accounts** and **multiple synced directories per account**, managed from an
  in-app **Accounts & Sync** window (tray → *Accounts & Sync…*): sign in/out,
  add/remove accounts, and add/remove synced folders (local → remote
  subfolder). Config moves to a `version: 2` shape (`accounts[].pairs[]`),
  migrating the old single-account file automatically (and moving the keychain
  entry to `username@server`).
- **Sync to a remote subfolder**: `kolimi-sync` gains `--remote /Docs` (and
  `sync_once_rooted`), so a local folder mirrors a chosen server folder instead
  of always the account root — the mechanism behind multi-directory sync.
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
- **Desktop OS keychain**: the account password and E2EE passphrase are stored
  in the **system keychain** (Secret Service via zbus on Linux; Credential
  Manager / Keychain on Windows/macOS), keyed by server URL. If no keychain is
  running they fall back to the Linux **kernel session keyring** (`keyctl`,
  session-only, never written to disk); only when neither is available do they
  fall back to the `0600` config file. The plaintext `desktop.json` no longer
  holds the password when a keychain or session keyring is present.
- **Desktop E2EE surfacing**: the tray and setup window show the encryption
  state ("Encryption: N root(s), unlocked/locked"), and the app **notifies**
  when secrets fall back to the config file so the weaker storage is never
  silent. Encrypted-root sync is verified end-to-end (server integration
  tests).
- **Desktop packaging + release**: `kolimi-desktop` bundles to **`.deb`** and
  **AppImage** (Tauri bundler) with icons and a `.desktop` entry, plus an AUR
  package (`kolimi-desktop`). A new **Desktop Release** workflow builds both
  bundles and updates the AUR on `desktop-v*` tags. CI now also runs the
  desktop unit tests and a `.deb` packaging check. First release:
  **`desktop-v0.1.11`**.

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
