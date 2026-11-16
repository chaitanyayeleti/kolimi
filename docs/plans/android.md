# Android client (phase 2) — plan and design

Status: **plan refreshed 2026-11-16; implementation not started** · Tracks
issue **#11**
Builds on: [clients.md](clients.md), [decision 0002](../decisions/0002-client-stack.md),
RFC 0006 (sync client), RFC 0007 (E2EE), RFC 0008 (device enrollment)

The desktop client (phase 1) is shipped. This is the plan for a first-party
Android app for **F-Droid**, built as a Kotlin/Compose shell over the existing
Rust core (`kolimi-sync` + `kolimi-crypto`) through `kolimi-ffi`. No Android
project exists in this checkout yet; this refresh records what is already
ready in the core and the first implementation slice.

## 0. Current state (2026-11-16)

The Rust core is further along than the original plan assumed:

| Piece | State |
| --- | --- |
| `kolimi-ffi` surface | `sync_once`, `e2ee_setup`, `start_enrollment`, `finish_enrollment`, `pending_enrollment`, `approve_device`, `forget_device` |
| Auth | `FfiSyncConfig` already carries a bearer `token`; HTTP Basic also accepts **app passwords** |
| E2EE options | `e2ee_passphrase`, `e2ee_recovery_code`, `e2ee_prf_secret`, `encrypted_roots`, `mls` |
| Sync selection | `remote` can restrict a root to a server subfolder |
| Errors | `FfiError::Locked` distinguishes “needs unlock” from a hard failure |
| Bindings | CI generates Kotlin, Swift, and Python bindings from a Linux `.so` |
| Android project | None yet; no NDK cross-compile or Gradle build in CI |

Two corrections to the original plan:

1. **Background sync should use an app password, not the session token.**
   The server accepts session tokens as Bearer, but sessions expire; app
   passwords are revocable, long-lived, and work over HTTP Basic even when
   TOTP is enabled. The Android login flow should create a named app password
   after the first password+TOTP login, store it in the Android Keystore, and
   use it for sync and API calls. The session cookie/token can be discarded.
2. **Encrypted content needs an explicit UI path.** The sync engine can
   encrypt/decrypt a synced folder, but the Kotlin browse/download/upload
   path cannot decrypt by itself. v1 should treat encrypted roots as
   **sync-managed**: browse the local mirror, open/share files from there,
   and let `kolimi-sync` handle encryption. Direct streaming of encrypted
   files through the UI is a v1.5 FFI addition, not a v1 promise.

The remaining core work is small: optionally add `list_remote_tree` /
`remote_changed_since` for a richer sync-status screen, and decide whether a
direct `is_locked` helper is worth exposing. Enrollment, token auth, PRF, MLS,
and the `Locked` error are already present.

## 1. Goal and non-goals

**Goal:** an F-Droid app that can log in, browse, upload/download, and run
**background delta sync** of a local folder against a Kolimi server, including
E2EE, with no Google Play Services and no trackers.

**Non-goals (v1):** iOS, passkeys (WebAuthn on Android usually needs GMS),
CalDAV/CardDAV UI, sharing-UI beyond read-only "Shared with me",
arbitrary SAF folders, a full offline metadata cache, and completing
first-login MFA setup or forced password rotation inside the app. Accounts in
those states should finish setup in the web UI; the app can also accept a
manually created app password.

## 2. Architecture — one core, a thin shell

```
┌───────────────────────────── Android app (Kotlin, Compose) ─────────────────────────────┐
│  UI (Compose)      Settings / Login / Browser / Transfers / Sync status / E2EE unlock     │
│  Data layer        Ktor client → JSON API (browse, preview, upload UI, trash, shares)      │
│  Platform glue     Android Keystore (app password + E2EE key) · WorkManager (scheduling)   │
└───────────────▲──────────────────────────────────────────────────────────────────────────┘
                │ UniFFI (JNA) — libkolimi_ffi.so
┌───────────────┴───────────────────────────── Rust core (shared, unchanged) ───────────────┐
│  kolimi-sync   delta sync, conflicts, device file, E2EE unlock                             │
│  kolimi-crypto E2EE keyring, per-file keys, X25519 identities                              │
│  kolimi-ffi    the small UniFFI surface (remaining helpers — see §5)                       │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

Two HTTP paths by design:

- **Rust core** owns *sync* (chunked delta transfer, E2EE, conflict handling)
  and *crypto*. This is the part that must be shared and is already written.
- **Kotlin** owns the *interactive* UI calls (browse a folder, fetch a
  thumbnail, rename, trash). These are plain JSON endpoints; doing them in
  Kotlin keeps the UI native, paged, cacheable, and offline-tolerant, and
  keeps the FFI surface small.

## 3. Repo and module layout

```
apps/kolimi-android/            # own Gradle build (not a Cargo workspace member)
  settings.gradle.kts
  app/
    src/main/java/xyz/yeleti/kolimi/…      # Compose UI, Ktor client, Keystore, WorkManager
    src/main/jniLibs/{arm64-v8a,x86_64}/   # libkolimi_ffi.so (produced by cargo-ndk)
    build.gradle.kts
  rust/                                    # build glue: cargo-ndk invocation + bindings
  fastlane/metadata/android/en-US/         # F-Droid listing
crates/kolimi-ffi/                         # the shared UniFFI core (already exists)
```

The Rust side stays in the root Cargo workspace (`crates/kolimi-ffi`); the
Android app is a Gradle project that *consumes* the built `.so` and the
generated Kotlin bindings. CI already generates Kotlin/Swift/Python bindings
today (`.github/workflows/ci.yml`, `ffi (bindings)`).

## 4. Feature set for v1

1. **Setup** — server URL, password + TOTP login, or paste an existing app
   password; TLS trust. Accounts that still need first-login MFA setup or a
   forced password change finish that in the web UI.
2. **Browse** — list a folder, breadcrumbs, sort, file sizes, thumbnails for
   images, download to device, upload, mkdir, rename, move, delete.
3. **Trash / versions** — list trash, restore/purge; version list + restore.
4. **Search** — server-side search box.
5. **Shared with me** — read-only mounts (same `/api/browse` tree).
6. **Sync** — pick a local folder (app-private for v1), periodic background
   sync via `WorkManager`, manual "sync now", conflict + failure notifications.
7. **E2EE** — unlock with passphrase / recovery code (or enroll this device,
   RFC 0008) and sync encrypted roots; plaintext never reaches the server.

## 5. FFI surface

The original plan’s additions are now mostly implemented:

| Addition | Status |
| --- | --- |
| `SyncAuth` (password or bearer token) | **Done** — `FfiSyncConfig.token`; Basic still accepts app passwords |
| Device enrollment (`start`/`finish`/`pending`/`approve`) | **Done** |
| `Locked` error | **Done** — `FfiError::Locked`; no separate `is_locked()` helper yet |
| `list_remote_tree()` / `remote_changed_since()` | **Not done** — optional, for a richer sync-status screen |
| Direct encrypted read/write for the UI | **Not done** — v1 uses the synced local mirror instead (§9) |

Everything else (browse, preview, upload UI, trash, shares) stays in Kotlin's
Ktor client. **Rule:** the FFI grows only where Rust already owns the logic;
we do not re-expose the whole JSON API through UniFFI.

## 6. Auth and credential storage

The original plan recommended reusing the session token. Use a **named app
password** instead:

1. Log in in Kotlin with `POST /api/session` (password + TOTP). The fresh
   session is allowed to create an app password without another re-auth.
2. Create `POST /api/me/app-passwords` with a label such as
   `Android — Pixel 8`.
3. Store the returned app password in the **Android Keystore**
   (hardware-backed AES-GCM), never in SharedPreferences plaintext, logs, or
   auto-backup.
4. Discard the session cookie. Use HTTP Basic (`username` + app password) for
   sync and the Kotlin API client.
5. On sign-out or “remove this device,” call
   `DELETE /api/me/app-passwords/current` (or revoke by id) before deleting
   local state.

If the account cannot create an app password yet (first-login MFA setup,
forced password rotation, or passkey-only), show a clear explanation and
offer to paste an app password created in the web UI. Do not try to bypass the
server’s restricted session surface.

Why not the session token: sessions expire, while background sync needs a
long-lived credential; app passwords are revocable and survive TOTP. The
`token` field remains useful if a caller already has a session and wants to
avoid Basic, but it is not the background-sync credential.

**Open security item:** app passwords currently grant full account access.
Until scoped app passwords exist (see [future.md](future.md)), the Android app
must disclose that and rely on revocation. When scopes land, request only
`sync` and the read/write surfaces the app actually uses.

## 7. Local storage

`kolimi-sync` operates on a real filesystem path (`std::fs`), so:

- **v1:** an **app-private directory** (`context.filesDir/kolimi` or
  `getExternalFilesDir`). No runtime permissions, no SAF complexity, and it
  works with the existing sync engine unchanged.
- **Later:** SAF / document-provider integration would need stream-based sync
  (not `std::fs`), so it is explicitly out of v1. A "share to Kolimi" import
  and an export action are the cheap middle ground.

## 8. Background sync

- `WorkManager` (`androidx.work`) periodic work, 15-minute minimum interval,
  plus a unique expedited "sync now" job from the UI. No GMS/Firebase —
  `WorkManager` uses the platform `JobScheduler`.
- The worker builds the FFI client from the Keystore **app password** and calls
  `sync_once`; overlapping runs are prevented with a unique work name and an
  in-process mutex. A long first sync should run as a foreground worker with a
  notification, not silently in the background.
- Constraints: `NetworkType.CONNECTED`; retry with backoff on transient
  failures; post a notification on conflicts/failures (a later
  UnifiedPush/ntfy integration can replace polling).
- Android 13+ needs `POST_NOTIFICATIONS` for conflict/failure notifications;
  request it when sync is enabled, not at first launch.

## 9. E2EE on mobile

- Unlock with passphrase or recovery code (both already in the FFI), or
  **enroll this device** so it can unlock without the passphrase (RFC 0008;
  an already-unlocked device approves it).
- The device key is stored via the same `keystore` path as the CLI where a
  platform keystore exists — on Android the app owns this, so the app stores
  the device file in its private dir and the key in the Android Keystore.
- Encrypted roots are **sync-managed in v1**: the file browser shows the
  local mirror, “Open” and “Share” use Android viewers via `FileProvider`,
  and uploads into the mirror are encrypted by `kolimi-sync`. The Kotlin HTTP
  path is never asked to decrypt ciphertext.
- Direct encrypted streaming (tap a remote encrypted file without syncing it
  first) is a v1.5 FFI addition: `download_decrypted` / `upload_encrypted`
  with streaming, or an equivalent local-cache API. Do not fake it by
  downloading ciphertext into Kotlin.
- If the user does not store the passphrase/device key, background sync can
  report `Locked` after a reboot; the UI must prompt for unlock rather than
  retrying forever.
- Encrypted thumbnails come from the local mirror, never from
  `/api/preview` (the server cannot decrypt them).

## 10. Build pipeline and CI

- **Rust:** `cargo-ndk` builds `kolimi-ffi` (`cdylib`) for `arm64-v8a` and
  `x86_64` into `app/src/main/jniLibs/<abi>/libkolimi_ffi.so`.
- **Bindings:** CI already generates Kotlin/Swift/Python bindings from a Linux
  `.so` (`ffi (bindings)` job). Android needs the same generation from each
  Android `.so`, either committed or produced during the Gradle build.
- **TLS crypto provider:** the current dependency tree pulls **`aws-lc-sys`**
  through reqwest’s `rustls` feature. That may cross-compile with the NDK and
  cmake, but it is unproven and adds build-server risk. **W0 must choose:**
  either prove `aws-lc-sys` builds cleanly for both ABIs, or switch the sync
  client to `rustls-no-provider` with the `ring` provider installed at
  startup. Do not assume the `ring` path works until a device APK syncs over
  TLS.
- **CI job `android`** (new): install JDK, Android SDK/NDK and Rust Android
  targets; run `cargo-ndk`; generate Kotlin bindings; run `./gradlew
  assembleDebug`, unit tests, and lint. Keep it off the release critical path
  until W6; add an emulator smoke test once the app can log in.

## 11. F-Droid readiness (build for these from W0)

- **FOSS only** — the repo is AGPL-3.0; no GMS, Firebase, analytics, or
  trackers. `WorkManager`/`androidx` are fine.
- **Offline/from-source build** — commit `Cargo.lock` (already done) and
  **vendor** the Rust dependencies (`cargo vendor` + a `[source]` replacement
  in `.cargo/config.toml`) so the build server needs no network.
- **Toolchain** — pin the Rust version (`rustup-init -y --default-toolchain
  <pinned>`); F-Droid allows Rust/Rustup and Maven Central as prebuilt
  sources. Use `--remap-path-prefix` for reproducible paths.
- **JNA** — UniFFI's Kotlin bindings need `net.java.dev.jna:jna:5.x@aar`
  (from Maven Central, allowlisted) which bundles `jnidispatch.so`. Confirm
  it passes F-Droid's scanner; fallback is a hand-written JNI shim over a
  small C ABI (avoiding JNA entirely).
- **Metadata** — app id, versionCode/Name, `fastlane` listing, any
  `AntiFeatures`; F-Droid signs the APK.

## 12. Week-by-week plan

| Week | Deliverable | Exit criteria |
| --- | --- | --- |
| **W0 — feasibility (de-risk)** | `apps/kolimi-android` layout; CI cross-compiles the core for `arm64`/`x86_64` and links a trivial JNI call; decide TLS provider; prove JNA loads the `.so` | A debug APK on a device calls a Rust `hello` over UniFFI; CI green |
| **W1 — skeleton + login** | Compose shell, Settings (server URL), password + TOTP login, token in Keystore, list the root folder | Logs in and shows the tree |
| **W2 — files** | Browse/navigate, download/upload, mkdir/rename/move/delete, thumbnails, search | File management parity with the essentials |
| **W3 — sync** | `kolimi-sync` in-app over an app-private folder, manual + `WorkManager` periodic sync, conflict handling, status screen | Round-trip + background sync; conflicts preserved |
| **W4 — trash/versions + shares** | Trash list/restore/purge, version list/restore, "Shared with me" | Read-only shared mounts browse correctly |
| **W5 — E2EE** | Unlock (passphrase/recovery) + device enrollment, encrypted roots, Keystore persistence | Encrypted sync end-to-end; plaintext never on the server |
| **W6 — F-Droid prep + submit** | Material 3 polish, notifications, `fastlane` metadata, vendor crates, draft `fdroiddata` recipe, local VM build | Recipe builds cleanly offline; MR submitted |

### First implementation slice

Do not start the full app until W0 answers these:

1. Does `libkolimi_ffi.so` build for `arm64-v8a` and `x86_64`, load through
   UniFFI/JNA, and complete a real TLS sync against a test server?
2. Does the chosen TLS provider (`aws-lc-sys` or `ring`) build reproducibly
   for Android without hand-installed tools?
3. Is app-private storage enough for v1, with `FileProvider` for “open/share”
   and an export action?

If W0 passes, W1 is a thin vertical slice: **login with password + TOTP →
create app password → store it in Keystore → browse the root folder**. No sync,
no E2EE, no file editing. That slice proves the auth and HTTP path before the
sync engine is wired in.

## 13. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| **`aws-lc-sys` won't cross-compile cleanly for Android** | W0 spike: prove the NDK/cmake build, or switch sync to `rustls-no-provider` + the `ring` provider and install it at startup. |
| **JNA AAR / prebuilt `jnidispatch.so` flagged by F-Droid** | Maven Central is allowlisted; verify in W0. Fallback: hand-written JNI over a C ABI (drop UniFFI's Kotlin/JNA layer). |
| **UniFFI + Rust + NDK on F-Droid's offline builder** (highest risk) | Vendor crates, pin the toolchain, reproduce the build in a local VM before submitting (W6). |
| **Encrypted files have no direct UI path in v1** | Treat encrypted roots as sync-managed; open/share from the local mirror. Direct streaming is a v1.5 FFI feature, not a hidden fallback. |
| **SAF vs `std::fs`** | v1 uses an app-private folder (no SAF); SAF needs stream-based sync — out of scope. |
| **Passkeys need GMS** | Password + TOTP for v1 (as planned). |
| **Battery/Doze** | `WorkManager` periodic + a foreground "sync now"; no polling. |
| **App-private storage is wiped on uninstall** | Document it; offer export / a later SAF folder. |
| **Android auto-backup leaks credentials or device keys** | `android:allowBackup="false"`, or exclude the Keystore-wrapped files and sync state from backup rules. |
| **Self-signed or private CA servers fail TLS** | v1 requires a publicly trusted certificate; document the constraint. A per-server certificate pin or user CA is a later, explicit trust feature — never a silent “ignore certificate” toggle. |

## 14. v1 acceptance and test plan

The first release is acceptable when:

- A fresh install logs in with password + TOTP, creates a named app password,
  and browses the account root.
- Plaintext upload, download, mkdir, rename, move, delete, trash/restore, and
  search work through the Kotlin API client.
- A selected remote subfolder syncs to the app-private mirror on demand and
  via `WorkManager`; conflicts keep the local copy and surface a notification.
- An encrypted root syncs end-to-end, opens from the local mirror, and the
  server stores only ciphertext; a locked keyring shows an unlock prompt, not
  an endless retry.
- Revoking the app password stops sync on the next run; sign-out removes
  local credentials.
- No token, app password, passphrase, device key, or plaintext file name
  appears in logs or Android auto-backup.
- The F-Droid recipe builds from a clean, network-isolated environment.

Test layers:

| Layer | What it covers |
| --- | --- |
| Rust `kolimi-ffi` tests | Enrollment, token/app-password sync, E2EE setup, `Locked`, MLS |
| Kotlin JVM tests | API client, Keystore abstraction, sync scheduling, error mapping |
| Compose UI tests | Login, browse, transfer, sync status, unlock prompt |
| Emulator instrumentation | Keystore, `WorkManager`, notification permission, background sync |
| Real device | Doze/battery, large-file transfer, TLS, file open/share |
| F-Droid VM | Offline build, vendored crates, JNA packaging, reproducible APK |

## 15. Decisions

Confirmed 2026-10-14:

1. **App id** — `xyz.yeleti.kolimi`.
2. **minSdk / targetSdk** — minSdk **24**, targetSdk latest stable.
3. **ABIs** — `arm64-v8a` + `x86_64` (`armeabi-v7a` only if ever needed).
4. **UI HTTP** — native Kotlin/Ktor; the FFI stays focused on sync + crypto.
5. **Local folder** — app-private directory; SAF deferred.
6. **Passkeys in v1** — no (needs GMS).

Revised 2026-11-16:

7. **Auth model** — log in with password + TOTP, create a named **app
   password**, store it in the Android Keystore, and use HTTP Basic for sync
   and API calls. Do not use the expiring session token for background sync.
8. **Encrypted roots** — sync-managed in v1. Browse/open/share from the local
   mirror; direct encrypted streaming is v1.5.
9. **Distribution** — F-Droid first. A Play Store listing is a separate
   decision and would not change the F-Droid constraints.
10. **TLS** — publicly trusted certificate in v1; custom CA/pinning is a
    later explicit trust feature, never a silent bypass.
