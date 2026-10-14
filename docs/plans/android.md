# Android client (phase 2) — plan and design

Status: **approved** · Date: 2026-10-14 · Tracks issue **#11**
Builds on: [clients.md](clients.md), [decision 0002](../decisions/0002-client-stack.md),
RFC 0006 (sync client), RFC 0007 (E2EE), RFC 0008 (device enrollment)

The desktop client (phase 1) is shipped. This is the plan for a first-party
Android app released on **F-Droid**, built as a Kotlin/Compose shell over the
existing Rust core (`kolimi-sync` + `kolimi-crypto`) through `kolimi-ffi`.

## 1. Goal and non-goals

**Goal:** an F-Droid app that can log in, browse, upload/download, and run
**background delta sync** of a local folder against a Kolimi server, including
E2EE, with no Google Play Services and no trackers.

**Non-goals (v1):** iOS, passkeys (WebAuthn on Android usually needs GMS),
CalDAV/CardDAV UI, plugin UI, sharing-UI beyond read-only "Shared with me",
arbitrary SAF folders, and a full offline metadata cache.

## 2. Architecture — one core, a thin shell

```
┌───────────────────────────── Android app (Kotlin, Compose) ─────────────────────────────┐
│  UI (Compose)      Settings / Login / Browser / Transfers / Sync status / E2EE unlock     │
│  Data layer        Ktor client → JSON API (browse, preview, upload UI, trash, shares)      │
│  Platform glue     Android Keystore (token + E2EE passphrase) · WorkManager (scheduling)   │
└───────────────▲──────────────────────────────────────────────────────────────────────────┘
                │ UniFFI (JNA) — libkolimi_ffi.so
┌───────────────┴───────────────────────────── Rust core (shared, unchanged) ───────────────┐
│  kolimi-sync   delta sync, conflicts, device file, E2EE unlock                             │
│  kolimi-crypto E2EE keyring, per-file keys, X25519 identities                              │
│  kolimi-ffi    the small UniFFI surface (extends slightly — see §5)                        │
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

1. **Setup** — server URL, password + TOTP login, TLS trust.
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

Today `kolimi-ffi` exposes only: build a client, `sync_once`, `e2ee_setup`
(see `crates/kolimi-ffi/src/lib.rs`). For the app we add:

| Addition | Why | Where |
| --- | --- | --- |
| `SyncAuth` (password **or** bearer token) in `FfiSyncConfig` | mobile should authenticate with the session token, not a stored password (§6) | `kolimi-sync::Http`, `kolimi-ffi` |
| `list_remote_tree()` / `remote_changed_since()` (optional) | if we want the sync *status* screen to show the server side without Kotlin HTTP | `kolimi-sync` |
| `enroll_device()` / `forget_device()` | expose RFC 0008 enrollment to the app (functions already exist in `kolimi-sync`) | `kolimi-ffi` |
| `is_locked()` / `Locked` error | distinguish "needs passphrase" from a hard failure (matches RFC 0011) | `kolimi-ffi` |

Everything else (browse, preview, upload UI, trash, shares) stays in Kotlin's
Ktor client. **Rule:** the FFI grows only where Rust already owns the logic;
we do not re-expose the whole JSON API through UniFFI.

## 6. Auth and credential storage

- **Login** in Kotlin: `POST /api/session` with password (+ TOTP code). The
  server returns a session cookie; the same value is accepted as
  `Authorization: Bearer <token>` (see `bearer_tokens_authenticate_api_requests`).
- **Store** that token (and the E2EE passphrase, if the user chooses to save
  it) in the **Android Keystore** (hardware-backed AES-GCM), never in
  SharedPreferences plaintext and never in logs.
- **Sync** uses the token too — this is why we add `SyncAuth` to `kolimi-sync`
  (§5). Alternative for v1 (simpler, matches desktop/CLI): keep the password
  in the Keystore and use HTTP Basic. **Recommendation: token**, because it
  honors TOTP and is revocable without changing the password.

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
- The worker builds the FFI client from the Keystore token and calls
  `sync_once`; overlapping runs are prevented with a unique work name and an
  in-process mutex.
- Constraints: `NetworkType.CONNECTED`; retry with backoff on transient
  failures; post a notification on conflicts/failures (a later
  UnifiedPush/ntfy integration can replace polling).

## 9. E2EE on mobile

- Unlock with passphrase or recovery code (both already in the FFI), or
  **enroll this device** so it can unlock without the passphrase (RFC 0008;
  an already-unlocked device approves it).
- The device key is stored via the same `keystore` path as the CLI where a
  platform keystore exists — on Android the app owns this, so the app stores
  the device file in its private dir and the key in the Android Keystore.
- Encrypted roots are configured in Settings; the encrypted-folder UI reuses
  the sync engine's existing `Locked` semantics.

## 10. Build pipeline and CI

- **Rust:** `cargo-ndk` builds `kolimi-ffi` (`cdylib`) for `arm64-v8a` and
  `x86_64` into `app/src/main/jniLibs/<abi>/libkolimi_ffi.so`.
- **Bindings:** `cargo run -p kolimi-ffi --bin uniffi-bindgen -- generate
  --library libkolimi_ffi.so --language kotlin` → committed or generated
  during the Gradle build.
- **TLS crypto provider:** rustls currently pulls **`aws-lc-sys`** (needs
  cmake + a C toolchain per Android ABI). For Android we pin the rustls
  **`ring`** provider (ring has first-class Android targets) to avoid the
  cmake/NDK build. *(Concrete risk item — §13.)*
- **CI job `android`** (new): install NDK + Rust Android targets, run
  `cargo-ndk`, generate Kotlin bindings, then `./gradlew assembleDebug`
  (and a lint/unit-test step). Kept off the release critical path until W6.

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

## 13. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| **`aws-lc-sys` won't cross-compile cleanly for Android** | Pin rustls to the `ring` provider for the mobile build (W0). |
| **JNA AAR / prebuilt `jnidispatch.so` flagged by F-Droid** | Maven Central is allowlisted; verify in W0. Fallback: hand-written JNI over a C ABI (drop UniFFI's Kotlin/JNA layer). |
| **UniFFI + Rust + NDK on F-Droid's offline builder** (highest risk) | Vendor crates, pin the toolchain, reproduce the build in a local VM before submitting (W6). |
| **SAF vs `std::fs`** | v1 uses an app-private folder (no SAF); SAF needs stream-based sync — out of scope. |
| **Passkeys need GMS** | Password + TOTP for v1 (as planned). |
| **Battery/Doze** | `WorkManager` periodic + a foreground "sync now"; no polling. |
| **App-private storage is wiped on uninstall** | Document it; offer export / a later SAF folder. |

## 14. Decisions (confirmed 2026-10-14)

1. **App id** — `xyz.yeleti.kolimi`.
2. **minSdk / targetSdk** — minSdk **24**, targetSdk latest stable.
3. **ABIs** — `arm64-v8a` + `x86_64` (`armeabi-v7a` only if ever needed).
4. **Auth model** — session **token** (login once with password + TOTP, pass
   the token to the Rust sync engine via a new `SyncAuth`).
5. **UI HTTP** — native Kotlin/Ktor; the FFI stays focused on sync + crypto.
6. **Local folder** — app-private directory; SAF deferred.
7. **Passkeys in v1** — no (needs GMS).
