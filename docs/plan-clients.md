# Client roadmap (Android first)

Goal: ship first-party clients, starting with an **Android app released on
F-Droid**, then desktop, then iOS. One Rust core, thin platform shells —
the sync engine and crypto already live in `kolimi-sync` + `kolimi-crypto`,
and `kolimi-ffi` (UniFFI) already emits Kotlin/Swift/Python bindings.

## Architecture (one core, platform shells)

- **Core (Rust, shared):** `kolimi-sync` (delta sync, conflicts) and
  `kolimi-crypto` (E2EE, keyring, sharing) behind the existing UniFFI
  boundary in `kolimi-ffi`. No OS dependencies, so every client reuses it.
- **Android UI:** Kotlin + Jetpack Compose (all-FOSS: AndroidX/Compose
  are Apache-2.0), with the Rust core compiled to `.so` per ABI
  (`cargo-ndk`) and consumed through the generated Kotlin bindings.
- **Background sync:** `WorkManager` (periodic + on-demand). No Google
  Play Services, no Firebase.
- **Why not a pure-Rust Android UI:** file access (Storage Access
  Framework), notifications, Keystore, and background scheduling all need
  platform glue anyway. A Rust GUI (`slint`/`egui` via `android-activity`)
  is a possible later experiment, not the v1 path.

## F-Droid requirements (build the app to fit these from day one)

- **License:** FOSS only. Repo is AGPL-3.0 — fine. Bundle the license text.
- **No proprietary code:** no Google Play Services, Firebase, Crashlytics,
  proprietary analytics, or trackers. AndroidX/Compose/WorkManager are OK.
- **Buildable from source by F-Droid's build server:** the recipe builds
  from the release tag. Rust crates must be available offline during the
  build → commit a `Cargo.lock` and **vendor** dependencies
  (`cargo vendor`, or use `srclibs`), and run `cargo-ndk` from the recipe.
- **Metadata:** an app id, `versionCode`/`versionName`, and `fastlane`
  files (title, short/full description, screenshots, changelog) for the
  store listing; declare `AntiFeatures` only if applicable.
- **Signing:** F-Droid signs with its own key; do not also ship the same
  package on Play with a different signature (F-Droid supports
  reproducible/Play-compatible signing if desired, but that's optional).
- **Reproducible builds (stretch):** pin toolchains and dependencies so
  F-Droid's rebuild matches ours.
- **Network:** the app talks to a user-chosen self-hosted server, so it is
  not a tracker, but review F-Droid's anti-feature flags on submission.

## Week-by-week (6 weeks)

| Week | Deliverable | Exit criteria |
| --- | --- | --- |
| **0 — decisions & feasibility** | Repo layout (`apps/kolimi-android`), app id/package, minSdk, ABI set; a CI job that cross-compiles the Rust core for `aarch64`/`x86_64` Android and links a trivial JNI call | Rust `.so` builds in CI; UniFFI Kotlin bindings compile in a Gradle project |
| **1 — skeleton + login** | Compose app: settings (server URL), login (password), list remote files | App logs into `cloud.yeleti.xyz` and shows the tree |
| **2 — sync core** | Wire `kolimi-sync` (pull/push, chunk deltas), local folder via SAF or app dir, `WorkManager` periodic sync | Upload/download round-trip; background sync runs; conflict → `.conflict-<ts>` |
| **3 — auth & storage hardening** | Password + TOTP; tokens in Keystore (`EncryptedSharedPreferences`); TLS with system trust; clear error UX; certificate/host validation | Wrong password/TOTP handled; token survives restart; no secrets in logs |
| **4 — E2EE** | Passphrase unlock, `--e2ee-root` equivalent, encrypted push/pull; security review of the shell | Plaintext marker never lands on the server; encrypted sync works on-device |
| **5 — polish + F-Droid prep** | Material 3 polish, sync notifications, refresh, offline queue; `fastlane` metadata; vendor crates; draft the fdroiddata recipe | APK builds from a clean environment with no network beyond mirrors |
| **6 — submit** | Open a merge request to `fdroiddata`; respond to review; tag the release | App accepted/visible on F-Droid |

## Risks & mitigations

- **Rust on F-Droid's build server** (offline build): vendor all crates and
  keep `Cargo.lock`; validate with F-Droid's `build` in a local VM before
  submitting. *(Highest-risk item — de-risk in week 0.)*
- **Passkeys/WebAuthn on Android** commonly needs Google Play Services →
  use password + TOTP for v1; treat passkeys as a later, optional feature.
- **Doze/battery** limits periodic work → use `WorkManager` with a sensible
  interval and a foreground "sync now".
- **ABI matrix** → ship `arm64-v8a` + `x86_64` (covers devices + emulators);
  add `armeabi-v7a` if reach is needed.
- **TLS/rustls** keeps the build free of system OpenSSL — already the case.

## Decisions to confirm

- App id / package name (e.g. `dev.kolimi.app` or `io.github.chaitanyayeleti.kolimi`).
- `minSdk` (e.g. 26) and target SDK.
- UI stack: Kotlin + Compose (recommended) vs a Rust GUI experiment.
- Passkeys in v1? (recommend: no) · Which ABIs?
- Local storage: Storage Access Framework picker vs app-private directory.

## After Android

- **Desktop:** evolve `apps/kolimi-tray` (Tauri) into a full cross-platform
  app for Linux/Windows/macOS, or switch to Dioxus/Slint for a Rust-native
  UI. Package as .deb/AUR/AppImage, MSI, .dmg (with signing/notarization).
- **iOS:** SwiftUI shell over the same UniFFI core (`aarch64-apple-ios`),
  `BGTaskScheduler` for background; App Store later.
