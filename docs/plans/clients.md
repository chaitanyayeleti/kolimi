# Client roadmap (desktop first, then mobile)

Priority order:

1. **Desktop app** — shipped for Linux, Windows, and macOS.
2. **Mobile** — Android/F-Droid first, then iOS. **Planning refreshed
   2026-11-16; implementation not started.**

One Rust core, thin platform shells: the sync engine and crypto already
live in `kolimi-sync` + `kolimi-crypto`, and `kolimi-ffi` (UniFFI) already
emits Kotlin/Swift/Python bindings.

## Architecture (one core, platform shells)

- **Core (Rust, shared):** `kolimi-sync` (delta sync, conflicts) and
  `kolimi-crypto` (E2EE, keyring, sharing) behind the existing UniFFI
  boundary in `kolimi-ffi`. No OS dependencies, so every client reuses it.
- **Desktop:** a full app built on **Tauri** (Rust backend + system
  webview) that **reuses the existing Leptos UI** (`kolimi-ui`) and adds
  native background sync via `kolimi-sync`. `apps/kolimi-desktop` is the
  promoted tray shell (own workspace). (A Rust-native GUI — Dioxus/Slint/egui
  — is an alternative if a webview is undesirable; it means a separate UI.)
- **Mobile:** Kotlin + Jetpack Compose (Android) / SwiftUI (iOS) shells
  over the same UniFFI core; `WorkManager` / `BGTaskScheduler` for
  background sync. No Google Play Services, no Firebase.

## Phase 1 — Desktop (weeks 1–6)

| Week | Deliverable | Exit criteria |
| --- | --- | --- |
| **1 — stack + shell** | Decide Tauri-reuse vs Rust-native; promote `apps/kolimi-tray` into `apps/kolimi-desktop`; full window that loads the server `/app/` UI (Option A) and logs in | App opens, logs into a server, browses files |
| **2 — files** | Upload/download, drag-and-drop, rename/move/delete, versions/trash, search, previews (reuse the JSON API + UI) | Feature parity with the web UI in the desktop shell |
| **3 — native sync** | Embed `kolimi-sync`: local "Kolimi" folder, tray icon, auto-start, periodic + on-demand sync, conflict handling | Round-trip sync; background sync on Linux; conflicts → `.conflict-<ts>` |
| **4 — auth & credentials** | Password + passkey/TOTP login; credentials in the OS secret store (libsecret / Credential Manager / Keychain); TLS trust | Secure storage works on Linux; no secrets in logs/config plaintext |
| **5 — E2EE + sharing** | E2EE setup/unlock UI, encrypted roots, share/unshare dialogs | Encrypted sync end-to-end from the desktop app |
| **6 — packaging + release** | `.deb` + AUR + AppImage (Linux), then MSI (Windows), `.dmg` (macOS); signing/notarization; auto-update | Installable on Linux; first desktop release tagged |

Windows/macOS follow once Linux is solid (mainly packaging, signing, and
platform glue for the secret store and tray).

**Status (as of 2026-11-16): phase 1 complete and released through the
`desktop-v*` workflow; phase 2 is planned but not started.** Week 1 =
shell (window, first-run setup, tray). Week 2 = parity via the loaded web UI
plus the two native gaps it can't cover: OS file-drop uploads (Tauri's
file-drop handler disabled so the web UI's own drop logic runs) and downloads
routed to `~/Downloads` with tray status. Week 3 = native sync polish: tray
icon states (idle/syncing/error/paused), notifications on failure/conflicts,
XDG autostart toggle, and pause/resume. Week 4 = OS keychain for the password
and E2EE passphrase (Secret Service / Credential Manager / Keychain) with a
session-keyring and warned file fallback. Week 5 = E2EE surfacing and
end-to-end verification. Week 6 = packaging: `.deb` + AppImage + AUR
`kolimi-desktop`, released via the Desktop Release workflow on `desktop-v*`
tags. Phase 2 (mobile) is planned but not started; see
[android.md](android.md).

## Phase 2 — Mobile (planned, not started)

Design detail: **[android.md](android.md)**. The plan was refreshed on
2026-11-16; implementation has not started. Kotlin/Compose shell over the
UniFFI core; `WorkManager` background sync.

| Week | Deliverable | Exit criteria |
| --- | --- | --- |
| **7 — feasibility** | `apps/kolimi-android` layout; CI cross-compiles the Rust core for `aarch64`/`x86_64` and links a trivial JNI call; TLS provider decided | Rust `.so` + Kotlin bindings build in CI; a debug APK completes a TLS sync |
| **8 — skeleton + login** | Settings (server URL), password + TOTP login, named app password in Keystore, list files | Logs in and shows the tree |
| **9 — files** | Browse/navigate, upload/download, mkdir/rename/move/delete, search | File management parity for the essentials |
| **10 — sync** | `kolimi-sync` in-app, app-private folder, `WorkManager` periodic sync, conflicts | Round-trip + background sync + conflict notification |
| **11 — E2EE** | Passphrase/recovery unlock, device enrollment, encrypted roots from the local mirror | Plaintext never reaches the server |
| **12 — F-Droid prep + submit** | Material 3 polish, notifications, `fastlane` metadata, vendor crates, fdroiddata recipe; submit MR | App accepted on F-Droid |

## F-Droid requirements (build for these from the start of phase 2)

- **FOSS only** (repo is AGPL-3.0 — fine). No GMS/Firebase/analytics/trackers.
- **Buildable from source by F-Droid's build server:** commit `Cargo.lock`
  and **vendor** crates so the build works offline; run `cargo-ndk` from the
  recipe. *(Highest-risk item — de-risk first.)*
- **Metadata:** app id, versionCode/Name, `fastlane` listing, declare
  `AntiFeatures` if applicable. F-Droid signs the APK.

## Risks & mitigations

- **Rust/UniFFI on F-Droid's offline build server** → vendor crates; validate
  in a local VM before submitting.
- **Desktop credential stores** differ per OS → small platform glue
  (`keyring` crate) rather than hand-rolled per-OS code.
- **macOS/Windows signing** (notarization, EV cert) → plan early, budget time.
- **Passkeys/WebAuthn on Android** often needs GMS → password + TOTP for v1.

## Decisions

- Desktop stack: **Tauri reusing the Leptos UI**. Decided and shipped.
- Desktop OS order: **Linux first**, then Windows/macOS. All three are
  packaged; Windows/macOS bundles remain unsigned.
- Mobile: app id, SDK levels, ABIs, storage, and the no-passkeys-v1 decision
  are recorded in [android.md](android.md). The plan was refreshed on
  2026-11-16; implementation has not started.
