# Decision 0002: Desktop client stack and plan (phase 1)

Status: **Approved** · Date: 2026-10-12 · Approved: 2026-10-13 ·
Depends on: RFC 0006 (sync client), [plan-clients.md](../plans/clients.md),
issue #12

## Outcome (approved 2026-10-13)

- **Architecture: Option A** (remote webview) — the Tauri window loads the
  server's `/app/` URL, with native tray + background sync alongside. Evolve
  toward Option B (embedded UI + Rust proxy, offline) in phase 1.5.
- **Repo:** promote `apps/kolimi-tray` in-repo → `apps/kolimi-desktop`.
- **Scope:** Linux-only for phase 1; Windows/macOS follow.
- **Distribution:** `.deb` + AppImage + AUR (`kolimi-desktop`); add the
  optional Tauri auto-updater in week 6.

## Context

The sync core exists (`kolimi-sync`/`kolimi-ffi`) and `apps/kolimi-tray`
proves the Tauri stack builds, but there is **no full desktop app** — no
window with the file UI, no OS-keychain credentials, no packaging. This
records the phase-1 plan (Linux first) and the stack decision to approve
before starting.

## Decision to make: how the UI is delivered

| Option | What it is | Reuses Leptos UI | Effort | Offline UI |
| --- | --- | --- | --- | --- |
| **A. Remote webview** *(recommended)* | Tauri window loads the server's `/app/` URL; native tray + sync alongside | 100%, unchanged (same-origin cookies/CSRF work) | Low | No (sync yes) |
| **B. Embedded UI + Rust proxy** | Bundle the wasm; webview origin = app; Rust backend proxies API calls (Bearer token, no CORS) | Yes, needs auth/CORS rework | High | Yes |
| **C. Local static server** | App runs a tiny in-process server serving the wasm + reverse-proxying the remote; webview → localhost | 100% | Medium | No (sync yes) |

**Recommendation:** **A** for phase 1, then evolve toward **B** (offline UI
+ native API) as phase 1.5.

## Repo layout

- Promote `apps/kolimi-tray` → **`apps/kolimi-desktop`** (Tauri v2, its own
  workspace, like the tray today).
- Reuse `kolimi-sync` (sync) and `kolimi-crypto` (E2EE) unchanged; `kolimi-ffi`
  is for mobile.
- Keep desktop in this repo for now; split only when its release cadence
  diverges.

## Phase 1 plan (Linux, ~6 weeks)

| Week | Deliverable | Exit criteria |
| --- | --- | --- |
| 1 — shell | Scaffold `apps/kolimi-desktop`; window loads the server URL (configurable); tray icon/menu; first-run settings | App opens, logs in, browses files |
| 2 — native sync | Embed `kolimi-sync`: local `~/Kolimi`, sync on start / every 5 min / on demand, tray status, notifications, XDG autostart | Round-trip + background sync; conflicts → `.conflict-<ts>` |
| 3 — auth & credentials | OS keychain (`keyring`: secret-service/libsecret) for URL/user/password/E2EE passphrase; TLS trust | No plaintext secrets; secure storage works |
| 4 — E2EE + sharing | E2EE setup/unlock (reuse web dialogs under option A), encrypted roots, share/unshare | Encrypted sync end-to-end |
| 5 — packaging | `.deb` (cargo-deb) + AppImage + AUR `kolimi-desktop`; icons, `.desktop` | Installable on Linux |
| 6 — release | Optional Tauri auto-updater; `desktop (Tauri)` CI job; first desktop release + docs | First desktop release tagged |

## CI

New `desktop (Tauri)` job on `ubuntu-latest` with `webkit2gtk-4.1` /
`libappindicator` deps — build + `cargo check` (fast), plus a packaging
check for `.deb`/AppImage.

## Risks & mitigations

- Linux webview deps (webkit2gtk, appindicator) → document + pin in CI/packaging.
- Keychain on headless/no secret-service → fall back to `chmod 600` config with a warning.
- AppImage size → thin bundle, strip.
- If option B later: design the proxy/CORS boundary early.

## Open questions (to confirm)

1. Architecture: **A** / B / C.
2. Repo: promote the tray here (vs a separate repo).
3. Scope: Linux-only for phase 1.
4. Distribution: `.deb` + AppImage + AUR; auto-update yes/no.

## References

- [docs/plans/clients.md](../plans/clients.md)
- Issue #12 (desktop client, phase 1)
- `apps/kolimi-tray`, `crates/kolimi-sync`, `crates/kolimi-ui`
