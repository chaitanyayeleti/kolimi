# Web UI — improvement plan

Status: **phase 1–2 implemented; 0.5.2 release pending** · Date: 2026-11-16
Target: **0.5.2** (speed and polish), **0.6.0** (sharing and discovery)
Builds on: [architecture.md](../architecture.md), [clients.md](../clients.md),
[releases.md](releases.md)

The authenticated UI is already feature-rich: list and grid views, bulk
selection, drag-and-drop upload, an upload tray, previews, versions, trash,
per-file sharing, MLS devices, passkeys, and the admin pages. This plan does
not redesign it. It closes four gaps that show up in daily use:

1. the first load is slow and re-downloads a 5 MB WASM bundle;
2. shares and public links have no home outside the file that created them;
3. there is no quick way back to shared, favorite, or recent content;
4. mobile selection, keyboard use, and a few theme/quota states need polish.

## 1. Goal

Make the web UI feel fast on first load, make sharing discoverable and
manageable, and make the common file operations usable with a keyboard and on
a phone — without changing the E2EE boundary, the single-binary packaging, or
the existing JSON API shapes.

The desktop app loads the server's `/app/` UI, so every web improvement ships
to desktop users without a desktop release. The bundled desktop UI remains
the Accounts & Sync window only.

## 2. Non-goals

- A redesign or a new frontend framework. Keep Leptos CSR, the existing CSS
  tokens, and the single `app_bg.wasm` bundle.
- A first-party calendar or contacts UI. CalDAV/CardDAV stay protocol-first
  for Thunderbird, Apple, Evolution, and DAVx5; invest in a **Connect a
  device** panel instead.
- Email delivery, SMTP, push notifications, or presence.
- Offline editing of encrypted files. A service worker may cache the app
  shell, never API responses or decrypted content.
- A native Android/iOS UI. That remains [android.md](android.md).
- Changing share authorization. `kolimi-vfs` stays the only authorization
  boundary; new endpoints call it like the existing ones.

## 3. Current state

| Area | Today | Gap |
| --- | --- | --- |
| Files | List/grid, sort/filter, bulk download/move/trash, drag-and-drop, upload tray, previews, versions, trash, full-text search | Grid/sort/filter reset on reload; no list keyboard navigation; checkboxes always visible on touch |
| Sharing | Per-file dialog for user/group/link shares, password links, MLS folder shares | No global list of created shares or public links; link expiry exists in the API but not the UI; Settings → Sharing is MLS-only and dead-ends when locked |
| Discovery | Server full-text search, client-side encrypted-name search, received mounts at the root | No **Shared**, **Favorites**, or **Recent** view; no notification when something is shared |
| Performance | 5.18 MB `app_bg.wasm`, 70 KB `app.js`, 49 KB `style.css` | No compression, no ETag, `Cache-Control: no-cache`; a reload re-fetches the full bundle |
| Theme | Light/dark/system, design tokens, reduced-motion rules | Manual dark mode leaves native checkboxes/selects light; unlimited quota renders as `0%` |
| Mobile | Responsive layout, drawer navigation, 2-column grid | Selection checkboxes are always shown; drawer and tap targets need refinement |
| Install | Responsive, installable-looking login | No web app manifest or offline shell |

Measured from the current build:

| Asset | Raw | gzip | brotli |
| --- | ---: | ---: | ---: |
| `app_bg.wasm` | 5,183,421 B | 1,681,741 B | 1,093,587 B |
| `app.js` | 70 KB | — | — |
| `style.css` | 49 KB | — | — |

The server currently serves these with `Cache-Control: no-cache` and no
`ETag`; there is no compression middleware. Brotli alone removes about 79% of
the WASM transfer.

## 4. Principles

1. **UI first, APIs additive.** Phase 1 and 2 need no schema change. Phase 3
   uses the existing share APIs. New tables arrive only for favorites,
   recents, and events.
2. **No new frontend build chain.** Keep `scripts/build-ui.sh`; add only
   build-time asset compression and optional `wasm-opt`. A test-only Node
   dependency such as `@axe-core/playwright` is acceptable.
3. **The server stays blind.** Share lists, favorites, recents, and event
   payloads carry node IDs, owner names, and share metadata — never plaintext
   encrypted names, file keys, or decrypted content.
4. **Progressive enhancement.** The app shell must paint before WASM loads.
5. **Every new surface is testable.** Playwright covers the flow; Rust tests
   cover new headers and endpoints; an axe check covers the main pages.
6. **No authorization shortcuts.** Every new endpoint resolves access through
   `kolimi-vfs` and returns the same `404`/`403` shape as the existing API.

## 5. Phases

### Phase 1 — fast first paint (0.5.2, P0)

**Build**

- Precompress `app_bg.wasm`, `app.js`, `style.css`, and the KDF assets in
  `scripts/build-ui.sh` (`.br` and `.gz` next to each file).
- Run `wasm-opt -Oz` after `wasm-bindgen` when binaryen is available; keep a
  size budget in CI so a regression fails the build.
- Add `<link rel="modulepreload" href="/app/app.js">` to `index.html`.

**Serve** (`crates/kolimi-server/src/ui.rs`)

- Pick the compressed representation from `Accept-Encoding`; set
  `Content-Encoding` and `Vary: Accept-Encoding`. Keep the original MIME type
  (`application/wasm`, `text/css`, `text/javascript`).
- Add a strong `ETag` from the embedded asset hash
  (`asset.metadata().sha256_hash()`); honor `If-None-Match` with `304`.
- Use `Cache-Control: public, max-age=31536000, immutable` for fingerprinted
  assets once names are hashed; until then use `no-cache` plus the ETag. The
  app shell and `index.html` stay `no-cache`.
- Do not compress the shell HTML; it is small and changes per release.

**Paint**

- Put a static loading shell inside `#app` in `crates/kolimi-ui/index.html`:
  logo, “Loading Kolimi…”, and a short hint. Use classes from `style.css`
  because the CSP forbids inline styles. Add a `<noscript>` message.
- Ensure the shell disappears when Leptos mounts; no layout jump.

**Tests**

- `ui.rs` unit tests: br/gzip selection, `Vary`, ETag/`304`, fallback to raw.
- Playwright: request `app_bg.wasm` with `Accept-Encoding: br` and assert
  `Content-Encoding`; send `If-None-Match` and assert `304`; assert the
  initial `/app/` HTML contains the loading shell.
- CI size budget: compressed WASM ≤ 1.25 MB, raw WASM no larger than today.

Acceptance: a fresh load transfers roughly 1.1 MB instead of 5.2 MB for the
WASM; a reload returns `304`; the page never paints blank.

### Phase 2 — polish and accessibility (0.5.2, P1)

**Theme and status**

- Add `color-scheme: dark` to `:root.dark` and the
  `prefers-color-scheme: dark` block so native checkboxes, selects, and
  scrollbars match the theme.
- Replace the single “Theme” cycle button with a small menu: System, Light,
  Dark. Keep the existing `localStorage` key.
- Fix the sidebar quota widget when `effective_quota_bytes == 0`: show “No
  quota” and omit the percentage/ring instead of `0%`.
- Persist list/grid, sort, and filter in `localStorage`; use the same signal
  defaults on load.

**Settings dead ends**

- Settings → Sharing currently shows “Unlock encryption to manage MLS
  shares” with no action. Add an **Unlock encryption** button that switches
  to the Encryption tab (or opens the unlock dialog).
- Do the same for the device list; enrollment can remain visible while
  locked.
- Rename the tab to **Encrypted sharing** if the global Shared page lands in
  0.6.0, so “Sharing” is not ambiguous.

**Mobile**

- Add a **Select** action in the top bar; show checkboxes only in selection
  mode, or after a long-press on a tile/row. Clear selection on navigation.
- Make the existing mobile drawer scrim more visible and add a close
  affordance; keep the 44 px minimum tap target on actions.
- Make the bulk bar wrap and stay above the safe-area inset.

**Keyboard**

- Global handler in `browser/mod.rs`, ignored while focus is in an input,
  textarea, or select:
  - `/` focuses search; `Escape` clears search or closes the context menu.
  - `ArrowUp`/`ArrowDown` move the active row; `Home`/`End` jump.
  - `Enter` opens the active row; `Space` toggles selection.
  - `Delete` trashes the selection after confirmation.
  - `Ctrl/Cmd+A` selects all visible entries.
- Use a roving `tabindex` on rows/tiles; announce selection and bulk results
  through the existing toast/`aria-live` region.

**Accessibility gate**

- Add `@axe-core/playwright` to `browser-e2e`; run it on login, Files,
  Settings, Shared, and Admin. Fail on serious/critical violations.
- Add a skip link (“Skip to files”) before the sidebar.
- Verify focus-visible rings in both themes and that dialogs restore focus.

Acceptance: no white native controls in manual dark mode; no `0%` for an
unlimited quota; selection works on a phone without accidental taps; the
main pages pass axe; the file list is usable without a mouse.

### Phase 3 — Shared page and link controls (0.6.0, P0)

The APIs already exist; this phase is mostly UI:

| Need | Existing API |
| --- | --- |
| Received shares | `GET /api/shares/received` |
| Created shares | `GET /api/shares/owned` |
| Change permission/expiry/password | `PATCH /api/shares/{id}` |
| Revoke | `DELETE /api/shares/{id}` |
| Share one path | `GET/POST /api/shares` |

**Sidebar entry**

Add **Shared** between Files and Trash. The page has three sections or tabs:

- **Received** — owner, permission (`read`/`write`, shown as view/edit),
  folder/file, size, modified, and lock state. Decode encrypted names when
  the keyring is unlocked; otherwise show “Encrypted share” with the owner.
  Open navigates to the mount path.
- **Created** — recipient (user/group) or “Public link”, path, permission,
  created, expiry, and a “missing” badge when the target was deleted. Decode
  encrypted paths when the keyring is unlocked; otherwise mark them as
  encrypted. Actions: revoke, copy link, adjust permission (read/write for
  user/group), and set a new password for links.
- **Public links** — filter the Created list to `kind == "link"`. Show the URL
  (`/s/<token>`), created/expiry, and copy/revoke. The password is write-only
  after creation; offer “Set new password” rather than pretending to show it.

**Encrypted links**

A public link to an encrypted file carries the file key, chunk lengths, and
display name in the URL fragment; the server deliberately never sees them.
`GET /api/shares/owned` returns only `/s/<token>`, so the bare URL is not a
working link.

- Prefer rebuilding the fragment from the wrapped file key and manifest when
  the user copies from the Shared page, while the vault is unlocked. Do not
  persist link keys by default.
- If a persisted fragment is offered, make it an explicit per-link choice,
  scope it to that share, and clear it on sign-out. The server never receives
  it either way.
- When neither is available, show “Unlock encryption to copy the full link”
  rather than a broken URL.
- Never send the fragment to the server, logs, audit entries, or events.
- Test: create an encrypted link, reload the app, copy it from Shared, and
  open it in a private window; server responses and logs contain no key.

**Share dialog**

- Add expiry presets for links: Never, 1 day, 7 days, 30 days, custom. Map
  them to `expires_in_secs` (`0` = never) on create and `PATCH` on edit.
- Add copy confirmation for the link and QR; add a “Manage all shares” link to
  the Shared page.
- When encryption is locked, explain which action is unavailable and offer
  the unlock CTA instead of a generic error.

**Tests**

- Playwright creates a user share, a group share, and an expiring link; sees
  all three on Shared; revokes one; edits expiry; copies the URL.
- Encrypted received share shows the owner and lock state before unlock, and
  the decoded name after unlock.
- Rust: no new endpoints expected; add coverage only if `share_json` needs a
  field (for example `created_at` is already present).

Acceptance: a user can answer “what have I shared, with whom, until when, and
how do I revoke it?” without opening each file; a link can be created with an
expiry from the UI.

### Phase 4 — Favorites and recents (0.6.0, P1)

**Schema** (next migration number; currently `0031`)

```sql
CREATE TABLE favorites (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, node_id)
);

CREATE INDEX favorites_user_created
    ON favorites(user_id, created_at DESC);

CREATE TABLE recents (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    opened_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, node_id)
);

CREATE INDEX recents_user_opened
    ON recents(user_id, opened_at DESC);
```

Do not edit applied migrations; renumber if another migration lands first.

**API**

- Add the node ID (for example `node_id`) to browse entries and received
  mounts so the UI can favorite a node without a second lookup.
- `GET /api/favorites` — accessible favorites with current path, name, kind,
  and `encrypted`; resolve through `kolimi-vfs`.
- `PUT /api/favorites/{node_id}` and `DELETE /api/favorites/{node_id}`.
- `GET /api/recents` — the caller's recent nodes, capped at 50.
- `POST /api/recents` — record an explicit open/download/preview; upsert and
  prune beyond 50. Do not record every browse request.
- All endpoints return `404` for a node the caller cannot access.

**UI**

- Star action in the row/tile context menu and details dialog; a **Favorites**
  sidebar section.
- **Recent** section, ordered by `opened_at`; empty state explains that
  opening files adds them.
- If a favorite is a received share that is later revoked, omit it from the
  list rather than returning a stale path.

Acceptance: a star survives reload and a second browser; Recent shows the
last files actually opened; revoked shares disappear.

### Phase 5 — notifications and PWA (0.6.x, P2)

**Notifications**

Schema:

```sql
CREATE TABLE user_events (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    read_at INTEGER
);

CREATE INDEX user_events_unread
    ON user_events(user_id, read_at, id);
```

- Emit events for `share.created`, `share.revoked`, `device.revoked`, and a
  quota threshold (80%/95%, once per period). Keep the initial set small.
- `GET /api/events?since=&limit=` returns newest events plus an unread count.
- `POST /api/events/read` accepts `{ "ids": [...] }` or `{ "all": true }`.
- The UI polls every 30 seconds first; an SSE stream can follow if the polling
  cost matters. The existing sync SSE is a reference, not a requirement.
- Payloads must be E2EE-safe: `share_id`, owner, kind, permission, and an
  `encrypted` flag; never a plaintext encrypted name or a file key.
- Add a bell in the top bar with an unread badge and a panel that links to the
  Shared page. Mark read on open.

**PWA**

- Add `/app/manifest.webmanifest` with name, short name, icons (192/512/
  maskable), `display: standalone`, and theme/background colors.
- Add `/app/sw.js`:
  - precache the app shell (`/app/`, `app.js`, `app_bg.wasm`, `style.css`,
    icons);
  - stale-while-revalidate for static assets;
  - network-only for `/api/`, `/dav/`, `/s/`, and any authenticated response;
  - version the cache and delete old caches on activate.
- Add `worker-src 'self'` (and `manifest-src 'self'`) to the CSP.
- Show a “new version available — reload” prompt on `controllerchange`
  instead of silently swapping the bundle.
- Clear caches on sign-out; never cache decrypted blobs or file content.

Acceptance: the app installs from the browser; an offline reload shows the
shell and a clear “you are offline” state; no API or decrypted content is in
the cache.

### Phase 6 — related core work (separate releases)

These are not required for the UI phases, but they remove the biggest
remaining friction:

| Work | Why | Size |
| --- | --- | --- |
| Resumable browser uploads | Today a failed single PUT restarts; E2EE uploads read the whole file into memory. Reuse a chunked session API. | L |
| Desktop conflict list | Sync reports only a count; expose conflict paths and “open folder” / keep local or remote. | M |
| Paginated browse + virtualized list | `/api/browse` returns every entry; large folders will stall the UI. | M/L |
| Admin System page | Version, DB/blob size, last backup/verify, janitor, search index, uptime. | M |
| Connect a device panel | Create an app password, show WebDAV/CalDAV URLs and QR, move app passwords out of “Passkeys”. | S/M |
| Preview cache | ETag/mtime-keyed thumbnails; stop re-running the image worker on every grid view. | S/M |

## 6. Test plan

- **Rust** — `ui.rs` header/ETag/304 tests; endpoint tests for favorites,
  recents, events, and authorization; migration upgrade test with a seeded
  database.
- **Playwright** — the existing `browser-e2e` suite plus:
  - compressed asset headers and `304`;
  - Shared page create/list/revoke/expiry;
  - favorites persistence and revoked-share cleanup;
  - notification unread/read flow;
  - PWA manifest and offline shell;
  - keyboard navigation and `/` search;
  - axe on login, Files, Settings, Shared, Admin.
- **Security** — no plaintext encrypted names, file keys, tokens, or
  passwords in new responses or event payloads; CSRF on mutations; service
  worker scope limited to `/app/`; caches cleared on sign-out.
- **Manual** — mobile viewport, dark theme, reduced motion, keyboard-only
  pass, and a slow-network first load.

## 7. Release sequencing

| Release | Content | Migrations | Desktop |
| --- | --- | --- | --- |
| **0.5.2** | Phases 1–2 | None | No bump; desktop loads the new UI |
| **0.6.0** | Phases 3–4 | Favorites, recents | No bump unless desktop conflicts land |
| **0.6.x** | Phase 5 | User events | No bump |

If two releases are too much overhead, fold Phases 1–4 into **0.6.0**; do not
hold the performance and polish work for notifications or PWA.

Before tagging, update `CHANGELOG.md`, `ROADMAP.md`, the `docs/README.md`
plan row, `usage.md` (Shared/Favorites/Recent), `reference.md` (new
endpoints), and `how-to.md` (recipes). Run `scripts/check-docs.sh` and the
browser suite.

## 8. Open questions

1. **Shared placement** — sidebar page (recommended) or a Settings tab? A
   sidebar page is a daily destination; Settings stays for configuration.
2. **Favorites scope** — allow favorites on received shares, or only owned
   nodes? Recommended: any accessible node, filtered on read.
3. **Recent semantics** — explicit open/download/preview only, or every
   browse? Recommended: explicit actions only; browsing a folder is not
   “recently used”.
4. **Notifications transport** — 30-second polling first, SSE later?
   Recommended: polling; it avoids a new long-lived connection and is enough
   for share events.
5. **Asset fingerprinting** — ETag only, or hashed filenames with immutable
   caching? Recommended: ETag in 0.5.2; fingerprint if reload traffic still
   matters.
6. **Public link limits** — expiry and password are enough for now; do not
   add download caps until there is a concrete request.

## 9. Acceptance criteria

- First load transfers about 1.1 MB of WASM (brotli) instead of 5.2 MB; a
  reload returns `304`; the app shell paints before WASM.
- Manual dark mode has no light native controls; unlimited quota is not
  shown as `0%`; view preferences survive reload.
- A user can list, inspect, revoke, and set expiry on shares and public links
  from one page; encrypted names stay opaque until unlock.
- Favorites and Recent work across reloads and browsers.
- The file list is keyboard-operable; the main pages pass axe.
- New endpoints pass Rust authorization tests; the browser suite covers the
  new flows; `scripts/check-docs.sh` passes.
