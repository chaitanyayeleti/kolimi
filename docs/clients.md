# Connecting clients

Kolimi exposes the same account through the web app, the desktop app,
`kolimi-sync`, WebDAV, and CalDAV/CardDAV. This page is the canonical guide
to connection URLs, credentials, and client-specific setup. Installation
paths are in [install.md](install.md); day-to-day web UI use is in
[usage.md](usage.md); flags and endpoints are in [reference.md](reference.md).

- [Credentials at a glance](#credentials-at-a-glance)
- [App passwords](#app-passwords)
- [WebDAV](#webdav)
- [CalDAV and CardDAV](#caldav-and-carddav)
- [Desktop app](#desktop-app)
- [`kolimi-sync` CLI](#kolimi-sync-cli)
- [Mobile](#mobile)
- [Troubleshooting](#troubleshooting)

## Credentials at a glance

| Surface | URL | Credential |
| --- | --- | --- |
| Web app | `https://cloud.example.com/app/` | Account password or passkey, plus TOTP when enrolled |
| Desktop app | `https://cloud.example.com/` | Account password + TOTP, or a linked web session / app password |
| `kolimi-sync` | `https://cloud.example.com/` | App password (recommended) or account password |
| WebDAV | `https://cloud.example.com/dav/` | Username + app password (HTTP Basic) |
| CalDAV | `https://cloud.example.com/dav/calendars/<user>/` | Username + app password |
| CardDAV | `https://cloud.example.com/dav/addressbooks/<user>/` | Username + app password |

The username is always the Kolimi account name (`alice`, not an email
address unless that is the account name).

## App passwords

Use an **app password** for every non-browser client: WebDAV, CalDAV,
CardDAV, `kolimi-sync`, and background desktop sync. An app password is a
long-lived, per-device credential that can be revoked independently of the
account password. The server stores only a BLAKE3 digest.

Create one in the web app:

1. Sign in and open **Settings → Passkeys**.
2. Under **App passwords**, enter a name such as `laptop-dav`, choose an
   access preset (Sync client, Files read-only, Files read/write, Calendars &
   contacts, or Full access), and optionally an expiry.
3. Choose **Create app password**.
4. Copy the token immediately — it is shown once. Paste it into the client
   or its keychain entry.

Notes:

- Presets are protocol-level scopes. **Sync client** covers file transport,
  chunks, keyring/MLS, and the share metadata needed to maintain encrypted
  shared folders. **Calendars & contacts** covers only those DAV trees.
  **Full access** is required for account administration and token
  management. Existing tokens without scopes keep full access.
- App passwords work with HTTP Basic even when the account has TOTP
  enrolled, and they are the only password path for passkey-only accounts.
- They do not work for the web UI session login; use the web sign-in page.
- Revoke a token from the same panel when a device is lost or retired. Admin
  account recovery also revokes every app password.
- Accounts with `must_setup_mfa` must finish **Secure your account** (TOTP
  or a passkey) before creating app passwords; data, sync, and DAV surfaces
  stay blocked until then.
- A plain account password still works over Basic when TOTP is **not**
  enrolled, but prefer an app password so the credential is revocable and
  does not expose the login password to client configuration files.

## WebDAV

The WebDAV root is `https://cloud.example.com/dav/` and maps to the account
root. Use the trailing slash. Paths mirror the file tree:

```
https://cloud.example.com/dav/                  account root
https://cloud.example.com/dav/Documents/        a folder
https://cloud.example.com/dav/Documents/a.pdf   a file
```

WebDAV is class 2: byte ranges, streamed reads, and `LOCK`/`UNLOCK` are
supported, and `quota-used-bytes` / `quota-available-bytes` report space.
Use `davs://` or `https://`; plain `http://` exposes the app password to the
network and should only be used behind a trusted tunnel.

Test with curl:

```sh
export DAV_PASS='app-password-here'

curl -u "alice:$DAV_PASS" -X PROPFIND -H 'Depth: 1' \
  https://cloud.example.com/dav/

curl -u "alice:$DAV_PASS" -T ./report.pdf \
  https://cloud.example.com/dav/Documents/report.pdf
curl -u "alice:$DAV_PASS" \
  https://cloud.example.com/dav/Documents/report.pdf
curl -u "alice:$DAV_PASS" -X DELETE \
  https://cloud.example.com/dav/Documents/report.pdf
```

Mount it:

- **GNOME Files:** *Other Locations → Connect to Server* →
  `davs://cloud.example.com/dav/`.
- **macOS Finder:** *Go → Connect to Server* →
  `https://cloud.example.com/dav/`.
- **Windows:** *Map network drive* → `https://cloud.example.com/dav/`.
  Windows' WebClient service must be running; it normally requires HTTPS
  for Basic credentials.
- **davfs2:**

  ```sh
  sudo mount -t davfs https://cloud.example.com/dav/ /mnt/kolimi
  ```

  Store the app password in `~/.davfs2/secrets` rather than `/etc/fstab`.

- **rclone:** create a WebDAV remote with URL
  `https://cloud.example.com/dav/`, vendor `other`, and the app password;
  then `rclone mount` or `rclone sync`.

Encrypted content is **not readable over WebDAV**. Encrypted files are
opaque ciphertext and encrypted folders may show `k1_…` names. Content reads
and writes (`GET`/`PUT`/`PROPPATCH`/`COPY`/`MOVE`) return `403`; `DELETE`
and `LOCK` are metadata-only and still work. Use the web app, desktop app,
or `kolimi-sync` for E2EE content. WebDAV is the right surface for plaintext
folders and for clients that encrypt their own payload (for example
Seedvault backups).

The root names `principals`, `calendars`, and `addressbooks` are reserved
for CalDAV/CardDAV and shadow the file tree; do not use them as folder
names.

## CalDAV and CardDAV

Kolimi serves calendars and contacts from the same `/dav/` root as separate
DAV namespaces:

| Resource | URL |
| --- | --- |
| Discovery | `https://cloud.example.com/.well-known/caldav` and `/.well-known/carddav` |
| Principal | `https://cloud.example.com/dav/principals/<user>/` |
| Calendar home | `https://cloud.example.com/dav/calendars/<user>/` |
| Address-book home | `https://cloud.example.com/dav/addressbooks/<user>/` |

Authenticate with the username and an app password. Clients that support
discovery can be pointed at `https://cloud.example.com/dav/`; if a client
asks for a direct collection URL, use the calendar or address-book home
above.

Suggested clients:

- **Thunderbird** — *New Calendar → On the Network → CalDAV* and
  *Address Book → New → CardDAV*.
- **DAVx5** (Android) — add the account with the server URL and app
  password; it discovers both homes.
- **Apple Calendar / Contacts** — add an *Other* CalDAV or CardDAV account
  with the server URL and app password.
- **Evolution** — add CalDAV and CardDAV calendars/address books.

CalDAV/CardDAV support collection creation, `calendar-query`,
`addressbook-query`, multiget, and `sync-collection` (RFC 6578). Calendars
and contacts are stored separately from the file tree and are **not**
end-to-end encrypted.

## Desktop app

The Tauri desktop app loads the server's `/app/` UI in a native window and
adds a tray menu, background folder sync, and OS keychain storage. You can
sign in to one or more accounts; each account has its own synced folders.
Install it from [install.md](install.md#desktop-client); Linux, Windows, and
macOS bundles are published with `desktop-v*` releases.

### Sign in

Background sync needs credentials that work while the window is closed, so
the desktop sign-in is separate from the webview session:

1. Open **Accounts & Sync** from the tray.
2. Enter the server URL, username, and account password.
3. If TOTP is enrolled, enter the current six-digit code or a recovery code.
4. The client authenticates through `/api/session`, creates an app password,
   and stores it in the OS keychain. The web session token is not kept.

Passkey-only accounts have no password to enter. Sign in to the main Kolimi
window first, then choose **Use current web session** in Accounts & Sync;
the native client reads the webview cookie locally and exchanges it for an
app password. Alternatively, create an app password in **Settings →
Passkeys** and paste it into the desktop sign-in form.

### Synced folders

Each **pair** mirrors one local folder to a remote subfolder. In the add/edit
form:

- **Local folder** — absolute path, or `~` is expanded.
- **Remote folder** — defaults to `/` (the account root).
- **Encrypted folders** — comma-separated paths relative to the pair, for
  example `Private, Photos`. Leave blank for no encryption.
- **Encrypt the entire sync folder** — encrypts the pair root itself. The
  UI stores the empty encrypted-root sentinel; do not also list the folder
  name.
- **Enable MLS group shares** — publishes this desktop as an MLS device and
  includes it in encrypted group-share key packages.

The pair's action menu also offers **Share**, **Unshare**, **MLS status**,
and **Migrate MLS**. The account's **Devices & keys** section lists MLS
devices, pending enrollments, and pinned recipient keys; automatic device
approval can be toggled per account.

The same window shows the E2EE status. If the account has no keyring,
**Set up encryption** creates one and shows the 24-word recovery phrase once;
if the keyring is locked, enter the passphrase to unlock it. The passphrase
never leaves the client. Enabling encryption does not convert existing
plaintext. Sync refuses to mark a remote root encrypted while it still
contains plaintext, so move or delete those files first (or start with a
fresh remote folder). Encrypted files are opaque on the server, but sizes,
timestamps, folder structure, and access patterns remain visible.

Sync runs at startup, every five minutes, and on demand. The **Sync** item
and tray show idle, syncing, paused, error, locked, and conflict states;
**Pause** and **Resume** affect both. The status card keeps the last error
and the last successful sync per folder. A conflict leaves the server
version at the original path and writes the local edit as
`name.conflict-<stamp>`.

The non-secret configuration lives in `desktop.json` under the platform
config directory:

- Linux: `~/.config/kolimi/desktop.json`
- Windows: `%APPDATA%\kolimi\desktop.json`
- macOS: `~/Library/Application Support/kolimi/desktop.json`

`KOLIMI_DESKTOP_CONFIG` overrides the path. The account password (kept for
E2EE re-authentication), E2EE passphrase, and sync app password are stored
in the OS keychain, keyed by `username@server`. If no keychain is available
the app falls back to the Linux kernel session keyring, then warns before a
`0600` config-file fallback; treat that file like `.netrc`.

Signing out or removing an account revokes the desktop's app password
server-side. Removing a pair stops syncing it but leaves both copies in
place.

Limitations: autostart uses XDG autostart on Linux only (use the OS login
items on Windows/macOS); Windows and macOS bundles are unsigned; the macOS
bundle is arm64-only. There is no mobile app yet.

## `kolimi-sync` CLI

`kolimi-sync` performs one-shot syncs; run it from a timer, watcher, or
backup job. It uses HTTP Basic and cannot answer an interactive TOTP prompt,
so TOTP and passkey-only accounts must supply an **app password**:

```sh
export KOLIMI_PASSWORD='app-password-here'

kolimi-sync \
  --server https://cloud.example.com \
  --user alice \
  --local ~/Kolimi \
  --remote /Kolimi
```

Encrypted subtrees are opt-in per run:

```sh
export KOLIMI_E2EE_PASSPHRASE='…'

# encrypt <local>/Private <-> /Kolimi/Private
kolimi-sync ... --e2ee-root Private

# encrypt the whole sync root (empty value)
kolimi-sync ... --e2ee-root ''
```

Create the keyring once with `--e2ee-setup` and store the printed recovery
code offline. The desktop app can also create or unlock the keyring from
**Accounts & Sync**. See the full flag list in
[reference.md](reference.md#kolimi-sync).

## Mobile

There is no shipped mobile app. `kolimi-ffi` exposes `sync_once` and E2EE
setup/unlock to Kotlin/Swift wrappers; background scheduling is platform
code. The Android plan is [plans/android.md](plans/android.md).

## Troubleshooting

| Symptom | Check |
| --- | --- |
| WebDAV returns `401` | Username and app password. If TOTP is enrolled, the account password is rejected over Basic; create an app password. |
| DAV/sync returns `403` | Finish the forced password change or **Secure your account** MFA setup in the web app. |
| WebDAV lists `k1_…` names or `403` on download | The folder is encrypted. Generic DAV clients cannot decrypt; use a Kolimi client. |
| Desktop is missing from **Settings → Devices → MLS devices** | Enable **MLS group shares** on the pair and run **Sync now**. The desktop only publishes itself when MLS is enabled. |
| Desktop signs out after a password recovery | Admin recovery revokes app passwords. Sign in again to create a new one. |
| `davfs2` reports a certificate error | Mount the `https://` URL with a certificate the system trusts; do not disable verification. |
| CalDAV discovery fails | Point the client directly at `/dav/`, then at `/dav/principals/<user>/` or the calendar/address-book home. |
