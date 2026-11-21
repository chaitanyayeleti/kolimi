# Using Kolimi

Day-to-day guide for the web UI, desktop app, and sync client. Server
administration lives in [operations.md](operations.md); flags and endpoints
are in [reference.md](reference.md).

- [Sign in](#sign-in)
- [Account and security](#account-and-security)
- [Files and folders](#files-and-folders)
- [Sharing](#sharing)
- [Desktop app and sync](#desktop-app-and-sync)
- [Other apps and the CLI](#other-apps-and-the-cli)
- [Admin quick reference](#admin-quick-reference)
- [Troubleshooting](#troubleshooting)

## Sign in

Open the server's `/app/` URL (for example `https://cloud.example.com/app/`).

- **Password** — sign in with the account password. If TOTP is enabled,
  enter the six-digit code or a recovery code when prompted.
- **Passkey** — enter the username, then choose **Sign in with a passkey**.
  Passkey-only accounts cannot use the password form.
- **Invite link** — open the one-time link, choose a password, then sign in.
  The link expires and works once.
- **Forced rotation** — an administrator can mark a temporary password as
  requiring a change. Kolimi shows the change-password screen before the
  file browser until a new password is set.
- **First sign-in MFA** — accounts created from **Admin → Users** (or the
  admin API) or through an invite must enroll TOTP or a passkey on the
  **Secure your account** page before the file browser opens. The choice is
  required, but either method clears the block. Existing accounts and
  CLI-created accounts are not forced.

The encryption passphrase is separate from the account password. The login
password protects the account; the passphrase unlocks encrypted files and is
never sent to the server.

## Account and security

Open **Settings** in the sidebar.

- **Account** — change the login password, edit the optional display name and
  email, label sessions (for example “Work laptop”), and revoke individual
  sessions or all other devices. A password change asks for the current
  password or a two-factor code and signs out other sessions.
- **Encryption** — create or unlock the encryption keyring. The recovery
  phrase is shown once; store it offline. Changing the passphrase replaces
  the account keyring. **Encrypt existing names** renames already-encrypted
  items in place (contents are not re-uploaded; plaintext files are skipped).
- **Sharing** — upgrade legacy per-file folder shares to MLS groups.
- **Devices** — review MLS devices and revoke one that is lost or untrusted.
- **Passkeys** — register or remove passkeys and enable TOTP/recovery codes.
- **App passwords** — also under *Settings → Passkeys*: long-lived,
  per-device credentials for WebDAV, CalDAV/CardDAV, and sync clients. Choose
  a preset (Sync client, Files read-only, Files read/write, Calendars &
  contacts, or Full access) and an optional expiry. The token is shown once;
  revoke it here when a device is lost. App passwords work even when TOTP is
  enabled or the account is passkey-only. Full access can manage the account,
  so prefer the narrowest preset that works.

Email is informational only. Kolimi does not send mail or use it to sign in.
Account recovery through an administrator is separate from losing the
encryption passphrase; see [operations.md](operations.md#account-recovery).

## Files and folders

- Upload with the toolbar or by dropping files into the window.
- Use **New folder**, the list/grid toggle, and search to navigate. The
  **Filter files** and **Sort files** controls keep folders first and let you
  narrow the list to folders, files, encrypted items, or received shares.
- Large folders load 1,000 entries at a time; use **Load more** at the bottom
  of the list to append the next page without rendering the whole directory
  at once.
- Tick row checkboxes for multi-select, then use the bulk bar to download,
  move, or trash the selection. Each row’s **Actions** menu has details,
  sharing, rename, versions, and delete.
- Right-click a file or folder (or use its action buttons) to rename,
  download, share, delete, or open its version history and restore an older
  version.
- Deleted items go to **Trash** and can be restored or purged.
- **Shared with me** appears as a mount in the sidebar. Read-only shares
  cannot be changed; write shares can be edited in place.
- **Shared** in the sidebar is the management view: *Received* lists shares
  from other people, *Shared by me* lists user/group shares, and *Links*
  lists public links. Copy a link, change user/group access, adjust link
  expiry or password, or revoke from there. Encrypted file links rebuild
  their `#k=…` key fragment in the browser; unlock encryption first, or the
  page offers the unlock action instead of copying a broken URL.
- The sidebar storage ring shows used space against your quota (when one is
  set).

Encrypted content is marked **Encrypted** in the file list. If a folder is
locked, unlock the keyring first. Encrypted names are decrypted locally.
Image thumbnails use the sandboxed preview worker; encrypted files have no
server-side thumbnail, preview, or content search.

Search matches plaintext names and indexed content. For encrypted files,
names are matched locally after unlock; encrypted content is never indexed.

## Sharing

Use **Share** on a file or folder:

- **User** — share with one account.
- **Group** — share with every member of a group.
- **Public link** — create a read-only URL. Choose an expiry (Never, 1, 7,
  or 30 days) and whether Kolimi generates a password, you set one, or the
  link is open.
- **Request files** — an upload-only link to a plaintext folder. Recipients
  can upload but cannot list, download, or overwrite anything. Set a file
  count and total size limit, an expiry, and an optional password. The files
  appear in the folder normally.

User and group permissions are **read** or **write**. File-request links
always use write permission internally and cannot be switched to read; to
change the mode, revoke the link and create a new one. Encrypted folders
cannot receive file requests because public uploads arrive as plaintext.
Write shares of encrypted folders and single files work for named users and
groups; the web UI can download single-file shares but has no inline editor
for them.

For encrypted content, the recipient must have unlocked Kolimi at least once
so their key package exists. Group membership changes update share ACLs and
wrapped keys but **do not rotate MLS keys**: after adding or removing a
member, re-share the affected encrypted folders from a client so the keyring
advances. Revoking a share cannot erase data a recipient already downloaded.

## Desktop app and sync

The desktop app loads the server's web UI in a native window and adds the
tray menu, background sync, and OS keychain storage. Create a local folder
pair from **Accounts & Sync**. Full client setup, including passkey-only
sign-in and keychain details, is in [clients.md](clients.md#desktop-app).

Background sign-in is separate from the web app so sync can run with the
window closed. Enter the account password plus the current TOTP code (or a
recovery code); passkey-only accounts sign in to the main window first and
then choose **Use current web session**. You can also paste an app password
created under **Settings → Passkeys**. The client stores a revocable app
password in the OS keychain rather than keeping your web session.

If the account has no encryption keyring yet, Accounts & Sync can create one
with **Set up encryption** and shows the 24-word recovery phrase once; a
locked keyring is unlocked there too.

The sidebar **Sync** item and the tray show idle, syncing, paused, error,
locked, and conflict states; click either to open Accounts & Sync. The status
card shows the last sync for each folder, and **Pause** / **Resume** controls
there match the tray item. If the server is unreachable, the main window
shows an offline banner with a Retry action, and the Accounts & Sync status
card keeps the last error and last successful sync visible.

Encrypted folders are normally relative paths inside the pair (for example
`Private` means `<local>/Private` ↔ `<remote>/Private`). Enable **Encrypt the
entire sync folder** when the pair itself should be encrypted; the remote
root is then marked encrypted. Enabling it on a root that still contains
plaintext is refused, so move those files first. Enable **MLS group shares**
on a pair to publish this desktop as an MLS device and include it in
encrypted group-share key packages.

## Other apps and the CLI

WebDAV is served at `https://cloud.example.com/dav/`; CalDAV and CardDAV
use `/dav/calendars/<user>/` and `/dav/addressbooks/<user>/`. Use an **app
password** for these clients rather than the account password. Mounting,
CalDAV/CardDAV setup, and encrypted-folder caveats are in
[clients.md](clients.md#webdav).

The `kolimi-sync` CLI mirrors a local directory and is one-shot, so run it
from a timer or watcher. TOTP and passkey-only accounts need an app password;
the CLI cannot answer an interactive challenge:

```sh
export KOLIMI_PASSWORD='app-password-here'

kolimi-sync \
  --server https://cloud.example.com \
  --user alice \
  --local ~/Kolimi \
  --remote /Kolimi
```

Use `--e2ee-root Private` for encrypted subtrees, `--e2ee-root ''` for the
whole sync root, and `--e2ee-setup` once to create the keyring. The desktop
app is available for Linux, Windows, and macOS. The Android client is
planned but parked; there is no mobile build yet.

## Admin quick reference

Administrators get an **Admin** entry in the sidebar:

- **Users** — create accounts, search/filter, edit quotas, grant/revoke
  admin, disable/enable, force sign-out, reset passwords, and delete.
- **Invites** — create one-time onboarding links with an expiry. The link is
  shown once; revoke it if it leaks.
- **Groups** — manage group rosters and deletion.
- **Audit** — inspect the hash-chained log, filter by action/subject, and
  verify the chain.

Every destructive user change and password recovery requires a fresh admin
password or two-factor proof. See [operations.md](operations.md) for the
full workflow and recovery rules.

## Troubleshooting

- Login, passkey, quota, sync, and E2EE issues:
  [operations.md#troubleshooting](operations.md#troubleshooting).
- WebDAV, CalDAV, desktop sign-in, and client connection issues:
  [clients.md#troubleshooting](clients.md#troubleshooting).
- Server/CLI flags and environment variables:
  [reference.md](reference.md).
- Install, TLS, and upgrade paths: [install.md](install.md).
