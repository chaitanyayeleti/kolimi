# Using Kolimi

Day-to-day guide for the web UI, desktop app, and sync client. Server
administration lives in [operations.md](operations.md); flags and endpoints
are in [reference.md](reference.md).

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
  the account keyring.
- **Sharing** — upgrade legacy per-file folder shares to MLS groups.
- **Devices** — review MLS devices and revoke one that is lost or untrusted.
- **Passkeys** — register or remove passkeys and enable TOTP/recovery codes.

Email is informational only. Kolimi does not send mail or use it to sign in.
Account recovery through an administrator is separate from losing the
encryption passphrase; see [operations.md](operations.md#account-recovery).

## Files and folders

- Upload with the toolbar or by dropping files into the window.
- Use **New folder**, the list/grid toggle, and search to navigate.
- Right-click a file or folder (or use its action buttons) to rename,
  download, share, delete, or open its version history.
- Deleted items go to **Trash** and can be restored or purged.
- **Shared with me** appears as a mount in the sidebar. Read-only shares
  cannot be changed; write shares can be edited in place.

Encrypted content is marked **Encrypted** in the file list. If a folder is
locked, unlock the keyring first. Encrypted names are decrypted locally.

## Sharing

Use **Share** on a file or folder:

- **User** — share with one account.
- **Group** — share with every member of a group.
- **Public link** — create a URL with an optional password and expiry.

Permissions are **read** or **write**. Write shares work for encrypted
folders and single files; the web UI can download single-file shares but has
no inline editor for them.

For encrypted content, the recipient must have unlocked Kolimi at least once
so their key package exists. Group membership changes update share ACLs and
wrapped keys but **do not rotate MLS keys**: after adding or removing a
member, re-share the affected encrypted folders from a client so the keyring
advances. Revoking a share cannot erase data a recipient already downloaded.

## Desktop app and sync

The desktop app loads the server's web UI in a native window and adds the
tray menu, background sync, and OS keychain storage. Create a local folder
pair from **Accounts & Sync**; the tray shows idle, syncing, paused, and
error states.

The `kolimi-sync` CLI mirrors a local directory:

```sh
kolimi-sync \
  --server https://cloud.example.com \
  --user alice \
  --local ~/Kolimi \
  --remote /
```

Use `--e2ee-root` for encrypted subtrees and `--e2ee-setup` once to create
the keyring. The desktop app is available for Linux, Windows, and macOS.
The Android client is planned but parked; there is no mobile build yet.

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
- Server/CLI flags and environment variables:
  [reference.md](reference.md).
- Install, TLS, and upgrade paths: [install.md](install.md).
