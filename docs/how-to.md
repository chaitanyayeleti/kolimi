# How-to guides

Task-first recipes for common Kolimi operations. Each recipe links to the
reference page for details rather than repeating it.

- [Account and security](#account-and-security)
- [Files and sharing](#files-and-sharing)
- [Clients and sync](#clients-and-sync)
- [Administration](#administration)
- [Deployment and recovery](#deployment-and-recovery)
- [Troubleshooting](#troubleshooting)

## Account and security

### Create the first administrator

The installer creates the admin for you. With a container or a manual
install, run the command once against the server's data directory:

```sh
kolimi-server user add admin
```

The first account is an administrator. See
[install.md](install.md#first-run) for the install-specific command.

### Invite a user

1. Sign in as an administrator and open **Admin → Invites**.
2. Choose an expiry from 1 hour to 30 days and create the link.
3. Send the link to the user. It works once; revoke it if it leaks.
4. The user sets a password, signs in, and must enroll TOTP or a passkey
   before the file browser opens.

See [operations.md](operations.md#users) for the admin workflow.

### Create a user with a temporary password

1. Open **Admin → Users** and create the account. Confirm your own admin
   password (and a current two-factor code, if enabled) when prompted.
2. Enable **Require password change at next sign-in** if you are handing
   over a temporary password.
3. Give the user the password out of band. They change it at first sign-in
   and then complete the mandatory MFA step.

CLI-created accounts are not forced into MFA; Admin-created and invited
accounts are.

### Set up TOTP or a passkey

1. Sign in. New accounts land on **Secure your account**; existing accounts
   open **Settings → Passkeys**.
2. For TOTP, scan the QR code, enter the six-digit code, and store the ten
   one-time recovery codes.
3. For a passkey, name it and confirm your account password (and a current
   TOTP/recovery code if two-factor is enabled).

Removing the last passkey from a passwordless account is refused.

### Make an account passwordless

1. Register at least one passkey in **Settings → Passkeys**.
2. Run `kolimi-server user passkey-only <user>`.
3. Confirm the passkey sign-in works. Password login is rejected afterward;
   use app passwords for sync and DAV clients.

The CLI refuses to remove the password if the account has no passkey.

### Create an app password for a client

1. Open **Settings → Passkeys → App passwords**.
2. Name the device (for example `laptop-webdav`).
3. Choose an access preset: **Sync client**, **Files read-only**,
   **Files read/write**, **Calendars & contacts**, or **Full access**.
   Prefer the narrowest preset; full access can manage the account.
4. Choose an expiry (90 days by default, or never/30 days/1 year) and
   create it. Creating a **Full access** token asks for a fresh
   re-authentication proof; the narrower presets do not.
5. Copy the token immediately; it is shown once.
6. Paste it into the WebDAV, CalDAV, desktop, or `kolimi-sync` client.
7. Revoke it here when the device is lost or retired.

New tokens default to the **Sync client** scopes and a 90-day lifetime.
Existing tokens created before scopes were introduced keep full access. If
you want least privilege, revoke and reissue them. App passwords work with
HTTP Basic even when TOTP is enabled or the account is passkey-only. See
[clients.md](clients.md#app-passwords).

### Change your password or revoke sessions

Open **Settings → Account**. A password change asks for your current
password and, if two-factor is enabled, a current TOTP/recovery code, and
signs out your other sessions. Passwords must be at least 10 characters and
are checked against a small common-password blocklist. The same
panel labels sessions and revokes one or all other devices.

### Recover a locked-out account

1. Verify the user's identity out of band. This is not self-service.
2. Run `kolimi-server user recover <user>`.
3. The command sets a new password, drops sessions, revokes app passwords,
   clears TOTP, and removes passkeys by default.
4. Have the user sign in, change the password, and re-enroll MFA.

Use `--keep-totp` or `--keep-passkeys` only when those devices are known to
be safe. See [operations.md](operations.md#account-recovery).

## Files and sharing

### Upload, organize, and restore files

- Upload with the toolbar or drag files into the window.
- Use **New folder**, list/grid, filter, sort, and search.
- Tick rows for bulk download, move, or trash.
- Open a file's **Actions → Versions** to restore an older version.
- Deleted items go to **Trash**; restore or purge them there.

Encrypted files have no server-side preview or content search. Their names
are matched locally after you unlock the keyring.

### Share a file or folder

1. Select the item and choose **Share**.
2. Pick **User** or **Group** and choose **Can view** or **Can edit**.
3. For encrypted content, unlock encryption first. The recipient must have
   unlocked Kolimi once so their key package exists.
4. Use **Revoke** in the same dialog to remove access.

A single-file write share can be replaced in place by the recipient; it
cannot be deleted from the share root.

### Create a public link

1. Choose **Share → Public link**.
2. Pick an expiry and a password mode (generated, none, or a password you
   set).
3. Copy the URL and the generated password shown once.
4. Manage or revoke the link from **Shared → Links**. Encrypted file links
   need encryption unlocked when you copy them; the key stays in the URL
   fragment and never reaches the server.

### Request files with an upload-only link

1. Choose **Share → Public link** on a **plaintext folder**.
2. Set **Link type** to **Request files (upload only)**.
3. Set the maximum number of files and total size, plus expiry and password.
4. Create the link and send it. Recipients see only an upload form; they
   cannot list, download, or overwrite files.
5. Uploads appear in the folder as ordinary files. Name collisions get
   ` (2)`, ` (3)`, and so on instead of replacing anything.
6. Track used files/bytes and revoke from **Shared → Links**.

Encrypted folders cannot accept file requests: public uploads would arrive
as plaintext, which breaks the E2EE boundary. Use a named user/group write
share for encrypted folders instead.

### Change the encryption passphrase

1. Unlock the keyring and open **Settings → Encryption**.
2. Choose **Change passphrase**, enter the new passphrase twice, and confirm
   your account password.
3. Only the passphrase wrap changes: files, recovery phrase, and other
   device wraps are untouched.

### Encrypt a folder or your whole sync folder

- **Web:** **Settings → Encryption** creates the keyring. `Vault/` is
  encrypted; **Encrypt existing names** renames already-encrypted items in
  place.
- **Desktop:** edit a pair and use **Encrypted folders** for relative
  subtrees, or **Encrypt the entire sync folder** for the pair root.
- **CLI:** use `--e2ee-root Private` for a subtree or `--e2ee-root ''` for
  the whole sync root.

Enabling encryption on a remote root that still contains plaintext is
refused. Move or delete those files first.

### Upgrade legacy shares to MLS

1. Open **Settings → Sharing**.
2. Choose **Upgrade shares to MLS**.
3. Recipients must have unlocked once so they have a key package.

Legacy per-file wraps remain readable. See
[operations.md](operations.md#sharing).

## Clients and sync

### Connect a desktop app

1. Install the desktop app from [install.md](install.md#desktop-client).
2. Open **Accounts & Sync** and add the server, username, and password.
3. Enter the current TOTP code, or use **Use current web session** for a
   passkey-only account.
4. Add a synced folder pair: local folder, remote folder, and optional
   encrypted subtrees or whole-folder encryption.
5. Enable **MLS group shares** if this desktop should join encrypted group
   shares, then choose **Sync now**.

Full details, including keychain behavior and passkey-only sign-in, are in
[clients.md](clients.md#desktop-app).

### Link a passkey-only desktop

1. Sign in to the main Kolimi window with the passkey.
2. Open **Accounts & Sync**.
3. Choose **Use current web session** for the account.

The native client exchanges the webview session for a revocable app password
and does not keep the session cookie.

### Fix a desktop that is missing from MLS devices

1. Edit the pair and enable **MLS group shares**.
2. Save and choose **Sync now**.
3. Check **Settings → Devices → MLS devices**.

The desktop publishes itself only when MLS is enabled for that pair.

### Mount WebDAV

1. Create an app password under **Settings → Passkeys**.
2. Use `https://cloud.example.com/dav/` as the URL and the account username
   plus the app password as credentials.
3. Mount with GNOME Files, Finder, Windows, davfs2, or rclone.

The full mount examples are in [clients.md](clients.md#webdav). Encrypted
folders return `403` to DAV clients; use a Kolimi client for E2EE content.

### Connect CalDAV or CardDAV

Use `https://cloud.example.com/dav/` for discovery, or the direct homes:

- Calendar: `https://cloud.example.com/dav/calendars/<user>/`
- Address book: `https://cloud.example.com/dav/addressbooks/<user>/`

Authenticate with the username and an app password. Calendars and contacts
are not E2EE. See [clients.md](clients.md#caldav-and-carddav).

### Run a scheduled CLI sync

```sh
export KOLIMI_PASSWORD='app-password-here'

kolimi-sync \
  --server https://cloud.example.com \
  --user alice \
  --local ~/Kolimi \
  --remote /Kolimi
```

The CLI is one-shot; run it from a systemd timer or watcher. TOTP and
passkey-only accounts must use an app password. Add `--e2ee-root Private` or
`--e2ee-root ''` for encrypted content.

## Administration

### Create a group and share with it

1. Open **Admin → Groups**, create the group, and add members.
2. In a file's **Share** dialog choose **Group** and the group name.
3. For encrypted folders, recipients must have unlocked once. Membership
   changes update ACLs but do not rotate MLS keys; re-share the encrypted
   folder from a client after changing members.

You can also manage groups from the CLI with
`kolimi-server group add|add-member|remove-member|delete`.

### Set or change a quota

```sh
kolimi-server user quota alice 10737418240   # bytes
kolimi-server user quota alice unlimited
kolimi-server user quota alice default
kolimi-server user usage alice --reconcile
```

The web UI shows the storage ring; the admin Users table marks near/over
quota. See [operations.md](operations.md#users).

### Disable, sign out, or delete a user

- **Disable** from **Admin → Users** or `kolimi-server user disable <user>`.
  Existing sessions stop working; the account can be re-enabled.
- **Force sign-out** drops live sessions without disabling the account.
- **Delete** from **Admin → Users**, or with
  `kolimi-server user delete <user> --yes`. It removes the account, files,
  shares, DAV data, E2EE keys, and blobs.

You cannot disable or delete your own account, and the last enabled
administrator is protected.

### Verify the audit log

```sh
kolimi-server audit list --limit 50
kolimi-server audit verify
```

The same views are under **Admin → Audit**; **Verify chain** recomputes the
hash chain. See [operations.md](operations.md#audit-log) for checkpoints,
signing, and anchoring.

### Sign and anchor audit checkpoints

Available in **0.7.1+**. Back up the data directory before upgrading; 0.7.1
adds migration `0038`. Signing is local — no external service is required.
Anchoring is optional and is the part that publishes the signed head somewhere
the server cannot rewrite.

1. Generate a key outside the data directory:

   ```sh
   sudo -u kolimi kolimi-server audit keygen \
     --out /etc/kolimi/audit-signing.key --label main
   sudo chmod 600 /etc/kolimi/audit-signing.key
   ```

2. Add `KOLIMI_AUDIT_SIGNING_KEY=/etc/kolimi/audit-signing.key` to the
   server environment and restart. Sealing now signs every new checkpoint.
   Backfill old ones with:

   ```sh
   kolimi-server audit sign --key /etc/kolimi/audit-signing.key --all
   ```

3. Verify against the public key you keep somewhere outside the server:

   ```sh
   kolimi-server audit verify --trusted-key <hex-public-key> --require-signatures
   ```

   Expected output includes:

   ```text
   signatures: 1 signed, 1 verified, 0 unsigned, 0 untrusted, 0 errors (trust: trusted-keys)
   ```

   `audit verify` exits `1` if the entry chain, a checkpoint, a trusted
   signature, or an anchored head does not match. `--require-signatures` also
   fails any checkpoint that has no valid trusted signature. Without
   `--trusted-key`/`--trusted-keys`, it reports signature counts but does not
   verify them cryptographically. A trusted-keys file has one line per key:

   ```text
   <key_id> <public_key_hex> [label]
   ```

4. Optionally publish heads. A mounted journal:

   ```sh
   KOLIMI_AUDIT_ANCHOR_LOG=/mnt/audit-anchors/kolimi.jsonl
   ```

   or an HTTPS sink:

   ```sh
   KOLIMI_AUDIT_ANCHOR_URL=https://anchors.example.net/kolimi
   KOLIMI_AUDIT_ANCHOR_TOKEN=...
   ```

   Then verify against a copy of that log:

   ```sh
   kolimi-server audit verify --trusted-keys FILE \
     --anchor-log /mnt/audit-anchors/kolimi.jsonl
   ```

   Check delivery and retry pending records with:

   ```sh
   kolimi-server audit anchors list
   kolimi-server audit anchors flush
   ```

   Enabling anchoring later does not backfill the outbox; publish the current
   head once with `kolimi-server audit head` (one head commits to the whole
   earlier chain).

5. Verify an exported retention bundle independently:

   ```sh
   kolimi-server audit verify-export --file audit-12.jsonl \
     --trusted-key <hex-public-key>
   ```

The janitor seals automatically at 1,024 pending entries or when the oldest
unsealed entry is older than 24 hours. Override the age with
`KOLIMI_AUDIT_SEAL_AGE_SECS`; set it to `0` to disable the age trigger.

If a configured key cannot be loaded, sealing is refused rather than writing
unsigned checkpoints. A journal on the server's own disk adds no protection;
use WORM/object-lock storage or a second host. Details and rotation:
[operations.md](operations.md#signing-checkpoints).

With the Traefik/Docker stack in `packaging/docker/compose.traefik.yaml`, the
container runs as UID `65532` (distroless nonroot). Mount the key read-only and
set the path in the `kolimi` service:

```yaml
    environment:
      KOLIMI_AUDIT_SIGNING_KEY: /run/secrets/audit-signing.key
    volumes:
      - kolimi-data:/data
      - /etc/kolimi/audit-signing.key:/run/secrets/audit-signing.key:ro
```

The host file must be owned by `65532` with mode `0600`:

```sh
sudo install -m 600 -o 65532 -g 65532 audit-signing.key \
  /etc/kolimi/audit-signing.key
```

Generate the key on the host or another machine, not inside the container's
`/data` volume. This compose file lists environment variables explicitly, so
putting `KOLIMI_AUDIT_SIGNING_KEY` only in `.env` is not enough unless the
service references it as `${KOLIMI_AUDIT_SIGNING_KEY}`.

### Scrape metrics

On 0.5.1+, set `KOLIMI_METRICS_TOKEN` in the server environment (systemd
`/etc/kolimi/kolimi.env`, Compose `.env`, or the Helm
`metrics.existingSecret` value) and use it as a bearer token:

```yaml
scrape_configs:
  - job_name: kolimi
    scheme: https
    bearer_token: <KOLIMI_METRICS_TOKEN>
    static_configs:
      - targets: ["cloud.example.com"]
```

The token works only on `/metrics`. Alternatively, scrape with an admin
username and an **app password** over HTTP Basic. The browser shows an HTML
dashboard; append `?format=text` for Prometheus text. Setup details are in
[metrics.md](metrics.md#enable-the-metrics-token); the catalog and alert
examples are in [metrics.md](metrics.md).

### Back up and restore

```sh
kolimi-server backup --data /var/lib/kolimi --to /backups/kolimi-2026-10-11
kolimi-server verify --data /var/lib/kolimi
```

To restore, stop the server, replace the data directory with the backup,
start the server, and run `verify` again. Migrations are forward-only, so
keep the pre-upgrade backup. See
[operations.md](operations.md#backup-and-restore).

### Upgrade safely

1. Take an online backup and verify it.
2. Stop the service, replace the binary, and start it.
3. Run `kolimi-server verify`.
4. Check the changelog for migrations and client-version notes.

Do not downgrade across a migration. See
[install.md](install.md#upgrading) and
[plans/releases.md](plans/releases.md).

## Deployment and recovery

### Configure TLS or a reverse proxy

Use direct TLS flags, or terminate TLS at a trusted proxy and set
`KOLIMI_SECURE_COOKIES=true` and `KOLIMI_TRUST_PROXY=1`. `KOLIMI_ORIGIN`
must exactly match the public URL or passkeys will fail. See
[install.md](install.md#tls-and-reverse-proxies).

### Reset a lost browser MLS state

1. Open **Settings → Sharing**.
2. Choose **Reset this browser's MLS state** and confirm.
3. Sync or unlock from a working device on the same account so it re-adds
   the browser.

Only the browser's sealed MLS slot is deleted; files, keyring, and recovery
phrase are untouched.

### Revoke a lost MLS device

```sh
kolimi-sync ... --mls-devices
kolimi-sync ... --mls-revoke-device <DEVICE_ID>
```

For a recipient's device in a share you own, add `--with <user>`. The web
roster is under **Settings → Devices**. Revocation protects future epochs;
already-downloaded plaintext cannot be recalled.

## Troubleshooting

| Problem | First check |
| --- | --- |
| WebDAV returns `401` | Use an app password, especially when TOTP is enabled. |
| Sync or DAV returns `403` | Complete forced password change or **Secure your account** MFA setup. |
| Desktop is missing from MLS devices | Enable **MLS group shares** on the pair and sync. |
| Encrypted files show `k1_…` in DAV | Expected; generic DAV clients cannot decrypt. |
| Previews fail | Check kernel Landlock support; the worker fails closed. |
| Sync conflict | The server version wins; the local edit is kept as `.conflict-*`. |
| Account locked out | Wait for the 15-minute lockout, or use admin recovery. |

More detail is in [operations.md](operations.md#troubleshooting) and
[clients.md](clients.md#troubleshooting).
