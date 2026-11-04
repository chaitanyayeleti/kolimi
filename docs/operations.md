# Operating Kolimi

Day-2 administration for a running server. Commands read `KOLIMI_DATA`
(default `./kolimi-data`); on systemd hosts that is `/var/lib/kolimi`.

## Users

```sh
kolimi-server user add alice                 # prompts for a password
kolimi-server user add alice --admin         # grant admin
kolimi-server user passwd alice              # change the password
kolimi-server user list                      # id, name, flags
kolimi-server user passkey-only alice        # drop the password (needs >= 1 passkey)
kolimi-server user totp-disable alice        # admin escape hatch when codes are lost
kolimi-server user recover alice             # new password + reset 2FA
kolimi-server user disable alice             # block logins, drop live sessions
kolimi-server user enable alice              # restore access
kolimi-server user delete alice --yes        # delete the user and everything they own
kolimi-server user quota alice 10737418240   # per-user storage quota (bytes)
kolimi-server user quota alice unlimited     # no limit
kolimi-server user quota alice default       # fall back to the server default
kolimi-server user usage alice               # used vs quota (cached counter)
kolimi-server user usage alice --reconcile   # recompute usage from disk
```

The first account created is an administrator. `user delete` removes the
account and everything it owns: sessions, passkeys, the file tree, shares,
DAV collections, E2EE keys and group memberships (database rows cascade),
**and the user's blob data on disk**. Audit entries are preserved with a
null actor. `user disable` takes effect immediately (existing sessions stop
working) and is the reversible alternative.

Passkeys are registered in the web UI (toolbar → **Passkeys**). A
passkey-only account signs in through WebAuthn; password login is rejected
(and audited).

## Account recovery

A user who has lost **every** passkey *and* the recovery code — or has a
forgotten password while TOTP is still enrolled — cannot sign in. Recovery
is a **privileged** action and requires **out-of-band verification of the
user's identity** first; it is not a self-service flow.

```sh
kolimi-server user recover alice             # prompts for a new password
```

`user recover` sets a new password, drops all of the account's live
sessions (so a lost or compromised credential cannot keep a session
alive), and by default **clears TOTP** so the new password alone works.
Options:

- `--keep-totp` — keep two-factor enabled (the user must still have codes).
- `--remove-passkeys` — also delete every registered passkey so the user
  re-enrols fresh (use if a device was lost or the account was compromised).

The action is recorded in the audit log as `user.recover`. Afterwards, have
the user sign in with the new password and re-enrol their passkey and
two-factor from the **Passkeys** panel.

The same operations are available to an authenticated administrator over
HTTP (JSON API, `Authorization: Basic` or a session cookie):

```sh
curl -u admin:pw https://cloud.example.com/api/users                 # list
curl -u admin:pw -X POST -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"…"}' https://…/api/users      # create
curl -u admin:pw -X PATCH -H 'Content-Type: application/json' \
  -d '{"disabled":true}' https://…/api/users/alice                   # disable
curl -u admin:pw -X PATCH -H 'Content-Type: application/json' \
  -d '{"admin":true}' https://…/api/users/alice                      # grant admin
curl -u admin:pw -X DELETE https://…/api/users/alice                 # delete
curl -u admin:pw 'https://…/api/users?limit=100'                     # paginated list
curl -u admin:pw https://…/api/users/alice/usage                     # fresh usage
curl -u admin:pw -X PATCH -H 'Content-Type: application/json' \
  -d '{"quota_bytes":10737418240}' https://…/api/users/alice          # set quota
```

Listing users is **paginated** (`?cursor=<id>&limit=`) and returns the
cached `quota_bytes`/`used_bytes` columns, so it stays a single indexed
query even with thousands of users; the per-user `/usage` endpoint is the
only one that walks the blob store.

Guards (both CLI and API): you cannot disable or delete your own account,
and the **last enabled administrator** cannot be disabled, demoted or
deleted — so the server always keeps an administrator.

## Groups and sharing

```sh
kolimi-server group add team
kolimi-server group add-member team alice
kolimi-server group list
kolimi-server group remove-member team alice
kolimi-server group delete team
```

Shares are created from the web UI (share dialog), the desktop app, or the
sync client for E2EE content (`kolimi-sync --share … --with bob|--group team`).

- **Plaintext shares** use the normal per-user/group/link ACLs.
- **Encrypted files** use v1/v2 per-file wrapping when MLS is off: the
  owner wraps the file key for each recipient, and the recipient decrypts
  on the next sync. With MLS enabled, a single file gets its own node
  group; legacy wraps stay readable.
- **Encrypted folders** use MLS when the client enables it (`--mls`, web
  default on, desktop pair option). The group is node-scoped; adding or
  removing a member advances the epoch and re-encrypts the share keyring.
- **Write shares** (`--write`, or permission *write* in the share dialog)
  work for encrypted folders and single files. A folder writer can
  add/edit/delete children through the web UI, desktop or CLI. A
  single-file writer can replace the file through the CLI/desktop or a
  WebDAV `PUT`, but cannot delete the share root; the web UI currently
  downloads single-file shares without an inline editor.
- `--unshare` / **Revoke** removes the ACL, drops the recipient's leaves
  for MLS, and rotates the keyring. Removing a **group** member deletes
  their v1 wrapped keys and revokes group-share access, but MLS membership
  is client-side: after changing a group, revoke/re-share from a client so
  the device is removed and the keyring rotates. A removed member keeps
  any plaintext they already downloaded; revocation cannot recall it.

The CLI details are in [reference.md](reference.md#kolimi-sync).

## Two-factor and recovery

- TOTP: 6-digit RFC 6238 codes, ten one-time recovery codes shown once
  at enrollment. Lost everything? `user totp-disable` (admin).
- Passkeys: up to 20 per account; lost all of them? An admin
  can set a password (`user passwd`) and the user registers new ones.
- E2EE: the keyring has passphrase + recovery code (+ optional passkey
  PRF) wraps. Losing **all** wraps means the data is unrecoverable —
  there is no server-side escrow by design.

## Backup and restore

```sh
# Online backup: consistent SQLite snapshot + blob store copy.
kolimi-server backup --data /var/lib/kolimi --to /backups/kolimi-2026-10-11

# Integrity: verifies every manifest and chunk hash.
kolimi-server verify --data /var/lib/kolimi
```

Restore: stop the server, replace the data directory with the backup,
start the server (migrations run at startup), then `verify`.

```sh
sudo systemctl stop kolimi
sudo rm -rf /var/lib/kolimi && sudo cp -a /backups/kolimi-2026-10-11 /var/lib/kolimi
sudo chown -R kolimi:kolimi /var/lib/kolimi
sudo systemctl start kolimi
kolimi-server verify --data /var/lib/kolimi
```

The background janitor also re-verifies blobs incrementally (BLAKE3)
and audits any corruption as `scrub.corrupt`; `verify` is the full
on-demand check.

## Audit log

Append-only, hash-chained; every entry hashes the previous one, so
edits, deletions and reordering are detectable.

```sh
kolimi-server audit list --limit 50    # JSON lines, newest first
kolimi-server audit verify             # exits 1 and names the first bad entry
```

Events cover logins and failures, logouts, passkeys, TOTP, file
mutations (via the change feed), shares, link unlocks/downloads, E2EE and
MLS key operations, preview-worker failures, and CLI changes. Content and
file bytes are never logged.

## Metrics

`GET /metrics` (Prometheus text format) on the server port:
request counts and latency histograms by route template, uploads,
preview outcomes, login failures. Labels never contain paths, file
names or user identifiers. `/healthz` is the liveness endpoint.

Opening `/metrics` in a browser (which sends `Accept: text/html`) shows a
read-only **HTML dashboard** instead — metric families as cards, with a
15-second auto-refresh; append `?format=text` to force the Prometheus
format. Scrapers (no `text/html` in `Accept`) always get the text format.

`/metrics` is **administrators only**. A signed-in admin can open it in
the browser; a scraper authenticates with HTTP Basic using an admin's
username and password. Non-admins get `403`, anonymous requests `401`. A
passkey-only (passwordless) admin cannot scrape, so point Prometheus at
an admin account that still has a password.

```yaml
scrape_configs:
  - job_name: kolimi
    scheme: https
    basic_auth:
      username: admin
      password: <admin password>
    static_configs:
      - targets: ["cloud.example.com"]
```

### Storage-usage metrics

`/metrics` also exposes `kolimi_users_by_usage_bucket{bucket}` — a
low-cardinality count of accounts by how full their quota is
(`0`, `1-50`, `50-90`, `90-100`, `over`, `unlimited`). Per-user gauges
(`kolimi_user_used_bytes{user}`) are **opt-in** via
`KOLIMI_METRICS_PER_USER=1` because they scale with the account count.

### Tracing (OpenTelemetry)

Traces are optional. Build the server with the `otel` feature and set
`KOLIMI_OTEL_ENDPOINT` to an OTLP/gRPC collector:

```sh
KOLIMI_OTEL_ENDPOINT=http://localhost:4317 kolimi-server serve
```

Without the feature or the env var, only the normal `fmt` logs are
emitted. Request spans come from the existing `tracing`/`tower-http`
instrumentation.

### Quota warnings

When a commit pushes an account to or over **90%** of its effective
quota, the server emits a `quota.warn` audit event and adds an
`X-Kolimi-Quota-Warning` header (the usage percentage) to the commit
response; the web UI shows a toast. `GET /api/users/{name}/usage` returns
`over_quota`, `warning`, `warning_percent` and `used_percent`, and the
admin panel marks near/over-quota accounts. `GET /api/users` accepts
`sort` (`id`, `username`, `used_bytes`, `quota_bytes`), `order`
(`asc`/`desc`) and `filter` (`over_quota`, `disabled`, `admin`).

## Hardening

- **Rate limiting.** Login, passkey ceremonies, public-link unlocks,
  previews and MLS requests are limited per client address (20 auth
  attempts / 5 min, 30 unlocks / 5 min, 120 previews / min, 600 MLS
  requests / 5 min), returning `429` with `Retry-After`. Behind a trusted
  reverse proxy, set `KOLIMI_TRUST_PROXY=1` so the client address comes
  from `X-Forwarded-For` instead of the proxy.
- **Login lockout** additionally locks an account for 15 minutes after
  5 failed attempts, and login responses are deliberately uniform and
  timing-equalised so failures do not reveal whether a username exists.
- **Security headers.** Every response carries
  `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`;
  `Strict-Transport-Security` is added when secure cookies are enabled.
  The web UI additionally sends a strict `Content-Security-Policy`.
- **Per-user storage quota.** `KOLIMI_USER_QUOTA_BYTES` is the server
  default (`0` = unlimited); each account may override it (`0` = unlimited,
  `NULL` = default) via the admin API/CLI. Uploads that would exceed a
  user's quota are refused with `413`. Usage is a **cached counter**
  (`users.used_bytes`) incremented by newly written bytes and decremented
  on GC; the janitor reconciles a bounded batch of counters from disk each
  pass to correct drift. Deduplicated re-uploads count conservatively.
- **Event streams.** At most 64 concurrent `/api/sync/events` SSE
  connections are served (further ones get `503`), and each is closed
  after 30 minutes.
- **Information exposure.** `/version` requires authentication — use
  `/healthz` for unauthenticated liveness. Group rosters
  (`/api/groups/{name}/members`) are only visible to the group's members
  and administrators; wrapping E2EE keys for a group requires the sharer
  to be a member.

## E2EE and MLS operations

### Setup

- **Web:** the first login offers **Set up your Vault** (or open
  *Settings → Encryption*). The passphrase and recovery phrase are handled
  locally; the server receives only wrapped key material. `Vault/` is
  encrypted by default.
- **CLI:** create the keyring once and store the printed recovery code
  offline:

  ```sh
  KOLIMI_E2EE_PASSPHRASE='…' kolimi-sync \
    --server https://cloud.example.com --user alice --local ~/Kolimi \
    --e2ee-setup
  ```

- **Desktop:** the **Accounts & Sync** window sets/unlocks the E2EE
  passphrase; it does not create a new keyring. Use the web or CLI for
  first-time setup.

### Encrypted content

- Only configured subtrees are encrypted: `--e2ee-root Private` in the
  CLI, `encrypted_roots` in a desktop sync pair, or `Vault/` in the web UI.
- The server stores ciphertext, wrapped per-file keys and an encrypted
  keyring it cannot read. Names can be encrypted (`k1_…`); sizes,
  timestamps, structure and access patterns remain visible.

### Sharing

- **Files (v1/v2, or a one-file MLS group with `--mls`):**

  ```sh
  kolimi-sync ... --share Private/doc.txt --with bob
  kolimi-sync ... --unshare --share Private/doc.txt --with bob
  ```

  Without MLS, the owner wraps the file key for each recipient.
  Recipients pull a decrypted copy under `Shared with me/`. `--group team`
  wraps for every group member. With `--mls`, the file gets its own node
  group; add `--write` to let the recipient replace it.

- **Encrypted folders (MLS):**

  ```sh
  kolimi-sync ... --mls --share Private/Team --with bob
  kolimi-sync ... --mls --write --share Private/Team --with bob
  kolimi-sync ... --mls --write --share Private/doc.txt --with bob
  ```

  The owner creates a node-scoped MLS group and an epoch-bound keyring.
  Bob joins from the Welcome on his next sync. `--write` allows edits;
  without it the share is read-only. Write shares work for folders and
  single files (the file is replaced in place).

  The web UI enables MLS for encrypted folder shares by default (set
  `localStorage["kolimi-mls"]="0"` to disable). The desktop pair needs
  `mls: true` or the Share action, which forces MLS.

- **Migration:** `kolimi-sync ... --mls-migrate` promotes existing
  encrypted folder shares; the web UI has *Settings → Encryption → Upgrade
  shares to MLS*. Legacy per-file wraps stay readable.

### Unlock and devices

- Unlock with the passphrase, recovery code, or a platform passkey-PRF
  output. The web client keeps sealed MLS state in IndexedDB after unlock;
  the CLI/desktop use `.kolimi/` and the OS keychain (or `0600` fallback).
- Enroll another device without re-typing the passphrase:

  ```sh
  # new device: prints id + approval code, then waits
  kolimi-sync ... --e2ee-enroll laptop

  # already-unlocked device: compare the code, then approve
  kolimi-sync ... --e2ee-approve <id> --e2ee-code <code>
  ```

  The web UI has a **Devices** panel for the same flow. `--e2ee-forget-device`
  removes local key material; the device must be enrolled again.

- **Lost or corrupt MLS state:** delete only the sealed MLS state and let
  the next sync create a new MLS device:

  ```sh
  kolimi-sync ... --mls-reset            # asks you to type "reset"
  kolimi-sync ... --mls-reset --yes      # non-interactive
  kolimi-sync ... --mls --e2ee-root Private   # publishes a new key package
  ```

  The first sync after a reset may report that a share has no Welcome for
  the new device. The next sync (or browser unlock) by a working device on
  the same account notices the fresh key package and re-adds the device
  automatically at a new epoch, rotating the keyring; the reset device joins
  on its following sync. A scoped sync only refreshes shares under its root.
  Re-sharing manually (`--mls --share … --with <user>`) remains the fallback
  when no working member is online, and if the lost device was the only owner
  device the share must be recreated. The old device leaf remains until it is
  removed; a removed member keeps any plaintext or keys already downloaded.

  In the browser, use **Settings → Encryption → Reset this browser's MLS
  state** (also confirms first). It deletes only this browser's sealed MLS
  slot; the E2EE keyring, recovery phrase and files are untouched. The next
  sync/unlock by a working device on the same account re-adds the browser.

- **Revoking a lost MLS device:** list the account roster, then revoke one
  device by id:

  ```sh
  kolimi-sync ... --mls-devices
  kolimi-sync ... --mls-revoke-device <DEVICE_ID>          # prompts
  kolimi-sync ... --mls-revoke-device <DEVICE_ID> --yes    # automation
  ```

  The command removes the device's MLS leaf from every group this client can
  write, rotates each share keyring, and only then deletes the roster row and
  unpublished key packages. The web UI has the same roster under
  **Settings → Encryption → MLS devices** with a revoke action. A removed
  device keeps any
  plaintext and file keys it already downloaded; revocation protects future
  epochs only.

  A device in a **read-only received share** cannot commit its own removal.
  The share owner must remove it first, or the share must be recreated:

  ```sh
  # run as the share owner; --with selects the recipient
  kolimi-sync ... --mls-devices --with bob
  kolimi-sync ... --mls-revoke-device <BOB_DEVICE_ID> --with bob
  ```

  The owner's removal records a per-group revocation, so automatic re-add
  skips that signature even if the device still has key packages. An explicit
  re-share clears the revocation. The recipient then retries
  `--mls-revoke-device` to clear their roster entry. If no remaining member
  can open a group, the command stops and the share must be recreated.

### Limitations

- **MLS is not externally audited.** See
  [audit/mls-delta.md](audit/mls-delta.md); the openmls `cargo-vet`
  exemptions are temporary.
- A removed member keeps plaintext and file keys already downloaded. The
  epoch rotation protects new keyrings/files, not the past.
- Losing the sealed device state (or deleting browser IndexedDB) loses the
  device's group membership. `--mls-reset` clears the local state; the next
  sync/unlock by a working device on the same account re-adds the fresh
  device. If no working member is online, or the lost device was the only
  owner device, the share must be manually recovered or recreated.
- Concurrent commits are serialized by the server: the second commit at
  the same parent epoch gets `409`. Clients stage commits locally and merge
  only after acceptance; the loser discards its pending state and replays
  the winning epoch. A commit and its Welcome are appended atomically.
- An account may have at most 16 active MLS devices in the server roster
  (180-day inactivity window), and each device may have at most 8 live key
  packages. Revoke an old device to free a roster slot immediately (see
  above); otherwise it ages out after 180 days of inactivity.
- A client older than the revoke release ignores group revocation records
  and may re-add a revoked device from its leftover key packages. Update
  every device that auto-refreshes before relying on revoke.
- Unused MLS key packages expire after 30 days; the janitor removes
  consumed/expired rows after a further seven-day grace period.
- Clients report the last epoch they processed (`POST /api/mls/epoch`).
  The janitor removes messages and keyrings below the minimum fresh report
  after a seven-day grace period. A device that has not reported for 30
  days is ignored, so an offline device older than that must rejoin rather
  than replay the whole history.
- A device that has already lost its local state cannot report; re-add it
  with the reset flow above.

## Recovery secrets

Kolimi has **three independent recovery secrets** — don't confuse them:

| Secret | What it recovers | How to use |
| --- | --- | --- |
| **Login password** | Account access (auth only) | An admin resets it: `kolimi-server user recover <user>`. Sessions are dropped; **no encrypted data is touched**. |
| **TOTP recovery codes** | Second factor at login | Shown **once** at TOTP enrollment (10 codes, one-time). Enter one in the login **“two-factor or recovery code”** field when you lose your authenticator. Re-enroll TOTP for a fresh set. |
| **E2EE recovery code** | The E2EE keyring (master key) | Shown **once** at web Vault setup or `kolimi-sync --e2ee-setup`. In the web UI: **Encryption → “Use recovery code”**; on the CLI: `kolimi-sync --e2ee-recovery <code>`. |

There is **no self-service password reset** — only an administrator can
reset a login password. If a user loses every credential, an admin runs
`kolimi-server user recover <user>` (add `--keep-totp` or
`--remove-passkeys` as needed); the user then re-enrols 2FA.

**Important:** losing the E2EE passphrase *and* the E2EE recovery code
makes the encrypted files unrecoverable — the server holds no keys and
cannot help. A password reset never affects encrypted content (it is
wrapped under the E2EE keyring, not the login password). MLS device state
has the same property: if it is lost, re-add the device from another
member.

## Desktop and mobile clients

- **Desktop** (`apps/kolimi-desktop`): a native Tauri window loads the
  server's `/app/` UI, with a tray and background sync. Sign in to one or
  more accounts and add several synced folders per account from the in-app
  **Accounts & Sync** window (tray → *Accounts & Sync…*). It writes
  `desktop.json` under the platform config directory:
  `~/.config/kolimi/` on Linux, `%APPDATA%\kolimi\` on Windows, and
  `~/Library/Application Support/kolimi/` on macOS.

  ```json
  {
    "version": 2,
    "autostart": false,
    "accounts": [
      {
        "server": "https://cloud.example.com",
        "username": "alice",
        "auto_approve_devices": true,
        "pairs": [
          {
            "local_dir": "/home/alice/Kolimi",
            "remote": "/",
            "encrypted_roots": [],
            "mls": false
          }
        ]
      }
    ]
  }
  ```

  Each **pair** mirrors one local folder to a remote subfolder (`remote`,
  default the account root `/`). Sync runs at startup, every five minutes,
  and on demand. Closing the window hides it to the tray; *Quit* exits.
  Autostart launches it hidden (`--hidden`). The autostart checkbox is
  implemented with XDG autostart on Linux; on Windows/macOS use the OS
  login-item settings until native integration lands.

  The account password and E2EE passphrase are kept in the **system
  keychain** (Secret Service via zbus on Linux; Credential Manager /
  Keychain on Windows/macOS), keyed by `username@server`. If no keychain is
  running they fall back to the Linux **kernel session keyring** (`keyctl`),
  session-only and never written to disk. Only when neither is available
  (headless with no keyutils) do they fall back to the `0600` config file,
  and the app warns; treat that file like `.netrc`. `KOLIMI_DESKTOP_CONFIG`
  overrides the path. The config file itself contains no secrets when a
  keychain or session keyring is available.

- **CLI** (`kolimi-sync`): one-shot sync; run it from a timer or watcher.
  `--remote /Docs` mirrors a local folder to a server subfolder; also
  `--e2ee-setup`, `--share/--unshare`, `--group`, `--mls`, `--write`.

- **Mobile:** `kolimi-ffi` exposes `sync_once` and E2EE setup/unlock to
  Kotlin/Swift wrappers; background scheduling is platform code. The
  Android plan is [plans/android.md](plans/android.md).

- **WebDAV / CalDAV / CardDAV:** any client. WebDAV is class 2: byte
  ranges, streamed reads and `LOCK`/`UNLOCK` make it usable as a mounted
  network drive (Windows Explorer, macOS Finder, GNOME Files, davfs2/gvfs,
  `rclone mount`) and as a backup destination. `quota-used-bytes` /
  `quota-available-bytes` report free space. CalDAV and CardDAV cover
  calendars and contacts (Thunderbird, iOS/macOS, DAVx5). Prefer a
  dedicated account per device until per-device app passwords land.

## Upgrades

See [install.md#upgrading](install.md#upgrading). Migrations are
forward-only; back up first and do not downgrade across a migration.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Blank page at `/app/` | A release binary was built without the web UI. Run `scripts/build-ui.sh` before `cargo build`, or use the official image/release (which stage it automatically). Debug builds read the staged assets from disk. |
| Passkey registration fails | `KOLIMI_ORIGIN` does not match the URL you visit (scheme + host + port). Fix and restart. |
| Cookies not sent over HTTPS | Set `KOLIMI_SECURE_COOKIES=true` (and ensure the proxy forwards `https`). |
| 413 on uploads | The reverse proxy's body limit; set `client_max_body_size 0` (nginx) and `proxy_request_buffering off`. |
| Upload fails at exactly 60s with `500` | Traefik's default `readTimeout` is 60s. Set `transport.respondingTimeouts.readTimeout: 0` (or a high value) on the HTTPS entrypoint and restart Traefik; `idleTimeout` still drops stalled connections. |
| Previews fail with 422/415 | Unsupported format, encrypted file (no server-side preview by design), or a kernel without Landlock (the worker still runs under seccomp/rlimits). |
| “too many failed attempts” | Login lockout (5 failures / 15 min, keyed on account **and** client address) or per-client rate limiting on auth/link/MLS endpoints; wait it out, then check the audit log for `auth.login_failed` reasons. |
| Sync reports conflicts | Expected when both sides edited a file: the server version wins and your edit is kept as `name.conflict-<ts>`. |
| “no MLS key package” / recipient cannot decrypt | The recipient has not unlocked once with MLS enabled. Have them open the web UI or run `kolimi-sync` once; the next owner sync/unlock re-adds their device. |
| “MLS device limit reached” | The account has 16 active MLS devices in the 180-day roster. List them with `--mls-devices` and revoke an old one with `--mls-revoke-device`, or wait for inactivity pruning. |
| “still a member of read-only share(s)” | The device is in a received share where this client cannot commit. Ask that share's owner to run `--mls-revoke-device <id> --with <you>`, or recreate the share; then retry the self-revoke. |
| “MLS key-package limit reached” | One device has 8 live packages, usually because a client is retrying or multiple clients share a device id. Wait for expiry/consumption or use the reset flow to create a fresh device. |
| MLS keyring 409 / “stayed busy” | Another device updated the same epoch keyring. Retry; the clients already retry a bounded number of times. If it persists, check for two active committers. |
| MLS state lost after clearing storage | IndexedDB/`.kolimi` is the device's group state; it cannot be reconstructed. Use **Settings → Encryption → Reset this browser's MLS state** (web) or `--mls-reset --yes`, then let a working device sync; if none is online, have a member re-share the folder. |
| Server won't start after upgrade | Restore the pre-upgrade backup (migrations are forward-only). |
| Disk filling on a Docker host | The BuildKit build cache and old images dominate. Inspect with `docker system df -v`; bound with `docker builder prune --keep-storage 6GB` and `docker image prune -a`. App data is the `kolimi-data` volume. |

Logs go to stderr; with systemd: `journalctl -u kolimi -f`.
