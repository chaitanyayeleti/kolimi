# Operating Kolimi

Day-2 administration for a running server. Commands read
`KOLIMI_DATA` (default `./kolimi-data`); on systemd hosts that is
`/var/lib/kolimi`.

## Users

```sh
kolimi-server user add alice                 # prompts for a password
kolimi-server user add alice --admin         # grant admin
kolimi-server user passwd alice              # change the password
kolimi-server user list                      # id, name, flags
kolimi-server user passkey-only alice        # drop the password (needs >= 1 passkey)
kolimi-server user totp-disable alice        # lose TOTP codes? admin escape hatch
kolimi-server user recover alice             # lost everything? new password + reset 2FA
kolimi-server user disable alice             # block logins, drop live sessions
kolimi-server user enable alice              # restore access
kolimi-server user delete alice --yes        # delete the user and everything they own
kolimi-server user quota alice 10737418240   # per-user storage quota (bytes)
kolimi-server user quota alice unlimited     # no limit
kolimi-server user quota alice default       # fall back to the server default
kolimi-server user usage alice               # used vs quota (cached counter)
kolimi-server user usage alice --reconcile   # recompute usage from disk
```

`user delete` removes the account and everything it owns: sessions,
passkeys, the file tree, shares, DAV collections, E2EE keys and group
memberships (database rows cascade), **and the user's blob data on disk**
is deleted with it. Audit entries are preserved with a null actor. `user
disable` takes effect immediately (existing sessions stop working) and is
the reversible alternative.

Passkeys are registered in the web UI (toolbar → **Passkeys**). A
passkey-only account signs in through WebAuthn; password login is
rejected (and audited).

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
curl -u admin:pw 'https://…/api/users?limit=100'                     # paginated list (+ quota/used)
curl -u admin:pw https://…/api/users/alice/usage                     # fresh usage for one user
curl -u admin:pw -X PATCH -H 'Content-Type: application/json' \
  -d '{"quota_bytes":10737418240}' https://…/api/users/alice          # set quota (null = default)
```

Listing users is **paginated** (`?cursor=<id>&limit=`) and returns the
cached `quota_bytes`/`used_bytes` columns, so it stays a single indexed
query even with thousands of users; the per-user `/usage` endpoint is the
only one that walks the blob store.

Guards (both CLI and API): you cannot disable or delete your own
account, and the **last enabled administrator** cannot be disabled,
demoted, or deleted — so the server always keeps an administrator.

## Groups and sharing

```sh
kolimi-server group add team
kolimi-server group add-member team alice
kolimi-server group list
kolimi-server group remove-member team alice   # also drops her E2EE keys for group shares
kolimi-server group delete team                # revokes the group's shares and keys
```

Shares are created from the web UI (share dialog) or by the sync client
for E2EE files (`kolimi-sync --share … --with bob|--group team`).

## Two-factor and recovery

- TOTP: 6-digit RFC 6238 codes, ten one-time recovery codes shown once
  at enrollment. Lost everything? `user totp-disable` (admin).
- Passkeys: unlimited per account (cap 20); lost all of them? An admin
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
edits, deletions, and reordering are detectable.

```sh
kolimi-server audit list --limit 50    # JSON lines, newest first
kolimi-server audit verify             # exits 1 and names the first bad entry
```

Events cover logins and failures, logouts, passkeys, TOTP, file
mutations (via the change feed), shares, link unlocks/downloads, E2EE
key operations, plugin traps, and CLI changes. Content and file bytes
are never logged.

## Metrics

`GET /metrics` (Prometheus text format) on the server port:
request counts and latency histograms by route template, uploads,
preview outcomes, login failures. Labels never contain paths, file
names, or user identifiers. `/healthz` is the liveness endpoint.

Opening `/metrics` in a browser (which sends `Accept: text/html`) shows a
read-only **HTML dashboard** instead — metric families as cards, with a
15-second auto-refresh; append `?format=text` to force the Prometheus
format. Scrapers (no `text/html` in `Accept`) always get the text format.

`/metrics` is **administrators only**. A signed-in admin can open it in
the browser (the session cookie is enough — no separate credential), and
a scraper authenticates with HTTP Basic using an admin's username and
password. Non-admins get `403`, anonymous requests `401`. A
passkey-only (passwordless) admin cannot scrape, so point Prometheus at
an admin account that still has a password.

Scrape example:

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

The default build has no OTLP dependency; without the feature or the env
var, only the normal `fmt` logs are emitted. Request spans come from the
existing `tracing`/`tower-http` instrumentation.

### Quota warnings

When a commit pushes an account to or over **90%** of its effective
quota, the server emits a `quota.warn` audit event and adds an
`X-Kolimi-Quota-Warning` header (the usage percentage) to the commit
response; the web UI shows a toast. `GET /api/users/{name}/usage` returns
`over_quota`, `warning`, `warning_percent`, and `used_percent`, and the
admin panel marks near/over-quota accounts. `GET /api/users` accepts
`sort` (`id`, `username`, `used_bytes`, `quota_bytes`), `order`
(`asc`/`desc`), and `filter` (`over_quota`, `disabled`, `admin`).

## Hardening

- **Rate limiting.** Login, passkey ceremonies, public-link unlocks, and
  preview requests are limited per client address (20 auth attempts /
  5 min, 30 unlocks / 5 min, 120 previews / min), returning `429` with
  `Retry-After`. Beyond a trusted reverse proxy, set
  `KOLIMI_TRUST_PROXY=1` so the client address comes from
  `X-Forwarded-For` instead of the proxy.
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
  on GC, so listings never walk the blob tree; the janitor reconciles a
  bounded batch of counters from disk each pass to correct any drift.
  Deduplicated re-uploads count conservatively toward the limit.
- **Event streams.** At most 64 concurrent `/api/sync/events` SSE
  connections are served (further ones get `503`), and each is closed
  after 30 minutes.
- **Information exposure.** `/version` now requires authentication —
  use `/healthz` for unauthenticated liveness checks. Group rosters
  (`/api/groups/{name}/members`) are only visible to the group's members
  and administrators; consequently, wrapping E2EE keys for a group
  requires the sharer to be a member.

## E2EE operations

- **Setup** (per user, once): `kolimi-sync --e2ee-setup …` creates the
  keyring (passphrase + recovery code) and publishes the user's X25519
  identity. Store the recovery code offline.
- **Encrypted subtrees**: `--e2ee-root Private` encrypts files under
  `Private/`; the server stores ciphertext, wrapped per-file keys, and
  the keyring it cannot decrypt.
- **Sharing**: `kolimi-sync --share Private/doc.txt --with bob` (or
  `--group team`). Recipients pull decrypted copies under
  `Shared with me/` (read-only). `--unshare` revokes; removing a group
  member drops their wrapped keys.
- **Unlock**: passphrase, recovery code, or a passkey PRF output
  (platform shells / FFI). The tray app reads `e2ee_passphrase` from
  `~/.config/kolimi/tray.json`; prefer the environment variable
  `KOLIMI_E2EE_PASSPHRASE` on shared machines.
- **Multi-device** (RFC 0008): enroll a new device without re-typing the
  passphrase. On the new device run `kolimi-sync --e2ee-enroll <name>`
  (prints the enrollment id and waits); on an already-unlocked device run
  `kolimi-sync --e2ee-approve <id>`. The new device saves
  `.kolimi/device.json` (`0600`) and unlocks from it thereafter. Devices
  are listed/removed via `/api/e2ee/devices`.
- **Web UI**: unlock the keyring (sidebar → **Encryption**) with your
  passphrase and use **Decrypt** on an encrypted file to download its
  plaintext in the browser. Decryption happens locally (wasm); the
  passphrase never leaves the browser.
- **Public links to encrypted files**: allowed. The file key and chunk
  lengths travel in the URL **fragment** (`#k=…&l=…`), which the browser
  never sends to the server, so the server stays blind. The recipient
  opens the link and clicks **Decrypt & download**.
- **Not implemented**: MLS group messaging (per-member wrapping today) and
  forward secrecy. Device removal is **advisory** — a device keeps any
  master key it already holds, so true revocation needs master-key
  rotation (MLS). See RFC 0007 / RFC 0008 and the roadmap.

## Recovery

Kolimi has **three independent recovery secrets** — don't confuse them:

| Secret | What it recovers | How to use |
| --- | --- | --- |
| **Login password** | Account access (auth only) | An admin resets it: `kolimi-server user recover <user>`. Sessions are dropped; **no encrypted data is touched**. |
| **TOTP recovery codes** | Second factor at login | Shown **once** at TOTP enrollment (10 codes, one-time). Enter one in the login **"two-factor or recovery code"** field when you lose your authenticator. Re-enroll TOTP for a fresh set. |
| **E2EE recovery code** | The E2EE keyring (master key) | Shown **once** at `kolimi-sync --e2ee-setup`. In the web UI: **Encryption → "Use recovery code"**; on the CLI: `kolimi-sync --e2ee-recovery <code>`. |

There is **no self-service password reset** — only an administrator can reset a
login password. If a user loses every credential, an admin runs
`kolimi-server user recover <user>` (add `--keep-totp` or `--remove-passkeys`
as needed); the user then re-enrolls 2FA.

**Important:** losing the E2EE passphrase *and* the E2EE recovery code makes
the encrypted files unrecoverable — the server holds no keys and cannot help.
A password reset never affects encrypted content (it is wrapped under the E2EE
keyring, not the login password).

## Plugins

Drop a component plus metadata into `<data>/plugins/` (see
`examples/README.md`) and restart. Plugins serve
`/plugins/<name>/…` for signed-in users; `GET /api/plugins` lists them.
The sandbox grants logging, a plugin-private KV store, and the clock —
no filesystem, network, or environment. Each call has a fuel budget and
a 16 MiB memory cap; traps are contained and audited (`plugin.error`).

## Desktop and mobile clients

- **Desktop** (`apps/kolimi-desktop`): a native Tauri window loads the
  server's `/app/` UI, with a tray and background sync. On first run a setup
  window writes `~/.config/kolimi/desktop.json`:

  ```json
  {
    "server": "https://cloud.example.com",
    "username": "alice",
    "password": "…",
    "local_dir": "/home/alice/Kolimi",
    "encrypted_roots": ["Private"],
    "e2ee_passphrase": "…"
  }
  ```

  It syncs at startup, every five minutes, and on demand, showing status in
  the tray menu. The account **password and E2EE passphrase are kept in the
  system keychain** (Secret Service via zbus on Linux; Credential Manager /
  Keychain on Windows/macOS), keyed by server URL. When no keychain is
  available (headless, no secret service) they fall back to the `0600` config
  file and the app warns; treat that file like `.netrc` — same-user-readable,
  not encrypted at rest — and keep it out of backups/syncs.
  `KOLIMI_DESKTOP_CONFIG` overrides the path. The tray shows the E2EE state
  ("Encryption: N root(s), unlocked/locked").
- **CLI** (`kolimi-sync`): one-shot sync; run it from a timer or
  watcher. `--e2ee-setup`, `--share/--unshare`, `--group`.
- **WebDAV / CalDAV / CardDAV**: any client. WebDAV is class 1 **and 2**:
  byte ranges (`Range`), streamed reads, and lock-based editing
  (`LOCK`/`UNLOCK`) let it serve as a mounted network drive (Windows
  Explorer *Map network drive*, macOS Finder, GNOME Files, davfs2/gvfs,
  `rclone mount`) and as a backup destination (rclone/restic/duplicity);
  `quota-used-bytes`/`quota-available-bytes` report free space. CalDAV and
  CardDAV cover calendars and contacts (Thunderbird, iOS/macOS, DAVx5).
  Credentials are the account password (or a passkey-only account's
  session); prefer a dedicated account per device until per-device app
  passwords land (pending work).

## Upgrades

See [install.md](install.md#upgrading). Migrations are forward-only.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Blank page at `/app/` | The binary was built without the web UI. Run `scripts/build-ui.sh` before `cargo build`, or use the official image/release (which stage it automatically). |
| Passkey registration fails | `KOLIMI_ORIGIN` does not match the URL you visit (scheme + host + port). Fix and restart. |
| Cookies not sent over HTTPS | Set `KOLIMI_SECURE_COOKIES=true` (and ensure the proxy forwards https). |
| 413 on uploads | The reverse proxy's body limit; set `client_max_body_size 0` (nginx) and `proxy_request_buffering off`. |
| Previews fail with 422/415 | Unsupported format, encrypted file (no server-side preview by design), or a kernel without Landlock (the worker still runs under seccomp/rlimits). |
| "too many failed attempts" | Login lockout (5 failures / 15 min, keyed on account **and** client address) or per-client rate limiting on auth/link endpoints; wait it out, then check the audit log for `auth.login_failed` reasons. |
| Sync reports conflicts | Expected when both sides edited a file: the server version wins and your edit is kept as `name.conflict-<ts>`. |
| Server won't start after upgrade | Restore the pre-upgrade backup (migrations are forward-only). |
| Disk filling on a Docker host | The BuildKit build cache (Rust `target/`, several GB) and old images dominate. Inspect with `docker system df -v`; bound the cache with `docker builder prune --keep-storage 6GB` and remove stale images with `docker image prune -a`. The app data is the `kolimi-data` volume (see `du -sh /var/lib/kolimi` or the volume path). |

Logs go to stderr; with systemd: `journalctl -u kolimi -f`.
