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
kolimi-server user disable alice             # block logins, drop live sessions
kolimi-server user enable alice              # restore access
kolimi-server user delete alice --yes        # delete the user and everything they own
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
```

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
- **Per-user storage quota.** Set `KOLIMI_USER_QUOTA_BYTES` to bound how
  many bytes each account may store; an upload that would exceed it is
  refused with `413`. The default `0` is unlimited. Re-uploaded
  (deduplicated) content counts conservatively toward the limit.
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
- **Not implemented**: MLS group messaging (per-member wrapping today),
  forward secrecy, web-UI decryption. See RFC 0007 and the roadmap.

## Plugins

Drop a component plus metadata into `<data>/plugins/` (see
`examples/README.md`) and restart. Plugins serve
`/plugins/<name>/…` for signed-in users; `GET /api/plugins` lists them.
The sandbox grants logging, a plugin-private KV store, and the clock —
no filesystem, network, or environment. Each call has a fuel budget and
a 16 MiB memory cap; traps are contained and audited (`plugin.error`).

## Desktop and mobile clients

- **Tray** (`apps/kolimi-tray`): config at
  `~/.config/kolimi/tray.json`:

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

  It syncs at startup, every five minutes, and on demand, showing status
  in the tray menu. `chmod 600` the file; platform keychain storage is
  planned.
- **CLI** (`kolimi-sync`): one-shot sync; run it from a timer or
  watcher. `--e2ee-setup`, `--share/--unshare`, `--group`.
- **WebDAV / CalDAV / CardDAV**: any client; use an app password —
  currently the account password or a passkey-only account's session
  are the only credentials, so prefer a dedicated account per device
  until per-device app passwords land (pending work).

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
| "too many failed attempts" | Login lockout (5 failures / 15 min per account); wait it out or check the audit log for `auth.login_failed` reasons. |
| Sync reports conflicts | Expected when both sides edited a file: the server version wins and your edit is kept as `name.conflict-<ts>`. |
| Server won't start after upgrade | Restore the pre-upgrade backup (migrations are forward-only). |

Logs go to stderr; with systemd: `journalctl -u kolimi -f`.
