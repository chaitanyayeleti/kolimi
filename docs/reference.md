# Reference

Commands, environment variables, HTTP surfaces and on-disk layout. For
narrative guides see [install.md](install.md), [usage.md](usage.md),
[clients.md](clients.md), and [operations.md](operations.md).

- [`kolimi-server`](#kolimi-server)
- [`kolimi-sync`](#kolimi-sync)
- [Environment variables](#environment-variables)
- [HTTP API](#http-api)
- [Data directory](#data-directory)

## `kolimi-server`

`kolimi-server` with no subcommand runs `serve`.

Global option, accepted by every subcommand (before or after the
subcommand name):

| Flag | Environment | Default |
| --- | --- | --- |
| `--data DIR` | `KOLIMI_DATA` | `./kolimi-data` |

### `serve`

| Flag | Environment | Default |
| --- | --- | --- |
| `--bind ADDR` | `KOLIMI_BIND` | `127.0.0.1:8080` |
| `--origin URL` | `KOLIMI_ORIGIN` | `http://localhost:8080` |
| `--tls-cert FILE` | `KOLIMI_TLS_CERT` | — |
| `--tls-key FILE` | `KOLIMI_TLS_KEY` | — |
| `--secure-cookies` | `KOLIMI_SECURE_COOKIES` | off |

`--origin` must be the URL users actually visit (scheme, host and port);
WebAuthn binds passkeys to it. `--secure-cookies` adds the `Secure` cookie
attribute and HSTS; enable it whenever TLS terminates at the server or a
trusted proxy.

### `user`

```sh
kolimi-server user add alice [--admin] [--password PW | --password-stdin]
kolimi-server user passwd alice [--password PW]
kolimi-server user list
kolimi-server user passkey-only alice      # requires a registered passkey
kolimi-server user totp-disable alice
kolimi-server user recover alice [--password PW] [--keep-totp] [--keep-passkeys]
kolimi-server user disable alice
kolimi-server user enable alice
kolimi-server user delete alice --yes
kolimi-server user quota alice BYTES|unlimited|default
kolimi-server user usage alice [--reconcile]
```

The first account created is an administrator. `user delete` removes the
account, its tree, shares, DAV data, E2EE keys and blobs; audit rows are
preserved with a null actor. The last enabled administrator cannot be
disabled, demoted or deleted.

### `group`

```sh
kolimi-server group add team
kolimi-server group add-member team alice
kolimi-server group list
kolimi-server group remove-member team alice
kolimi-server group delete team
```

Removing a member revokes their group-share access and deletes their v1
wrapped keys. MLS membership is client-side: revoke/re-share from a client
to remove the device and rotate the keyring. Deleting a group revokes its
shares.

### Maintenance

```sh
kolimi-server backup --data DIR --to DIR   # online SQLite snapshot + blobs
kolimi-server verify --data DIR            # full BLAKE3/chunk verification
kolimi-server audit list [--limit N] [--before ID]
kolimi-server audit verify                 # exit 1 on a broken hash chain
kolimi-server audit prune --before ID --to audit.jsonl
                                           # export + prune with an anchor
```

`backup` is safe while the server is running. `verify` is the full
on-demand check; the janitor also scrubs incrementally in the background.

`audit prune` writes the selected prefix to a new JSONL file (it refuses to
overwrite an existing path), fsyncs it, then deletes those rows and records
an anchor in the database. At least the newest entry is retained.
`audit verify` starts from that anchor, so the retained tail still proves
its linkage to the exported prefix. Keep the export: it is the only copy of
the pruned entries.

## `kolimi-sync`

Required for a normal sync:

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--server URL` | `KOLIMI_SERVER` | Server base URL |
| `--user NAME` | `KOLIMI_USER` | Account username (HTTP Basic) |
| `--password PW` | `KOLIMI_PASSWORD` | Account password or app password (HTTP Basic) |
| `--local DIR` | — | Local directory to mirror |
| `--remote PATH` | — | Remote subfolder (default `/`) |

Use an app password for TOTP or passkey-only accounts; the CLI cannot answer
an interactive TOTP prompt. Pass it through `KOLIMI_PASSWORD` or
`--password`. See [clients.md](clients.md#kolimi-sync-cli) for examples.

E2EE:

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--e2ee-setup` | — | Create/upload the keyring, print the recovery code, exit |
| `--e2ee-root PATH` | — | Encrypted subtree; repeatable/comma-separated. Empty value (`''`) encrypts the whole sync root |
| `--e2ee-passphrase PW` | `KOLIMI_E2EE_PASSPHRASE` | Unlock passphrase |
| `--e2ee-recovery CODE` | `KOLIMI_E2EE_RECOVERY` | Recovery-code unlock |
| `--e2ee-prf HEX` | `KOLIMI_E2EE_PRF` | Platform passkey-PRF output (64 hex chars) |
| `--e2ee-prf-stdin` | — | Read the PRF output from stdin instead of argv |
| `--e2ee-enroll NAME` | — | Enroll this device and wait for approval |
| `--e2ee-approve ID` | — | Approve a pending device enrollment |
| `--e2ee-code CODE` | — | Approval code for `--e2ee-approve` |
| `--e2ee-fingerprints` | — | Print pinned recipient fingerprints |
| `--e2ee-forget-device` | — | Remove local device key material |

Sharing / MLS:

| Flag | Meaning |
| --- | --- |
| `--share PATH` | Share a path relative to `--local` |
| `--with USER` / `--group NAME` | Recipient |
| `--unshare` | Revoke the share instead of creating it |
| `--mls` | Enable MLS group shares (`KOLIMI_MLS_SHARES` also works) |
| `--write` | Create a write share (implies `--mls`) |
| `--update-permission` | Change an existing share to `--write`/read |
| `--mls-migrate` | Promote existing encrypted folder shares to MLS |
| `--mls-reset` | Delete this device's sealed MLS state (prompts for `reset`) |
| `--yes` | Skip a destructive MLS confirmation (`--mls-reset`, `--mls-revoke-device`) |
| `--mls-status PATH` | Print epoch and members for a path |
| `--mls-devices` | List MLS devices, signature keys, last seen and visible groups |
| `--mls-revoke-device ID` | Remove one device's leaves, rotate keyrings, then clear its roster row |
| `--with USER` (MLS commands) | List or revoke that user's device from shares you own |

Notes:

- A write share is supported for encrypted folders and single files. A
  folder writer can add/edit/delete children; a single-file writer can
  replace the file through the CLI/desktop or WebDAV `PUT` but cannot
  delete the share root. The web UI downloads single-file shares; it has
  no inline editor for them.
- The recipient must have unlocked once (web, desktop or CLI) so a key
  package is published; otherwise the share fails with a clear error.
- For legacy v1/v2 per-file shares, `--share` wraps the file key for the
  recipient; `--unshare` revokes it.

## Environment variables

### Server

| Variable | Used for |
| --- | --- |
| `KOLIMI_BIND`, `KOLIMI_DATA`, `KOLIMI_ORIGIN` | Listen address, data dir, public origin |
| `KOLIMI_TLS_CERT`, `KOLIMI_TLS_KEY` | Direct TLS |
| `KOLIMI_SECURE_COOKIES` | Secure cookies + HSTS behind TLS |
| `KOLIMI_USER_QUOTA_BYTES` | Default per-user quota (`0` = unlimited) |
| `KOLIMI_PREVIEW_ALLOW_NO_LANDLOCK=1` | Permit preview decoding without Landlock (weaker sandbox; older kernels) |
| `KOLIMI_METRICS_PER_USER=1` | Opt in to per-user usage gauges |
| `KOLIMI_METRICS_TOKEN` | Read-only bearer token accepted only by `/metrics` |
| `KOLIMI_AUTH_RATE_LIMIT` | Login/passkey attempts per client per 5 minutes (default 20) |
| `KOLIMI_TRUST_PROXY=1` | Use `X-Forwarded-For` from a trusted proxy |
| `KOLIMI_OTEL_ENDPOINT` | OTLP/gRPC traces (requires the `otel` feature) |
| `RUST_LOG` | Log filter (default `info`) |

### Sync / desktop / packaging

| Variable | Used for |
| --- | --- |
| `KOLIMI_SERVER`, `KOLIMI_USER`, `KOLIMI_PASSWORD` | `kolimi-sync` connection |
| `KOLIMI_E2EE_PASSPHRASE`, `KOLIMI_E2EE_RECOVERY`, `KOLIMI_E2EE_PRF` | E2EE unlock (PRF can also come from `--e2ee-prf-stdin`) |
| `KOLIMI_MLS_SHARES` | Enable MLS in `kolimi-sync` |
| `KOLIMI_DEVICE_NAME` | Label shown in the MLS device roster (default: hostname) |
| `KOLIMI_DESKTOP_CONFIG` | Override `desktop.json` path |
| `KOLIMI_START_HIDDEN` | Start the desktop app hidden in the tray (same as `--hidden`) |
| `KOLIMI_ADMIN_PASSWORD` | Non-interactive `install.sh` admin password |
| `KOLIMI_IMAGE` | Image override for the Compose examples |
| `KOLIMI_DOMAIN`, `ACME_EMAIL` | Traefik Compose hostname and ACME contact |

## HTTP API

### Authentication

- `POST /api/session` with `{"username","password"}` sets the
  `kolimi_session` and `kolimi_csrf` cookies. Include `code` (TOTP or a
  recovery code) when the account has two-factor enabled; without it the
  response is `401` with `"totp_required": true`. Cookie-authenticated
  state-changing requests need `X-CSRF-Token` from the CSRF cookie.
- `DELETE /api/session` signs out. `GET /api/me` is session-only (HTTP
  Basic is deliberately rejected); most other API endpoints and WebDAV
  accept HTTP Basic for scripts and DAV clients.
- `POST /api/me/password` requires `X-Reauth-Token` from
  `POST /api/reauth`. Re-authentication accepts `{"password"}` or a TOTP /
  recovery `{"code"}` and returns a single-use token valid for five minutes;
  passkey-only sessions use `/api/reauth/passkey/begin|finish` instead. It
  keeps the current session and revokes the others.
- `GET /api/me/sessions` lists the caller's live sessions with creation,
  last-seen, IP, `User-Agent`, and optional label metadata.
  `PATCH /api/me/sessions/{id}` sets or clears `label`;
  `DELETE /api/me/sessions/{id}` revokes one; `DELETE /api/me/sessions`
  revokes all, or all others with `?keep_current=true`. Session tokens are
  never returned, and session/login responses use `Cache-Control: no-store`.
  Last-seen timestamps refresh at most once per minute; the session row is
  still checked on every request, so revocation is immediate.
- `PATCH /api/me` updates the optional `display_name` and `email` profile
  fields. Email is informational only; Kolimi sends no mail.
- Accounts marked `must_change_password` may only call `GET /api/me`,
  `POST /api/reauth`, `POST /api/me/password`, and `DELETE /api/session`.
  Every other API, WebDAV, and sync request returns `403`.
- Accounts marked `must_setup_mfa` (users created through the admin API or
  an invite) may only
  call the MFA setup surface (`GET /api/me`, `GET /api/totp`,
  `POST /api/totp/begin|enable`, `GET /api/passkeys`,
  `POST /api/passkeys/register/*`, `POST /api/reauth`,
  `POST /api/me/password`, `DELETE /api/session`) until TOTP or a passkey is
  enrolled.
- App passwords: `GET|POST /api/me/app-passwords` lists or creates tokens
  (the plaintext token is returned once), `PATCH /api/me/app-passwords/{id}`
  renames/rescopes/changes expiry, `DELETE /api/me/app-passwords/{id}`
  revokes one, and `DELETE /api/me/app-passwords/current` lets a device revoke
  the token it authenticated with. Creation/revocation accept a fresh
  `X-Reauth-Token`, or a session created within the last five minutes.
  HTTP Basic accepts an app password even when the account has TOTP.
  `last_used_at` refreshes at most once per minute; the token row is still
  read on every request, so deletion is immediate.
  `POST` accepts optional `scopes` (an array) and `expires_in_secs`
  (`0`/omitted = never). Omitted scopes default to `*` for compatibility.
  Scopes are `*`, `files:read`, `files:write`, `caldav:read`,
  `caldav:write`, `carddav:read`, `carddav:write`, and `sync`; write implies
  read. Scoped tokens are deny-by-default: account administration, passkeys,
  sessions, invites, audit, and token management require `*`. A `sync` token
  may also read share metadata and maintain the MLS groups used by encrypted
  shared folders. A scope failure returns `403` and never falls back to a
  cookie session.
- Invite links use `/invite#token=…`; the fragment never reaches the server.
  `POST /api/invites/lookup` and `POST /api/invites/accept` take the token in
  JSON, and acceptance creates the account. Admin routes are
  `GET|POST /api/invites` and `DELETE /api/invites/{id}`; responses never
  include stored hashes or a previously generated token.
- Admin `GET /api/users` accepts `q=` for a case-insensitive username search.
  `PATCH`/`DELETE /api/users/{username}`, recovery, and force sign-out
  require a fresh `X-Reauth-Token` from `POST /api/reauth`; recovery returns
  a generated password once with `Cache-Control: no-store` and is
  rate-limited per client.
- Admin group routes are `GET|POST /api/groups`,
  `DELETE /api/groups/{name}`, and
  `POST|DELETE /api/groups/{name}/members/{username}`. `GET /api/audit`
  accepts `limit`, `before`, `action`, and `subject`; `GET /api/audit/verify`
  recomputes the hash chain. Both audit routes are admin-only and omit chain
  hashes.
- Public links use `/public/{token}` and set a scoped unlock cookie after
  `POST /public/{token}/unlock`. `POST /api/shares` with `kind: "link"`
  accepts `password` (omitted = generated, `""` = none) and
  `expires_in_secs` (omitted = 30 days, `0` = never).
- Upload-only links (file requests) use `kind: "link"` with
  `permission: "write"` on a plaintext folder. `POST /api/shares` also
  accepts `max_files` (default 20, max 10,000) and `max_bytes` (default
  1 GiB, max 64 GiB). The public page shows only the folder name and the
  remaining limits; `GET /public/{token}/list*` and `/download*` return
  `403`. Uploads use `PUT /public/{token}/upload?name=<filename>` with a
  required `Content-Length`, are streamed to the owner's folder, and never
  overwrite: collisions get ` (2)`, ` (3)`, … suffixes. Expired, revoked,
  password-protected, encrypted, missing, or trashed targets are rejected.
  The response is `201` with the sanitized name and size; neither existing
  filenames nor the folder path are disclosed. Write links cannot be
  switched to read (or back) after creation; revoke and recreate instead.

### Directory browsing

`GET /api/browse?path=&limit=&cursor=` returns one page of a directory.
`limit` defaults to 1,000 and is capped at 5,000. `cursor` is the last name
from the previous page; the response carries `has_more` and `next_cursor`.
Names are unique within a parent, so pages do not duplicate entries; an
insert before the cursor appears on a refresh. `/Shared with me` itself and the mounts on the account root are small
fixed lists: mounts appear on the first root page only.

### WebDAV / CalDAV / CardDAV

- **WebDAV:** `https://host/dav/` is the account root; `/dav/<path>` maps
  to the file tree. Class 2 (`LOCK`/`UNLOCK`, byte ranges, streamed reads).
- **CalDAV:** principal at `/dav/principals/{user}/`, calendar home at
  `/dav/calendars/{user}/`.
- **CardDAV:** principal at `/dav/principals/{user}/`, address-book home at
  `/dav/addressbooks/{user}/`.
- `/.well-known/caldav` and `/.well-known/carddav` redirect to `/dav/`.
- Authenticate with HTTP Basic using the username and an **app password**.
  Encrypted subtrees are plaintext-only over DAV: content reads and writes
  return `403`; `DELETE`/`LOCK` are metadata-only and still work. Encrypted
  names may appear as `k1_…`. Client setup and mount examples are in
  [clients.md](clients.md#webdav).

### Endpoint groups

| Area | Endpoints |
| --- | --- |
| Session / account | `POST /api/session`, `DELETE /api/session`, `POST /api/reauth`, `GET|PATCH /api/me`, `GET /api/me/usage`, `POST /api/me/password`, `GET|DELETE /api/me/sessions`, `PATCH|DELETE /api/me/sessions/{id}`, `GET|POST /api/me/app-passwords`, `PATCH|DELETE /api/me/app-passwords/{id}`, `DELETE /api/me/app-passwords/current`, `GET|POST /api/users`, `PATCH|DELETE /api/users/{name}`, `/api/users/{name}/usage`, `/api/users/{name}/recover`, `/api/users/{name}/logout`, `/api/users/{name}/sessions` |
| Invites | `GET|POST /api/invites`, `DELETE /api/invites/{id}`, `POST /api/invites/lookup`, `POST /api/invites/accept` |
| Passkeys / TOTP | `/api/passkeys*`, `/api/passkeys/login/*`, `/api/reauth/passkey/*`, `/api/totp*` |
| Browse / files | `GET /api/browse`, `GET /api/files/info`, `POST /api/files/move`, `POST /api/files/encrypt`, `GET /api/search`, `GET /api/preview` |
| Trash / versions | `/api/trash*`, `/api/versions*` |
| Delta sync | `/api/sync/changes`, `/api/sync/tree`, `/api/sync/events`, `/api/sync/shared-tree`, `/api/files/manifest`, `/api/manifests/{id}`, `PUT /api/files`, `/api/chunks*` |
| Shares | `/api/shares`, `/api/shares/received`, `/api/shares/owned`, `/api/shares/{id}`, `/api/shareable`, `/api/groups/{name}/members` |
| Groups / audit (admin) | `GET|POST /api/groups`, `DELETE /api/groups/{name}`, `POST|DELETE /api/groups/{name}/members/{username}`, `GET /api/audit`, `GET /api/audit/verify` |
| Public links | `GET /public/{token}`, `/unlock`, `/list*`, `/download*`, `PUT /upload?name=` (upload-only links) |
| E2EE v1/v2 | `/api/e2ee/keyring`, `/api/e2ee/identity*`, `/api/files/key`, `/api/e2ee/share-key`, `/api/e2ee/share-name`, `/api/e2ee/enrollments*`, `/api/e2ee/devices*` |
| MLS | `/api/mls/key-packages`, `/api/mls/key-packages/consume`, `/api/mls/key-packages/{username}`, `/api/mls/devices`, `/api/mls/devices/{username}`, `/api/mls/group`, `/api/mls/commit`, `/api/mls/messages`, `/api/mls/epoch`, `/api/mls/keyring`, `/api/mls/revocations` |
| WebDAV / CalDAV / CardDAV | `/dav/`, `/dav/principals/{user}/`, `/dav/calendars/{user}/`, `/dav/addressbooks/{user}/`, `/.well-known/{caldav,carddav}` |
| Operations | `GET /healthz` (public), `GET /version` (authenticated), `GET /metrics` (admin or `KOLIMI_METRICS_TOKEN`) |

E2EE and MLS request bodies are opaque ciphertext/protocol payloads to the
server. The server validates sizes, ownership, ACLs and epoch ordering; it
does not decrypt them. `POST /api/mls/commit?path=` appends a commit and its
optional Welcome in one transaction, so a concurrent committer cannot advance
the epoch between them. `POST /api/mls/epoch?path=` accepts
`{"device_id","epoch"}` from a member after it processes group state; the
janitor uses the minimum fresh report to prune old messages and keyrings.
An account may have at most 16 active MLS devices in the roster at a time and
each device may have at most 8 live key packages; over-limit package uploads
return `409`. Inactive roster entries are pruned after 180 days. The roster
stores an optional device name and the public MLS signature key so a client
can map a device id to its group leaf. `GET /api/mls/devices/{username}`
exposes only that public metadata for a shared recipient. Removed signatures
are recorded per group (`/api/mls/revocations`) so automatic re-add skips
leftover key packages; an explicit re-share clears the entry. Deleting a
roster row (`DELETE /api/mls/devices?device_id=`) is bookkeeping, not an MLS
removal: clients must post the remove commit first.

See the [sync protocol](rfc/0002-sync-protocol.md), [E2EE](rfc/0007-e2ee.md)
and [MLS](rfc/0012-mls-groups.md) specs for wire details.

## Data directory

```
$KOLIMI_DATA/
  kolimi.db                  SQLite (WAL) database
  blobs/users/<id>/chunks/   content-addressed ciphertext/plaintext chunks
  blobs/users/<id>/manifests/ manifests
  blobs/tmp/                 atomic-write scratch space
  search/                    tantivy index
  tmp/                       server scratch space
```

Back up the whole directory with `kolimi-server backup`; copying it while
the server is running without that command can produce a torn SQLite
snapshot.
