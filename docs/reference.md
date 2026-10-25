# Reference

Commands, environment variables, HTTP surfaces and on-disk layout. For
narrative guides see [install.md](install.md) and
[operations.md](operations.md).

## `kolimi-server`

`kolimi-server` with no subcommand runs `serve`.

### `serve`

| Flag | Environment | Default |
| --- | --- | --- |
| `--bind ADDR` | `KOLIMI_BIND` | `127.0.0.1:8080` |
| `--data DIR` | `KOLIMI_DATA` | `./kolimi-data` |
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
kolimi-server user recover alice [--password PW] [--keep-totp] [--remove-passkeys]
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
```

`backup` is safe while the server is running. `verify` is the full
on-demand check; the janitor also scrubs incrementally in the background.

## `kolimi-sync`

Required for a normal sync:

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--server URL` | `KOLIMI_SERVER` | Server base URL |
| `--user NAME` | `KOLIMI_USER` | Account username (HTTP Basic) |
| `--password PW` | `KOLIMI_PASSWORD` | Account password |
| `--local DIR` | — | Local directory to mirror |
| `--remote PATH` | — | Remote subfolder (default `/`) |

E2EE:

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--e2ee-setup` | — | Create/upload the keyring, print the recovery code, exit |
| `--e2ee-root PATH` | — | Encrypted subtree; repeatable/comma-separated |
| `--e2ee-passphrase PW` | `KOLIMI_E2EE_PASSPHRASE` | Unlock passphrase |
| `--e2ee-recovery CODE` | `KOLIMI_E2EE_RECOVERY` | Recovery-code unlock |
| `--e2ee-prf HEX` | `KOLIMI_E2EE_PRF` | Platform passkey-PRF output (64 hex chars) |
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
| `--mls-status PATH` | Print epoch and members for a path |

Notes:

- A write share is supported for encrypted folders. Single-file MLS shares
  are read-only.
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
| `KOLIMI_METRICS_PER_USER=1` | Opt in to per-user usage gauges |
| `KOLIMI_TRUST_PROXY=1` | Use `X-Forwarded-For` from a trusted proxy |
| `KOLIMI_OTEL_ENDPOINT` | OTLP/gRPC traces (requires the `otel` feature) |
| `RUST_LOG` | Log filter (default `info`) |

### Sync / desktop / installer

| Variable | Used for |
| --- | --- |
| `KOLIMI_SERVER`, `KOLIMI_USER`, `KOLIMI_PASSWORD` | `kolimi-sync` connection |
| `KOLIMI_E2EE_PASSPHRASE`, `KOLIMI_E2EE_RECOVERY`, `KOLIMI_E2EE_PRF` | E2EE unlock |
| `KOLIMI_MLS_SHARES` | Enable MLS in `kolimi-sync` |
| `KOLIMI_DESKTOP_CONFIG` | Override `desktop.json` path |
| `KOLIMI_ADMIN_PASSWORD` | Non-interactive `install.sh` admin password |
| `KOLIMI_IMAGE` | Image override for the Compose examples |

## HTTP API

### Authentication

- `POST /api/session` with `{"username","password"}` sets the
  `kolimi_session` and `kolimi_csrf` cookies. Cookie-authenticated
  state-changing requests need `X-CSRF-Token` from the CSRF cookie.
- `DELETE /api/session` signs out. `GET /api/me` is session-only (HTTP
  Basic is deliberately rejected); most other API endpoints and WebDAV
  accept HTTP Basic for scripts and DAV clients.
- Public links use `/public/{token}` and set a scoped unlock cookie after
  `POST /public/{token}/unlock`.

### Endpoint groups

| Area | Endpoints |
| --- | --- |
| Session / account | `POST /api/session`, `DELETE /api/session`, `GET /api/me`, `GET /api/me/usage`, `GET /api/users`, `/api/users/{name}`, `/api/users/{name}/usage` |
| Passkeys / TOTP | `/api/passkeys*`, `/api/passkeys/login/*`, `/api/totp*` |
| Browse / files | `GET /api/browse`, `GET /api/files/info`, `POST /api/files/move`, `POST /api/files/encrypt`, `GET /api/search`, `GET /api/preview` |
| Trash / versions | `/api/trash*`, `/api/versions*` |
| Delta sync | `/api/sync/changes`, `/api/sync/tree`, `/api/sync/events`, `/api/sync/shared-tree`, `/api/files/manifest`, `/api/manifests/{id}`, `PUT /api/files`, `/api/chunks*` |
| Shares | `/api/shares`, `/api/shares/received`, `/api/shares/owned`, `/api/shares/{id}`, `/api/shareable`, `/api/groups/{name}/members` |
| Public links | `GET /public/{token}`, `/unlock`, `/list*`, `/download*` |
| E2EE v1/v2 | `/api/e2ee/keyring`, `/api/e2ee/identity`, `/api/files/key`, `/api/e2ee/share-key`, `/api/e2ee/share-name`, `/api/e2ee/enrollments*`, `/api/e2ee/devices*` |
| MLS | `/api/mls/key-packages`, `/api/mls/key-packages/consume`, `/api/mls/key-packages/{username}`, `/api/mls/group`, `/api/mls/messages`, `/api/mls/keyring` |
| Operations | `GET /healthz` (public), `GET /version` (authenticated), `GET /metrics` (admin) |

E2EE and MLS request bodies are opaque ciphertext/protocol payloads to the
server. The server validates sizes, ownership, ACLs and epoch ordering; it
does not decrypt them.

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
