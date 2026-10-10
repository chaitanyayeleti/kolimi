# RFC 0003 — Sharing, Groups, and the Permission Engine

- **Status:** Implemented (M3)
- **Milestone:** M3
- **Related:** RFC 0001 (Storage Engine), RFC 0002 (Sync Protocol),
  `docs/threat-model.md`

## Summary

Kolimi has exactly **one** server-side component that answers "may this
caller do this to this node?" — `kolimi-vfs::authz`. WebDAV, the JSON API,
public links, and the web UI all resolve paths and authorize through it.
Divergent permission checks are Nextcloud's number-one bug class; there is
no second implementation to drift.

## Model

### Principals

- **Owner** — the user whose tree contains a node.
- **Recipient** — a user, or every member of a group, a share is addressed
  to. Membership is evaluated live: adding or removing a group member takes
  effect immediately.
- **Anonymous** — a holder of a public-link token.

### Permissions

Two levels: `read` and `write`; `write` implies `read`. When several
shares apply to the same node and caller, the strongest wins. There is no
re-sharing in M3: only the owner can create or revoke shares.

### Mounts

A received share becomes a **mount** under the recipient's virtual
directory `/Shared with me/<name>`. The whole subtree of the shared node is
reachable through the mount with the share's permission; inheritance is
therefore by mount, not by ancestor-walking on every access. Consequences:

- A share on a folder exposes everything inside it.
- A share on a file exposes exactly that file.
- Mount names are deduplicated deterministically (`name (2)`, `name (3)`,
  ordered by share id).
- The name `Shared with me` is reserved at the root of a user's own tree.
- Recipients cannot rename or delete the mount root itself; they can only
  touch nodes inside it (with `write`).

### Operations

| Operation | Requirement |
|---|---|
| Read/list/download | `read` on the target |
| Create/upload into a folder | `write` on the folder |
| Overwrite a received file share | `write` on the file |
| Delete inside a share | `write` on the node (mount root excepted) |
| MOVE | `write` on the source and destination parent |
| COPY | `read` on the source, `write` on the destination parent |
| PROPPATCH | `write` (dead props live on the owner's node) |
| Share management | owner only (recipients may unshare themselves) |

Cross-owner MOVE/COPY is rejected in M3 (409). Moving data between blob
stores would require a deep copy; "save a copy to my drive" is a planned
follow-up. Writes made through a share are recorded in the **owner's**
change feed (their clients must see them) and, for files, push versions in
the owner's history.

### Public links

A link share has a 128-bit random token, an optional argon2id password, and
an optional expiry (defaults: password generated once at creation unless
explicitly cleared, expiry 30 days unless explicitly disabled). The
anonymous surface is:

- `GET /public/{token}` — metadata (and folder listing)
- `GET /public/{token}/list/{path}` — folder listing
- `GET /public/{token}/download/{path}` — file bytes
- `POST /public/{token}/unlock` — password → HttpOnly, SameSite=Lax cookie

Unlock attempts are rate-limited with the same lockout policy as logins
(per share, 5 failures / 15 minutes). Password checks and session hashes
mirror the account-session machinery. Public write (upload) links are not
supported yet.

## Data model (migration 0005)

- `groups` / `group_members`
- `shares` — `kind ∈ {user, group, link}`, partial unique indexes enforce
  one user/group share per node, links are unlimited; a CHECK constraint
  enforces kind/recipient consistency
- `link_sessions` — hashed unlock-session tokens, expired by the janitor

## Threat notes

- Tokens are 128-bit and unguessable; lookup is by exact match, and unlock
  failures are counted per share so brute-forcing a weak link password is
  bounded.
- Recipients can never see the owner's tree above the shared node:
  resolution of `/Shared with me/<mount>/...` starts at the mount root.
- Mount listings reveal only nodes that are shared with the caller;
  nonexistent and unauthorized mounts are indistinguishable (404).
- Deleting a shared node hides it from recipients immediately
  (mounts only include live nodes).
