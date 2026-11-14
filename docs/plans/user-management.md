# User management — plan

Status: **complete** · Date: 2026-11-14 · Phases 1–5 landed on `main`
Builds on: [operations.md](../operations.md), [reference.md](../reference.md),
[red-team report](../audit/redteam-2026-11-14.md)

The backend already has most of the user-administration primitives. The gap is
mostly HTTP surface and UI: a normal user cannot change their own password, and
an administrator cannot create, recover, inspect, or sign out a user without
the CLI.

## 1. Goal

Make account administration and self-service account security usable from the
web UI without weakening the current invariants:

- at least one enabled administrator;
- at least one passkey on a passwordless account;
- re-authentication for credential changes;
- hash-chained audit logging;
- no password hashes, session tokens, or key material in responses or logs.

## 2. Non-goals

- Full RBAC or delegated administration. Keep `is_admin` for server
  administration and groups for sharing.
- Email delivery, SCIM, SSO, or multi-tenant organizations.
- User impersonation.
- Renaming usernames; they are identity keys across shares and audit history.
- Soft-delete/undelete.

## 3. Current state

| Capability | API | CLI | Web UI |
| --- | --- | --- | --- |
| List / sort / filter users | Yes | `user list` | Yes, search + cursor paging |
| Create user | Yes | `user add` | Yes |
| User detail | Yes | No | Yes |
| Admin / disabled / quota changes | Yes | Yes | Yes |
| Change own password | Yes | `user passwd` | Yes |
| Recover account | Yes | `user recover` | Yes, re-auth required |
| List / revoke sessions | Yes | No | Yes |
| Group management | Yes | Yes | Yes |
| Audit log | Yes | `audit list` / `verify` | Yes, filters + verify |

Phases 1–5 are implemented. The Admin page has **Users**, **Invites**,
**Groups**, and **Audit** tabs; self-service password, profile, and session
controls live under **Settings → Account**.

## 4. Principles

1. Keep the existing `User` model; add columns only where the UI needs them.
2. Admin is a page with tabs, not a modal built around a 200-row list.
3. High-risk mutations require the existing re-authentication token
   (`POST /api/reauth`).
4. No secrets in list/detail responses. A generated temporary password is
   returned once and never logged or written to audit details.
5. Last-admin and last-passkey guards stay in the database where possible.
6. Every admin action is audited with the real actor and target.
7. New routes are additive. Existing routes keep their response shapes; adding
   a required re-auth header to destructive routes is a deliberate hardening
   change and must be called out in the changelog.

## 5. Phases

### Phase 1 — self-service account security (P0) — landed

Add **Settings → Account**:

- username, role, and member-since;
- change password;
- active sessions with device, IP, last-seen time;
- revoke one session;
- “Sign out other devices” and “Sign out everywhere”.

API:

- `POST /api/me/password` — requires a re-auth token; keeps the current
  session and revokes the others;
- `GET /api/me/sessions` — marks the current session;
- `DELETE /api/me/sessions/{id}`;
- `DELETE /api/me/sessions` — accepts `keep_current` for “other devices”.

Password change must use `POST /api/reauth` rather than reimplementing
password/TOTP verification. Passkey-only accounts do not get a password form;
they use the existing passkey management panel.

### Phase 2 — admin essentials (P0) — landed (Users page)

The Admin modal is now a page. This phase shipped the **Users** view; the
**Groups** and **Audit** tabs followed in Phase 3.

Users view:

- search, filters, sort, and real pagination;
- create a user with a generated temporary password or an admin-supplied one;
- user detail panel: id, created, last login, admin/disabled, TOTP, passkey
  count, active sessions, groups, owned/received shares, storage;
- reset password / recover account;
- force sign-out;
- disable/enable, grant/revoke admin, quota;
- delete with typed username confirmation and a data summary.

API:

- extend `POST /api/users` with optional `admin` and `quota_bytes`;
- add `POST /api/users/{username}/recover`;
- add `POST /api/users/{username}/logout`;
- add `GET /api/users/{username}/sessions`;
- enrich `GET /api/users/{username}` with auth/session/group/share counts;
- add username search to `GET /api/users` and use `next_cursor` in the UI for
  id-order pages. For usage/quota sorts, add keyset paging on
  `(used_bytes, id)` / `(quota_bytes, id)` or an explicit offset parameter;
  the current cursor is only valid for `sort=id`.

The recover payload is:

```json
{
  "password": "optional temporary password",
  "keep_totp": false,
  "keep_passkeys": false
}
```

When `password` is omitted, generate a random password and return it once with
`Cache-Control: no-store`. Recovery and force sign-out require
re-authentication. Phase 5 later extended the same requirement to the
existing `PATCH` and `DELETE /api/users/{username}` routes.

### Phase 3 — groups and audit (P1) — landed (Groups/Audit tabs)

Added the remaining Admin tabs.

Groups tab:

- list groups and members;
- create/delete a group;
- add/remove members;
- warn that group changes do not rotate MLS keys, so a client must re-share
  affected folders.

Audit tab:

- recent entries with time, actor, action, target, and expandable details;
- filter by action or target user;
- chain verification status.

API:

- `GET /api/groups`, `POST /api/groups`, `DELETE /api/groups/{name}`;
- `POST|DELETE /api/groups/{name}/members/{username}`;
- `GET /api/audit?limit=&before=&action=&subject=`;
- `GET /api/audit/verify`.

All of these are admin-only. Audit details are already JSON; the UI should
render them as structured key/value rows rather than a raw string.

### Phase 4 — onboarding (P2) — landed

- One-time invite links with an expiry, so an admin does not have to share a
  temporary password out of band.
- `must_change_password` enforced by the server, not only the UI.
- Optional display name and email fields.
- A read-only auditor role only if there is a concrete need; do not add RBAC
  pre-emptively.

Implementation notes:

- The Admin **Invites** tab creates links valid for 1 hour to 30 days. A
  link is shown once. The token is BLAKE3-hashed at rest and placed in the
  URL fragment; lookup/acceptance POST the token in a JSON body so it never
  appears in request lines or proxy logs.
- Acceptance creates the user and consumes the invite in one database
  transaction. Expired invites are cleaned up when the next invite is
  created, so a username can be invited again.
- Admin-created accounts can set `must_change_password`. The auth middleware
  blocks every API/WebDAV/sync path except the `/api/me` probe,
  `/api/reauth`, `/api/me/password`, and sign-out until the password is
  replaced.
- `display_name` and `email` are optional, visible in account/admin views,
  and editable via `PATCH /api/me`; email is not used for authentication or
  delivery.

### Phase 5 — hardening closeout (P1) — landed

- `PATCH` and `DELETE /api/users/{username}` now require a fresh
  `X-Reauth-Token`, like recovery and force sign-out. The UI prompts for the
  admin password or a second factor before quota, role, access, or deletion
  changes.
- Password recovery requires the admin to type the target username in
  addition to re-authenticating.
- Admin recovery requests have their own per-client rate limit.
- Login and session-list responses use `Cache-Control: no-store`.
- Sessions have an optional user-editable label (migration 0029) exposed via
  `PATCH /api/me/sessions/{id}` and rendered in Settings → Account.

The read-only auditor role remains intentionally unimplemented; adding it
would be an RBAC expansion and needs its own threat model.

## 6. Data model changes

### Sessions

Add nullable columns:

- `ip TEXT`;
- `user_agent TEXT`;
- `label TEXT` (optional, user-editable).

Existing rows stay valid. `start_session` needs the request IP and
`User-Agent`; the current session is identified by the request's session hash.
Do not expose token hashes.

### Users

Add:

- `last_login_at INTEGER` — updated on successful login for the admin list;
- `display_name TEXT` and `email TEXT` — optional profile fields;
- `must_change_password INTEGER NOT NULL DEFAULT 0`.

### Invites (phase 4)

```text
invites(
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL COLLATE NOCASE,
  token_hash BLOB NOT NULL UNIQUE,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  display_name TEXT,
  email TEXT,
  used_at INTEGER
)
```

The invite token is hashed at rest, single-use, and consumed when the user sets
their password. A partial unique index allows one pending invite per username;
expired rows are cleared when the next invite is created. The threat-model
result: use a 256-bit token, store only BLAKE3, put the plaintext in the URL
fragment, POST it in JSON bodies, return it exactly once, and rate-limit
lookup/acceptance.

No role-table migration is needed. Keep `is_admin`.

## 7. UI

### Admin page

- Tabs: **Users**, **Invites**, **Groups**, **Audit**.
- Users table columns: user, status, role, auth, storage, last seen, actions.
- Row opens a detail panel; destructive actions use a modal, never
  `window.prompt`.
- Quota input accepts `GB`/`MB`/`MiB` plus `default` and `unlimited`.
- Empty, loading, and error states are explicit.

### Settings → Account

- Account summary.
- Password change form.
- Session table with “this device” marker.
- “Sign out other devices” and “Sign out everywhere”.

Passkeys and TOTP stay in the existing **Passkeys** tab. Admin recovery is
separate from E2EE recovery; the UI must say so to avoid confusing the account
password with the encryption passphrase.

## 8. Security and invariants

- Re-authenticate before: password change, admin recovery, user deletion,
  force sign-out, and every user `PATCH` (quota, role, disable/enable).
- Preserve the last-enabled-admin guard in `set_admin`, `set_disabled`, and
  `delete_user`; exercise every new path through those methods.
- Preserve the passwordless-account last-passkey guard.
- Never return `password_hash`; never return session tokens; never log
  temporary passwords or session identifiers.
- Audit `user.recover`, `user.password_change`, `session.revoke`, and group
  changes with real actor IDs/usernames.
- Use typed username confirmation for delete and recovery.
- Set `Cache-Control: no-store` on recovery and session responses.
- Return `403` for missing/stale re-auth and `409` for last-admin conflicts.
- Rate-limit recovery and invite consumption as part of the existing auth
  hardening.

## 9. Testing

- API integration tests in `crates/kolimi-server/tests/users.rs`,
  `account.rs`, `groups_audit.rs`, `invites.rs`, and `phase5.rs`:
  - non-admin gets `403` on every admin route;
  - re-auth is required for recover/delete/grant/revoke;
  - last enabled admin cannot be disabled, demoted, or deleted;
  - password change keeps the current session and revokes others;
  - recovery drops sessions and audits the real admin actor;
  - session listing never exposes token hashes;
  - group changes are audited;
  - invite creation/acceptance/revocation, expiry, and single-use behavior;
  - forced password rotation blocks the API until the password is replaced;
  - user `PATCH`/`DELETE` reject a missing re-auth token;
  - recovery is rate-limited and session responses are `no-store`;
  - session labels are scoped to their owner.
- DB tests for `last_login_at`, session metadata/labels, invites, and the
  last-admin race.
- Browser E2E: create user, recover password, revoke a session, disable/delete,
  search/pagination.
- Migration test: existing sessions and users survive the new nullable
  columns.

## 10. Rollout and docs

- New API routes are additive. Existing response shapes stay stable.
  Recovery, force sign-out, and the existing user `PATCH`/`DELETE` routes
  now require `X-Reauth-Token`; callers must obtain a fresh token from
  `POST /api/reauth`. This is documented in the changelog as a deliberate
  compatibility change.
- Refactor `admin::recover_user` to accept an actor so CLI recovery still
  records `cli` and HTTP recovery records the admin.
- Update [operations.md](../operations.md) and [reference.md](../reference.md)
  with the new endpoints and recovery rules.
- The release changelog entry is under `0.4.8`.

## 11. Resolved questions

1. Invite links are the primary onboarding path; temporary passwords remain
   available for compatibility and can require rotation.
2. Session IP/user-agent metadata is retained per session for self-service
   revocation.
3. No read-only auditor role was added. The admin page plus the audit API
   cover the current need; revisit only for delegated, non-admin auditing.
4. `must_change_password` gates every API, WebDAV, and sync route except the
   probe, re-authentication, password change, and sign-out.
