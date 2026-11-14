# User management — plan

Status: **in progress** · Date: 2026-11-14 · Phase 1 landed on `main`
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
| List / sort / filter users | Yes | `user list` | Yes, capped at 200 and no cursor |
| Create user | Yes | `user add` | No |
| User detail | Yes | No | No |
| Admin / disabled / quota changes | Yes | Yes | Partial |
| Change own password | No | `user passwd` | No |
| Recover account | No | `user recover` | No |
| List / revoke sessions | No | No | No |
| Group management | Member list only | Yes | No |
| Audit log | DB only | `audit list` / `verify` | No |

The sessions table already records `created_at`, `expires_at`, and
`last_seen_at`. `GET /api/users` already supports sorting, filtering, and
cursor pagination, but the admin modal ignores the cursor. Recovery is
factored into `kolimi_server::admin::recover_user`, so the HTTP endpoint can
reuse it; the audit actor currently needs to become a parameter instead of
being hard-coded to `cli`.

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

### Phase 1 — self-service account security (P0)

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

### Phase 2 — admin essentials (P0)

Replace the Admin modal with a page containing **Users / Groups / Audit**
tabs.

Users tab:

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
`Cache-Control: no-store`. Recover, delete, force sign-out, and
grant/revoke-admin require re-authentication.

### Phase 3 — groups and audit (P1)

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

### Phase 4 — onboarding (P2)

- One-time invite links with an expiry, so an admin does not have to share a
  temporary password out of band.
- `must_change_password` enforced by the server, not only the UI.
- Optional display name and email fields.
- A read-only auditor role only if there is a concrete need; do not add RBAC
  pre-emptively.

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
- `must_change_password INTEGER NOT NULL DEFAULT 0` (phase 4).

### Invites (phase 4)

```text
invites(
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE,
  created_by INTEGER REFERENCES users(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
)
```

The invite token is hashed at rest, single-use, and consumed when the user sets
their password. This needs its own threat-model pass before implementation.

No role-table migration is needed. Keep `is_admin`.

## 7. UI

### Admin page

- Tabs: **Users**, **Groups**, **Audit**.
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
  force sign-out, and grant/revoke admin.
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

- API integration tests in `crates/kolimi-server/tests/users.rs`:
  - non-admin gets `403` on every admin route;
  - re-auth is required for recover/delete/grant/revoke;
  - last enabled admin cannot be disabled, demoted, or deleted;
  - password change keeps the current session and revokes others;
  - recovery drops sessions and audits the real admin actor;
  - session listing never exposes token hashes;
  - group changes are audited.
- DB tests for `last_login_at`, session metadata, and the last-admin race.
- Browser E2E: create user, recover password, revoke a session, disable/delete,
  search/pagination.
- Migration test: existing sessions and users survive the new nullable
  columns.

## 10. Rollout and docs

- New API routes are additive. Existing response shapes stay stable; the
  destructive user routes gain a required re-auth header, which must be
  documented as a deliberate compatibility change.
- Refactor `admin::recover_user` to accept an actor so CLI recovery still
  records `cli` and HTTP recovery records the admin.
- Update [operations.md](../operations.md) and [reference.md](../reference.md)
  with the new endpoints and recovery rules.
- Keep `CHANGELOG.md` entry for the release that ships the first phase.

## 11. First slice

1. `POST /api/me/password` and `GET/DELETE /api/me/sessions`.
2. Settings → Account tab.
3. Admin create-user and recover-password endpoints + forms.
4. Session metadata migration and force sign-out.
5. Search/pagination and user detail.

This is the smallest slice that removes the CLI-only workflows and gives users
control over their own credentials.

## 12. Open questions

1. For admin-created accounts, use a generated temporary password first, or
   build invite links immediately?
2. Should IP and user-agent be retained for every session, or only the most
   recent login? Privacy and support value trade off here.
3. Is a read-only auditor account needed, or is the admin page sufficient?
4. Should `must_change_password` gate every API route, or only the file UI?
