# RFC 0009: E2EE onboarding — first-login keyring setup, encrypt by default

Status: draft (design) · Depends on: RFC 0007 (E2EE), RFC 0008 (device
enrollment), RFC 0006 (sync client)

## Summary

RFC 0007 ships a correct key hierarchy but an awkward onboarding: E2EE is
**opt-in**, the keyring is created by a **separate CLI step**
(`kolimi-sync --e2ee-setup`), and only explicitly listed folders are
encrypted. A web-only user can never enable E2EE, and nothing is
encrypted unless someone opts in.

This RFC moves keyring creation into the **first login in the browser**
and makes **encryption the default** for the whole account. It changes
*onboarding and defaults only* — the cryptography, the key hierarchy,
sharing, device enrollment, and the server's blindness are all unchanged
from RFC 0007/0008.

The one invariant we do not relax: **the passphrase is entered by the end
user in the client and never transmitted to the server.** A design where
the admin or server supplies the passphrase at user creation is explicitly
rejected — it is not E2EE (see *Alternatives*).

## Motivation

Current state (as shipped):

1. Admin creates the login (`kolimi-server user add` / `POST /api/users`)
   — password only, no crypto.
2. *Separately*, the user runs `kolimi-sync --e2ee-setup` to generate and
   upload a keyring, and `--e2ee-root Private` to choose what is encrypted.
3. The web UI can only *unlock* an existing keyring, not create one.

Problems:

- E2EE is invisible to web-only users.
- "Nothing is encrypted unless you configure it" is a poor default for a
  product whose selling point is E2EE.
- The passphrase story ("where do I get this value?") is confusing when
  there is no keyring yet.

## Goals

- A new account can reach a working E2EE keyring **in the browser, at
  first login**, with no CLI.
- New content is **encrypted by default**; folders can opt out.
- The passphrase never leaves the client.
- Login password and encryption secret stay **separate**, so an admin
  password reset never touches encrypted data.
- Multiple unlock paths (passphrase, passkey PRF, recovery code) and
  device enrollment from RFC 0007/0008 keep working.

## Non-goals

- Changing the crypto (UMK/KEK/FK hierarchy, Argon2id parameters, chunk
  AEAD) — untouched.
- Key escrow / admin recovery of *content* — this RFC is zero-knowledge.
- Deriving the key from the login password (see *Alternatives*).
- Hiding metadata (names, sizes, access patterns) — unchanged from
  RFC 0007.

## Who enters the passphrase (the invariant)

E2EE holds only if the server never sees the material that unwraps the
master key. Therefore:

- The **login** may be created by an admin (password only).
- The **keyring** must be generated in the client (browser wasm or the
  sync client) with a passphrase the **end user** types.
- Only the **wrapped keyring** (UMK wrapped under a KEK) and KDF
  parameters are uploaded.

If an admin enters or sees the passphrase, the server can derive the KEK
and decrypt everything; that is server-side encryption, not E2EE.

## Current vs proposed

| Dimension | Current | Proposed |
|---|---|---|
| Keyring created | separate CLI step, after account exists | first login, in the browser |
| Who can enable E2EE | users who run `kolimi-sync` | any web user |
| Default scope | opt-in roots (`Private`) | whole account (opt-out folders) |
| Steps to enable | install CLI + `--e2ee-setup` | one dialog |
| Login password reset | keyring untouched | keyring untouched (same) |
| Passphrase reset | recovery code only | recovery code only (same) |
| New device | CLI enrollment | passkey or enrollment |
| Server sees | ciphertext + wrapped keys | same |
| Cryptography | UMK / KEK / FK | identical |

## Onboarding flow

1. **Account creation** (unchanged): admin creates the login, password
   only. No crypto material is generated server-side.
2. **First login (browser)**: the UI offers "Set up encryption" (default
   on; the user may defer):
   - wasm generates a random 32-byte **UMK**;
   - the user types a **passphrase**; the client derives
     `KEK = Argon2id(passphrase, salt)` and computes
     `wrapped_umk = AEAD(KEK, UMK)`;
   - the client **uploads only** `{wrapped_umk, salt, kdf_params}`;
   - the recovery code is generated and shown **once** (a second wrap of
     the UMK);
   - optionally, a **passkey** (WebAuthn PRF output → HKDF → KEK) is
     registered as an additional unlock path.
3. The account is marked E2EE-by-default: new nodes are encrypted.
4. Subsequent logins unlock with the passphrase, the passkey, or a device
   that already holds the UMK (RFC 0008 enrollment).

The existing `kolimi-sync --e2ee-setup` path remains for CLI/desktop
users; it produces the same keyring via the same endpoint.

## Default scope and opt-out

- Default encrypted root = the account root. New files under it are
  encrypted; the server marks nodes `encrypted` and never parses them.
- Opt-out folders (e.g. `Public/`, or content that needs server-side
  search/previews/sharing with non-E2EE users) may be declared plaintext.
- Encrypting a pre-existing plaintext tree is a one-time rewrite; mixed
  trees are allowed (a plaintext file in an encrypted directory is a
  client-side policy error, as in RFC 0007).
- **DAV carve-out (RFC 0010).** Keep at least one plaintext root (e.g.
  `Public/`, `Backups/`) for device integrations that speak WebDAV:
  contacts/calendar (CalDAV/CardDAV — already a separate namespace) and
  GrapheneOS Seedvault backups. A fully encrypted account leaves DAV
  empty, so this plaintext zone is required to keep those integrations
  working; enforce it with a `dav_roots` allow-list.

### Cost of encrypt-by-default

Server-side content search, previews/thumbnails, cross-file dedup, virus
scanning, and server-side collaboration do **not** work on encrypted
nodes (metadata-only search still does). For a personal cloud this is the
intended trade; team deployments should opt folders out. This must be
documented at the moment of setup.

## Password vs passphrase lifecycle

- **Login password** (auth only): reset freely — by the user or by the
  admin (`kolimi-server user recover`). No encrypted byte changes, since
  the data is wrapped under the passphrase-derived KEK, not the password.
- **Passphrase** (unwraps the UMK): the admin **cannot** reset it. The
  user recovers access with the **recovery code**, a **passkey**, or a
  **device** that already holds the UMK (RFC 0008). Losing every unlock
  path makes the data unrecoverable — the documented trade-off.
- Changing the passphrase **re-wraps the UMK**; files are never
  re-encrypted.

## Implementation sketch

- **Web UI**: a keyring-setup dialog. `kolimi-crypto` already compiles to
  wasm; Argon2id (m=64 MiB) runs in a worker to avoid blocking the UI.
- **Server**: reuse the keyring upload endpoint `kolimi-sync` already
  calls; add nothing crypto-sensitive. The server cannot validate the
  passphrase (it cannot test the wrap) — correctness is checked
  client-side, and a user with a login but no keyring is a supported
  state (the current "no keyring — set up first" path).
- **Passkey unlock**: WebAuthn PRF extension output → HKDF → KEK; the
  same ceremony that logs in also unwraps.
- **Default scope**: set the encrypted root to the account root; mark new
  nodes encrypted on push.
- **Keep**: CLI setup, sharing (`--share`/`--group`), device enrollment,
  `user recover`, and the entire key hierarchy.

## Alternatives considered

- **Admin/server enters the passphrase at creation.** Rejected: the server
  would hold the key material and could decrypt everything. Not E2EE.
- **Derive the key from the login password.** Rejected today: auth is
  HTTP Basic, so the server receives the password on every request and
  could derive the key. Safe only after switching to a PAKE (OPAQUE/SRP);
  then password unlock can be offered as an *opt-in* method labeled as
  weaker (reused/weak passwords become the encryption key).
- **Managed / escrow encryption.** The operator holds the master key, so
  both password *and* passphrase resets work and server-side features keep
  running — but it is not zero-knowledge. A valid product choice, but
  must not be called E2EE. Out of scope here.
- **Encrypt the manifest** (from RFC 0007). Deferred; unrelated to
  onboarding.

## Open questions

- Should first-login setup be **mandatory** (forced) or **offered** with
  a persistent banner until done?
- Where to hold the UMK in the browser across reloads: memory only vs
  IndexedDB-wrapped-under-passkey (convenience vs exposure).
- Argon2id cost in the browser: keep 64 MiB/t=3, or raise for wasm given
  modern devices.
- Policy for `Public/` and other opt-out folders: per-account default vs
  per-folder, and how the UI surfaces "this folder is not encrypted".
- Migration UX for existing accounts created before this RFC.
