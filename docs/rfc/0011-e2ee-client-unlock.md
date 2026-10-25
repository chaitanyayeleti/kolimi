# RFC 0011: E2EE in sync clients — locked state and per-client unlock

Status: implemented (desktop, 0.3.0) · Last verified: 0.3.0 ·
Depends on: RFC 0007 (E2EE), RFC 0008 (device
enrollment), RFC 0009 (E2EE onboarding), RFC 0006 (sync client)

## Summary

RFC 0007 defines a correct key hierarchy, but a **locked** encrypted folder
(a root that needs a passphrase the client does not hold) is reported the
same way as a genuine failure: the sync client returns an error, the tray
turns red and a failure notification fires **every poll**.

This RFC makes "locked" a **first-class, non-error state** and defines how
each client obtains the passphrase **locally** to clear it. It changes the
*client contract and UX only* — the cryptography, key hierarchy, sharing,
and the server's blindness are unchanged.

Two rules:

1. **Locked ≠ broken.** A configured encrypted root with no usable unlock
   material is a state the *user* resolves, not a sync failure. Clients show
   it distinctly, notify politely (once), and keep syncing everything else.
2. **Per-client unlock.** The keyring is unlocked independently in each
   client (browser, desktop, mobile, CLI). The passphrase is entered in the
   client and, where available, held by that client's **OS keystore**; it is
   never sent to the server. One client being locked never blocks another.

## Motivation

Current behaviour (as shipped):

- `kolimi-sync` returns `SyncError::E2ee("… no passphrase, recovery code,
  PRF, or device key …")` when an encrypted root is configured but no unlock
  material is present, and `SyncError::E2ee("no keyring on the server …")`
  when the account has no keyring yet.
- The desktop shell maps any error to the **error** tray state and a failure
  notification **every 60 s**, and it is indistinguishable from a network
  outage or a genuine bug.
- The desktop client has **no way to enter the E2EE passphrase** — it only
  ever reads one it was given — so a locked root stays locked and noisy until
  the user opens a terminal.

For a product whose promise is E2EE, "your encrypted folders are locked;
enter your passphrase" must be a calm, in-app path, not a recurring error.

## Design

### 1. The `Locked` error class (sync core)

`kolimi_sync::SyncError` gains a dedicated variant, distinct from `E2ee`:

```rust
/// E2EE is configured but locked: no keyring yet, no usable unlock
/// material locally, or the stored secret did not unlock it. A state the
/// user resolves (passphrase / recovery code / device), not a failure.
#[error("e2ee locked: {0}")]
Locked(String),
```

`Locked` is returned for the *user-action* cases: no keyring on the server,
no unlock material held, wrong passphrase, wrong recovery code, or a passkey
that does not unlock. `E2ee` remains for **policy/data** errors that are not
a simple unlock (mixed plaintext-in-encrypted-tree, malformed keyring, share
of an encrypted subtree), where retrying without a change is meaningless.

`SyncError::is_locked()` exposes the distinction to shells.

### 2. Desktop shell: a "locked" tray state

- A job that fails with `is_locked()` is counted as **locked**, not errored.
- If at least one directory is locked and nothing genuinely failed, the tray
  shows the **locked** state ("Kolimi — locked (unlock encryption)"), the
  status line reads *"Encryption locked — open Accounts & Sync to unlock"*,
  and a **single** notification fires per session (not every poll).
- Everything else still syncs; a locked root never masks real errors, and a
  real error never masquerades as locked.

### 3. Desktop shell: in-app unlock

The **Accounts & Sync** window shows an *End-to-end encryption* section for
any account with encrypted roots:

- a **locked / unlocked** badge,
- a passphrase field,
- **Unlock** (store and sync now) and **Forget** (drop the stored secret).

The passphrase is stored in the account's **OS-keystore** entry (the same
one that holds the password, RFC 0008 device/key handling unchanged), so it
never lands in `desktop.json`. Re-authenticating (sign-in) **preserves** an
already-stored passphrase instead of clearing it.

### 4. Where the keyring is created and unlocked

- **Creation** (an account with no keyring) is RFC 0009: a browser-first
  "set up encryption" wizard; the CLI `--e2ee-setup` path remains.
- **Unlock** is per client: the browser unlocks in the *Encryption* dialog
  (RFC 0007), the desktop unlocks in *Accounts & Sync* (§3), the CLI via
  `--e2ee-passphrase` / `--e2ee-recovery` / enrollment (RFC 0008).
- A client can also unlock by **device enrollment** (RFC 0008) instead of a
  passphrase; that stays first-class and is the recommended path for
  always-on machines.

## Non-goals

- Encrypt-by-default and opt-out folders — that is RFC 0009.
- Group/multi-writer E2EE and MLS — RFC 0007 / M8.
- Escrow, admin recovery of content, or deriving the key from the login
  password — explicitly out (RFC 0007/0009).

## Consequences

- The tray stops crying wolf, so "error" keeps its meaning.
- A desktop user can enable encrypted sync end-to-end without a terminal
  (given RFC 0009 for keyring creation).
- `Locked` is additive: existing `match`es on `SyncError` (all internal)
  treat it via the catch-all `Err(error)` arm; shells opt in to the nuance.

## Open questions

- Should a locked root be **retried with backoff** rather than every poll,
  or is the once-per-session notification enough? (Chosen: notify once,
  retry quietly every poll — cheap and self-healing once unlocked.)
- Should the desktop keep the passphrase only for the session (memory) by
  default, with an explicit "remember" toggle, rather than always storing it
  in the keystore?
- Mobile: rely on device enrollment (no passphrase typing) rather than a
  passphrase field, or offer both?
