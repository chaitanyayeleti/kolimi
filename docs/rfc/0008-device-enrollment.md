# RFC 0008: Multi-device E2EE enrollment

Status: draft (design) · Depends on: RFC 0007 (E2EE), RFC 0006 (sync client)

## Summary

RFC 0007 unlocks the user master key (UMK) from a passphrase, a passkey
PRF output, or the recovery code. That already works on any number of
devices — but each new device must be given one of those secrets. This
RFC adds **device-to-device enrollment**: a device that already holds the
UMK transfers it to a new device over an ephemeral X25519 exchange, so
the user does not re-type their passphrase.

The server only ever relays an opaque wrapped UMK; it cannot derive the
UMK, the device keys, or any file key.

## Threat model

- The server is honest-but-curious and may store every byte we send. It
  must learn nothing about the UMK or file keys (unchanged from RFC 0007).
- An attacker who can create an enrollment (e.g. a stolen password) but
  does **not** hold the UMK gets nothing: the enrollment is only useful
  once a device that holds the UMK approves it.
- Approval is the trust decision. The approving device shows the new
  device's name and a short **code**; the operator confirms they match.
  The server cannot forge an approval (it has no UMK).

## Crypto

Reuses the audited ECIES primitive (X25519 + HKDF-SHA256 +
XChaCha20-Poly1305) with a new domain separator, `kolimi-device-v1`:

```text
new device D:   device_secret ← random(32)         (kept on D only)
                device_public = X25519(device_secret)

approving device A (holds UMK):
    ephemeral ← random(32)
    shared    = X25519(ephemeral, device_public)
    wrap_key  = HKDF(shared, salt = eph_pub || device_public,
                     info = "kolimi-device-v1")
    wrapped   = eph_pub || nonce || AEAD(wrap_key, UMK)

new device D:
    shared    = X25519(device_secret, eph_pub)
    UMK       = AEAD_open(wrap_key, wrapped)
```

`kolimi-crypto` exposes this as `wrap_secret_for` / `unwrap_secret`
(committed vectors to follow with the implementation). The wrap is
domain-separated from share wrapping, so a share ciphertext can never be
replayed as an enrollment.

### Approval code

Approval is only meaningful if the approving device can tell that the
public key it is wrapping the UMK for really belongs to the new device
and not to the server. Both devices therefore derive a short code that
commits to the key and the enrollment id:

```text
code = BLAKE3("kolimi-enroll-code-v1" ‖ device_public_key ‖ id)  (6 bytes → 12 hex)
```

The new device computes it from its own key; the approving device
computes it from the key the server returned. A substituted key yields a
different code, so the operator sees a mismatch and the approving device
refuses. The code is a commitment, not a secret: the server can relay it,
but producing two different keys with the same code requires a BLAKE3
collision.

## Data model

```sql
CREATE TABLE e2ee_devices (
    id, user_id → users(id), name, public_key BLOB,
    created_at, last_seen_at
);
CREATE TABLE e2ee_enrollments (
    id, user_id → users(id), device_name, device_public_key BLOB,
    wrapped_master_key BLOB NULL, approved_at NULL, created_at, expires_at
);
```

Enrollments expire (default 15 minutes) and are cleaned up by the
janitor. `wrapped_master_key` stays NULL until approved.

## Protocol

1. **New device D** (authenticated by password/passkey, *not* E2EE-unlocked)
   `POST /api/e2ee/enrollments {device_name, device_public_key}` →
   `{id, expires_at}`. D derives the approval **code** from its own key and
   the id (above) and polls `GET /api/e2ee/enrollments/{id}`.
2. **Approving device A** (unlocked, holds the UMK) fetches the pending
   enrollment, sees D's name, key fingerprint, and the **code derived from
   the key the server returned**, and the operator confirms it matches D's.
   A computes `wrapped = wrap_secret_for(D.public, UMK)` and
   `POST /api/e2ee/enrollments/{id}/approve {wrapped_master_key}`. The
   server registers D in `e2ee_devices`.
3. **D** fetches `GET /api/e2ee/enrollments/{id}` → `{wrapped_master_key}`,
   runs `unwrap_secret(device_secret, wrapped)` → UMK, and stores it in the
   OS keystore (or re-wraps it under a local passkey/PRF). Enrollment is
   then deleted.

## Device management

- `GET /api/e2ee/devices` lists the account's devices (name, created,
  last seen) for the UI.
- `DELETE /api/e2ee/devices/{id}` revokes a device's record. This is
  **advisory**: the server cannot erase a UMK the device already holds, so
  true revocation means rotating the UMK and re-wrapping file keys (the
  same problem MLS solves) — documented as a limitation.

## Non-goals / open questions

- **No UMK rotation on revocation** (that is MLS / v2.1). A stolen device
  that already synced the UMK keeps decrypting data it had access to.
- Code UX: the 12-hex code is implemented (the CLI prints it; the approving
  device shows the name, fingerprint, and code). A QR payload for camera
  comparison remains a UI nicety.
- Whether an approved device should also add a passphrase/PRF wrap of its
  own to the server keyring (nice for device-independent unlock) or keep
  the UMK device-local only. Leaning: device-local by default.
- Rate-limit enrollment creation and cap pending enrollments per user.
