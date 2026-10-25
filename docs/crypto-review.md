# Internal crypto review: Kolimi E2EE (v1/v2)

Status: internal review complete (external review still required before
calling E2EE production-ready). Scope: `crates/kolimi-crypto`, the
server E2EE surface (`api_e2ee`, `e2ee_file_keys`, `e2ee_keyrings`), and
the `kolimi-sync`/desktop/web integration. Spec: RFC 0007.

**MLS (RFC 0012) is a separate implementation and is not covered by this
document.** It is implemented but not externally audited; see
[`docs/audit/mls-delta.md`](audit/mls-delta.md).

## What we are defending against

- **Honest-but-curious operator (A5):** the server stores ciphertext,
  wrapped keys, and a keyring it cannot decrypt.
- **Compromised storage:** tampering with stored bytes is detected
  (AEAD + BLAKE3 + structural manifest ids), not silently accepted.
- **Credential theft on the server:** password hashes and sessions leak
  nothing about E2EE content; the keyring is useless without a secret.

Not in scope (documented non-goals): hiding sizes, mtimes, chunk counts,
chunk-equality within one file's history, or access patterns; forward
secrecy and post-compromise security for groups (MLS); rollback
protection; MLS group state/epoch handling.

## Primitives and parameters

| Purpose | Choice | Notes |
| --- | --- | --- |
| AEAD | XChaCha20-Poly1305 | 24-byte nonces, constant-time RustCrypto implementation; no hardware dependency |
| KDF | HKDF-SHA256 | per-purpose `info` strings, method-tagged AAD |
| Passphrase KDF | Argon2id, m=64 MiB, t=3, p=1 | RFC 9106 low-memory-ish profile; ~100 ms on a laptop, ~2^16 memory per guess |
| Content hashing | BLAKE3 | content ids, chunk addresses, audit chain |
| Randomness | `getrandom` (OS CSPRNG) | keys, salts, nonces |
| Zeroization | `zeroize` on `MasterKey`/`FileKey` and KEK locals | best-effort in Rust; no core dumps by default |

## Invariants (each has a test)

1. The unwrapped master key exists only in client memory; the server
   stores `nonce || AEAD(UMK)` under passphrase/recovery/PRF KEKs.
2. Every file has an independent 256-bit key; wrapping is
   `nonce || AEAD(FK)` under the UMK with AAD `kolimi-fk-v1`.
3. Chunk nonces are `HKDF(FK, "kolimi-nonce-v1" || BLAKE3(plaintext))`:
   uniqueness reduces to BLAKE3/HKDF collision resistance. Equal
   plaintext → identical `(key, nonce, message)` triple → identical
   ciphertext, which is required for CAS delta and leaks only equality
   within one file's history.
4. Wrong secrets and tampered ciphertext fail closed (`Decryption` /
   `Unlock`); no partial or unauthenticated output is ever returned.
5. Wrapped blobs are length-checked (24+32+16 bytes) before use.
6. Recovery codes are 256 random bits, displayed once, parsed
   tolerantly (grouping/whitespace), never logged.

## Attack analysis

- **Server swaps a file key:** AEAD authentication fails; the client
  errors instead of writing garbage.
- **Server swaps chunk ciphertext:** chunk hash (BLAKE3 of ciphertext)
  no longer matches the manifest address; both server-side fetch
  verification and client decryption fail.
- **Server swaps a manifest:** the manifest's structural content id is
  verified by the server on read and by `verify`/scrub; a substituted
  manifest with a matching id requires a hash collision.
- **Server serves stale ciphertext (rollback):** the client sees a
  changed content id and pulls it as a normal remote change. No
  freshness protection in v1 — documented limitation.
- **Offline attack on the keyring:** passphrase wraps cost Argon2id
  64 MiB × 3 per guess; recovery/PRF wraps are 256-bit secrets.
  A weak passphrase remains the user's responsibility; the setup UX
  warns and the recovery code is generated, not chosen.
- **PRF:** security is delegated to the authenticator; the ceremony
  runs in the platform shell and only the 32-byte output crosses the
  FFI boundary (`e2ee_prf_secret`).
- **Key loss:** losing passphrase + recovery code + PRF wraps means
  unrecoverable data; this is explicit at setup (the CLI prints the
  warning after the recovery code).

## Metadata leakage (accepted, documented)

Chunk count and ciphertext lengths (plaintext + 40 bytes/chunk),
manifest structure (hashes of ciphertext), mtimes, and access patterns
are visible to the server. Encrypted nodes can use encrypted names
(`k1_…`), so names are not visible for those nodes, but name lengths and
the access graph still leak. Encrypted nodes are excluded from content
search and previews; name/path search works on the client-side
supplement and reports no content.

## Known gaps

- Manifest is structurally plaintext in v1/v2 (GC/verify depend on it);
  encrypting it is still a candidate.
- MLS group sharing is implemented in RFC 0012 but is outside this review
  and is not externally audited.
- No external audit yet; this document lists the invariants such an
  audit should target first.
- Rollback/freshness of server responses is not protected beyond content
  ids and chunk hashes.
- Zeroization is best-effort: allocator copies and swap are outside
  our control.

## Evidence

- Committed test vectors (`crates/kolimi-crypto/tests/vectors.json`)
  pin the wire format for independent implementations.
- `crates/kolimi-server/tests/e2ee.rs`: no plaintext anywhere in the
  server data dir (marker scan), passphrase/recovery/PRF unlock,
  encrypted edit/conflict flows, and an independent raw-HTTP decoder
  reading client uploads.
- `e2ee_share`, `e2ee_devices`, `e2ee_enroll` and `e2ee_group` cover
  recipient wrapping, device enrollment, revocation and group shares.
- The WASM UI has wasm-bindgen tests; browser flows are exercised
  manually (no committed browser E2E suite yet).
- Unit tests cover determinism, tamper detection, wrong-key failure,
  keyring JSON round-trips, and length validation.
