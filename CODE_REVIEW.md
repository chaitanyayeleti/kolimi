# Kolimi Project — Code Review (corrected status)

**Date:** 2026-10-14
**Scope:** All crates, apps, and scripts
**Note:** This keeps the original catalogue of issues but **corrects the
status column against the actual changeset**. The first automated fix pass
was not compiled or tested; it introduced regressions and left several
items untouched while marking them done. Those are recorded here.

Legend: ✅ fixed · 🟡 partial · ❌ open · ⚠️ false positive · ⛔ reverted
(reverted) · 🧪 fixed in the follow-up pass.

---

## Corrections to the original review (false positives)

| # | Original claim | Reality |
|---|---|---|
| 1 | Nonce reuse in deterministic chunk encryption | **False.** The nonce was derived from `BLAKE3(plaintext)`, so distinct plaintexts never shared a `(key, nonce)` pair; identical plaintext → identical ciphertext is the *intended* deterministic encryption for CAS/dedup. Not nonce reuse. The rewrite was reverted; the on-disk chunk format is unchanged. |
| 7 | XSS via `inner_html` QR codes | **Largely false.** `qr_svg()` renders with the `qrcode` crate (numeric `<rect>`s) — the input is encoded as modules, not interpolated as markup. The added 5-substring blacklist is ineffective and unnecessary. |
| 72 | HKDF info == AAD constant | Cosmetic domain-separation nit, not a vulnerability. Fixing it changes derived keys → changes ciphertext, so it was reverted for compatibility. |
| 75 | `content_id` uses `to_le_bytes()` (endianness-dependent) | **False.** `to_le_bytes()` is explicitly little-endian on every host (`to_ne_bytes()` is the native-endian one). The change to `to_be_bytes()` was reverted — it altered every `content_id` for no reason. |

## Regressions the first fix pass introduced (now resolved)

| Regression | Resolution |
|---|---|
| **E2EE chunk decrypt broken**: `chunk_key_for()` hashed its argument, but decrypt passed the stored hash → `BLAKE3(BLAKE3(pt))` → every chunk failed to decrypt (`cargo test -p kolimi-crypto` failed). | 🧪 Reverted `file.rs`/`keys.rs`/`identity.rs`/vectors to the original, compatible scheme. Round-trip passes (13 + 5 tests). |
| **Desktop app did not compile** (5 errors): `sign_out`'s `delete_password_only` used non-existent `keyring` methods (`get_credential`/`set_credential`) and treated `keyctl::session_delete` (returns `()`) as a `Result`. | 🧪 Rewrote as `forget_password()` using the existing `keyring_get`/`store_secrets` helpers; fixed `delete_secrets`. Also it now *actually* preserves the passphrase (the original attempt deleted the whole JSON, destroying it). |
| **File moves broke for non-root targets**: `format!("/{}{}", dest.trim_matches('/'), name)` produced `/Documentsfile.txt`. | 🧪 Fixed to `format!("{}/{}", dest.trim_end_matches('/'), name)`. |
| **`verify()` broke encrypted pulls**: applied to decrypted plaintext while encrypted manifests hash ciphertext. | 🧪 Verify each chunk's bytes against the manifest hash; run the whole-file manifest check only for plaintext. |
| `public.rs` `encode_path` no longer drops empty segments | Accepted (URLs still decode identically). |
| `ci.yml` was accidentally reduced to 4 jobs (deleting deny/audit/fuzz/ui/ffi/desktop/packaging/perf/vet/litmus) | Reverted to the full pipeline. |

---

## CRITICAL

| # | Issue | Status |
|---|---|---|
| 1 | Nonce reuse in chunk encryption | ⚠️ false positive · ⛔ reverted |
| 2 | Tombstone resurrection in sync pull | ✅ (`known.deleted \|\| locally_modified` → skip) |
| 3 | Transient pull error → remote deletion | ✅ (`404` = raced delete; other non-200 aborts) |
| 4 | Remote-deleted + local-modified → edit destroyed | ✅ (preserved as `.conflict-<ns>`) · 🟡 the preserved copy is then re-pushed since the state entry is gone (see follow-up) |
| 5 | Integer underflow in `range_segments` | ✅ (`start >= end_exclusive` → empty) |
| 6 | TOCTOU in `put_stream_access` mount root | ✅ (re-fetch child before finalize) |
| 7 | XSS via `inner_html` | ⚠️ false positive · sanitizer ineffective (left, harmless) |
| 8 | `sign_out` destroys E2EE passphrase | 🧪 fixed correctly this pass |

## HIGH

| # | Issue | Status |
|---|---|---|
| 9 | Passkey sign counter not persisted on error | ❌ open |
| 10 | `is_encrypted` defaults to `false` on error | ❌ open |
| 11 | Group member can revoke a group share | ❌ open |
| 12 | `create_user` first-admin race | ❌ open |
| 13 | `register_device` race | ❌ open |
| 14 | Encrypted: manifest committed but key upload fails | ❌ open |
| 15 | Chunk cache entries never verified | 🟡 cache is now verified when used on pull; the `chunk_bytes` cache-hit path still doesn't self-check |
| 16 | Path traversal via server-controlled `..` | ❌ open |
| 17 | Symlink following in `collect_files` | ❌ open |
| 18 | No HTTP timeouts | ❌ open |
| 19 | 2 GiB `m_cost` bound → unlock-time DoS | ❌ open |
| 20 | Silent error swallowing in the UI | ❌ open |
| 21 | WASI p2 full linker (defense-in-depth) | ❌ open |
| 22 | Empty passphrase accepted in FFI | ❌ open |
| 23 | Admin password visible in `ps` (`install.sh`) | ❌ open (the `litmus.sh` variant was fixed) |
| 24 | HTTP downloads in `litmus.sh` | ❌ open |

## MEDIUM

Not addressed in this changeset, except:

- **#37 Reassembled pull data never verified** — ✅ now: `is_consistent()` + per-chunk hash check + whole-file `verify()` for plaintext.
- **#40 Non-atomic chunk cache writes** — ✅ atomic write + `fsync`.

Everything else in **#25–#58** remains open (DB transactions/indexes #34–#36, TOTP replay #25, rate-limiter eviction #26, preview scratch leak #27, CSRF binding #30, E2EE curve-point validation #31, `SyncConfig` `Debug` leaks password #42, UI loading/toast races #43–#47, desktop mutex poisoning #48, non-atomic settings/autostart writes #50–#51, `quota_state` for deleted users #53, redundant chunk uploads #57, share-before-keys #58, …).

## LOW

The original marked this list "ALL FIXED"; in reality a subset was applied, and
the crypto items were reverted with the format rollback.

- **Applied:** #59–#65, #67, #70, #74, #76–#98, #100–#101, #103–#116.
- **Reverted / not applied:** #66 (mounts TTL cache not present), #68/#69/#71
  (zeroization — reverted with the crypto rollback; the workspace-level
  `x25519-dalek` `zeroize` feature was kept), #72/#73/#75 (reverted), #99 (UI
  tests — still none).
- **#102** (double-slash in move) was attempted but introduced a worse bug
  (missing separator); 🧪 fixed correctly in the follow-up pass.

## Follow-ups worth doing

1. **#4 conflict copy re-push**: after preserving a stale-vs-deleted file as
   `.conflict-<ns>`, the state entry is removed, so `is_conflict_name` (which
   now requires the original in state) no longer recognizes it and it gets
   pushed to the server. Track preserved copies (or keep a marker) so
   local-only conflict copies stay local.
2. **#15**: hash-check inside `chunk_bytes` on cache hit.
3. **#42**: hand-write `Debug` for `SyncConfig`/`DeviceFile` to omit the password.
4. **#16/#17/#18**: `..` rejection, `symlink_metadata` (no symlink follow), and
   `reqwest` connect/read timeouts in the sync core.
5. **Crypto zeroization (#68/#69/#71/#73)**: redo carefully *without* changing
   the chunk format (keep `hkdf` info `kolimi-chunk-v1` and the nonce scheme).

## Verified state after the follow-up pass

- `cargo test -p kolimi-crypto` — 13 + 5 pass (round-trip intact).
- `cargo test -p kolimi-chunk -p kolimi-sync` — pass.
- `cargo check --workspace --all-targets` — clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
- `cargo clippy -p kolimi-ui --target wasm32-unknown-unknown` — clean.
- `cargo fmt --all --check` (root + desktop) — clean.
- Desktop: `cargo check` + `cargo test` — pass.
- **Compatibility:** chunk ciphertext format and `content_id` hashing are
  unchanged from the released `0.1.15`, so existing encrypted data still reads.
