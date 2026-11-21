//! Append-only, hash-chained audit log.
//!
//! Every entry hashes the previous entry's hash together with its own
//! fields, so removing, reordering, or editing any row breaks
//! [`Db::audit_verify`]. Appends are serialized through an in-process
//! mutex (SQLite has a single writer anyway), which keeps the chain
//! linear. The log is tamper-evident, not fail-closed: callers decide
//! whether an append failure aborts the audited operation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::SqliteConnection;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use futures_util::StreamExt;

use crate::{AUDIT_ENTRIES, Db, DbError, now_millis};

/// Magic line of an audit signing key file (RFC 0014).
pub const AUDIT_SIGNING_KEY_MAGIC: &str = "kolimi-audit-signing-key-v1";
/// Domain separator for checkpoint signatures.
pub const AUDIT_SIGNATURE_DOMAIN: &str = "kolimi-audit-checkpoint-signature-v1";
/// Domain separator for signing-key ids.
pub const AUDIT_KEY_ID_DOMAIN: &str = "kolimi-audit-key-v1";
/// Anchor record kind written to journals and HTTP sinks.
pub const AUDIT_ANCHOR_KIND: &str = "kolimi-audit-anchor-v1";

/// One audit entry.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditEntry {
    /// Primary key (also the chain position).
    pub id: i64,
    /// Unix milliseconds.
    pub ts: i64,
    /// Acting user, when the event has one.
    pub actor_id: Option<i64>,
    /// Non-user actor (`cli`, `system`) or a denormalized username.
    pub actor: Option<String>,
    /// Dotted action name, e.g. `file.upsert`, `auth.login`.
    pub action: String,
    /// Path, username, or share id the action targets.
    pub subject: String,
    /// JSON object with extra context.
    pub details: String,
    /// Hash of the previous entry (empty for the first).
    pub prev_hash: Vec<u8>,
    /// BLAKE3 of `prev_hash` plus this entry's fields.
    pub hash: Vec<u8>,
}

/// Parameters for an audit-log page.
#[derive(Debug, Clone, Copy)]
pub struct AuditPageQuery<'a> {
    /// Maximum rows to return.
    pub limit: i64,
    /// Return entries with an id lower than this (newest-first paging).
    pub before: Option<i64>,
    /// Exact action name, e.g. `group.add`.
    pub action: Option<&'a str>,
    /// Exact subject, e.g. a username or group name.
    pub subject: Option<&'a str>,
}

/// Result of verifying the whole chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerify {
    /// Number of retained entries checked.
    pub entries: u64,
    /// Number of checkpoint headers checked.
    pub checkpoints: u64,
    /// Checkpoints whose entry bodies were pruned.
    pub pruned_checkpoints: u64,
    /// Checkpoints carrying at least one signature.
    pub signed_checkpoints: u64,
    /// Signatures verified against a trusted key.
    pub verified_signatures: u64,
    /// Checkpoints with no signature at all.
    pub unsigned_checkpoints: u64,
    /// Signatures whose key is not trusted.
    pub untrusted_signatures: u64,
    /// Signatures that failed verification.
    pub signature_errors: u64,
    /// Anchor records checked against the local chain.
    pub anchors_checked: u64,
    /// A published head is newer than local history.
    pub rollback_detected: bool,
    /// Where trust came from (`trusted-keys`, `configured-key`, `none`).
    pub trust_source: String,
    /// Newest anchor in the supplied log.
    pub latest_anchor: Option<AuditAnchorHead>,
    /// First bad entry or checkpoint boundary, if any.
    pub first_bad: Option<i64>,
    /// Latest checkpoint, when one exists.
    pub latest_checkpoint: Option<AuditCheckpointHead>,
}

/// Result of verifying a portable audit export bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditExportVerify {
    /// Checkpoint id from the bundle header.
    pub checkpoint_id: i64,
    /// Entries whose hashes were replayed.
    pub entries: u64,
    /// Signatures present in the bundle.
    pub signatures: u64,
    /// Signatures that matched a trusted key.
    pub trusted_signatures: u64,
}

/// The last pruned audit entry. Verification starts from this trust point.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AuditAnchor {
    /// Last entry removed by retention.
    pub pruned_through: i64,
    /// Hash of that entry; the next retained row's `prev_hash`.
    pub hash: Vec<u8>,
    /// Total entries removed by retention.
    pub pruned_entries: i64,
    /// Last prune time in Unix milliseconds.
    pub updated_at: i64,
}

/// Default number of unsealed entries that triggers an automatic checkpoint.
pub const AUDIT_CHECKPOINT_ENTRIES: i64 = 1024;
/// Maximum entries in one checkpoint batch.
pub const AUDIT_CHECKPOINT_BATCH: i64 = 4096;

/// One sealed audit checkpoint (RFC 0013).
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AuditCheckpoint {
    /// Primary key.
    pub id: i64,
    /// First sealed entry id.
    pub first_entry_id: i64,
    /// Last sealed entry id.
    pub last_entry_id: i64,
    /// Number of entries in the range.
    pub entry_count: i64,
    /// Previous checkpoint header hash (empty for the first).
    pub prev_checkpoint_hash: Vec<u8>,
    /// RFC 6962-style Merkle root over the sealed entry hashes.
    pub merkle_root: Vec<u8>,
    /// Hash of this checkpoint's header.
    pub checkpoint_hash: Vec<u8>,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// When the entry bodies were exported and pruned.
    pub entries_pruned_at: Option<i64>,
}

/// One signed checkpoint (RFC 0014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSigner {
    key_id: String,
    public_key: [u8; 32],
    signing_key: SigningKey,
    label: Option<String>,
}

impl AuditSigner {
    /// Loads a signing key from a mode-`0600` file.
    pub fn load(path: &Path) -> Result<Self, DbError> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(DbError::Audit(format!(
                "audit signing key {} must not be a symlink",
                path.display()
            )));
        }
        if !metadata.is_file() {
            return Err(DbError::Audit(format!(
                "audit signing key {} is not a regular file",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(DbError::Audit(format!(
                    "audit signing key {} must not be group/other accessible (use mode 0600)",
                    path.display()
                )));
            }
        }
        let text = std::fs::read_to_string(path)?;
        let mut content = Vec::new();
        let mut label = None;
        for line in text.lines().map(str::trim) {
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("# label:") {
                label = Some(rest.trim().to_string());
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            content.push(line);
        }
        if content.len() != 2 || content[0] != AUDIT_SIGNING_KEY_MAGIC {
            return Err(DbError::Audit(format!(
                "audit signing key {} has an invalid header",
                path.display()
            )));
        }
        let mut seed_bytes = hex::decode(content[1])
            .map_err(|_| DbError::Audit("audit signing seed is not valid hex".into()))?;
        let seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DbError::Audit("audit signing seed must be 32 bytes".into()))?;
        seed_bytes.fill(0);
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = audit_key_id(&public_key);
        Ok(Self {
            key_id,
            public_key,
            signing_key,
            label,
        })
    }

    /// Generates a new key file and refuses to overwrite an existing path.
    pub fn generate(path: &Path, label: Option<&str>) -> Result<Self, DbError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|error| DbError::Audit(format!("random source: {error}")))?;
        let signing_key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = audit_key_id(&public_key);
        let mut contents = format!(
            "{AUDIT_SIGNING_KEY_MAGIC}\n{}\n",
            hex::encode(signing_key.to_bytes())
        );
        if let Some(label) = label {
            contents.push_str(&format!("# label: {label}\n"));
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = options.open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        Ok(Self {
            key_id,
            public_key,
            signing_key,
            label: label.map(str::to_string),
        })
    }

    /// Signing-key id (16 hex characters).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Raw Ed25519 public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Hex Ed25519 public key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Optional operator label.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Signs a checkpoint header hash.
    pub fn sign_hash(&self, checkpoint_hash: &[u8]) -> Result<Vec<u8>, DbError> {
        if checkpoint_hash.len() != 32 {
            return Err(DbError::Audit(
                "checkpoint hash must be 32 bytes to sign".into(),
            ));
        }
        let mut message = Vec::with_capacity(AUDIT_SIGNATURE_DOMAIN.len() + 32);
        message.extend_from_slice(AUDIT_SIGNATURE_DOMAIN.as_bytes());
        message.extend_from_slice(checkpoint_hash);
        use ed25519_dalek::Signer;
        Ok(self.signing_key.sign(&message).to_bytes().to_vec())
    }
}

/// A public key the operator trusts for checkpoint signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedAuditKey {
    /// Key id derived from the public key.
    pub key_id: String,
    /// Raw 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
}

impl TrustedAuditKey {
    /// Parses a hex public key and derives its id.
    pub fn from_hex(value: &str) -> Result<Self, DbError> {
        let public_key = hex::decode(value.trim())
            .map_err(|_| DbError::Audit("trusted key is not valid hex".into()))?;
        if public_key.len() != 32 {
            return Err(DbError::Audit(
                "trusted key must be a 32-byte Ed25519 public key".into(),
            ));
        }
        let key_id = audit_key_id(
            public_key
                .as_slice()
                .try_into()
                .map_err(|_| DbError::Audit("trusted key length".into()))?,
        );
        Ok(Self { key_id, public_key })
    }

    /// Builds a trusted key from a key id and public key, checking the id.
    pub fn from_parts(key_id: &str, public_key: Vec<u8>) -> Result<Self, DbError> {
        let array: [u8; 32] = public_key
            .as_slice()
            .try_into()
            .map_err(|_| DbError::Audit("trusted key must be 32 bytes".into()))?;
        let expected = audit_key_id(&array);
        if !key_id.is_empty() && key_id != expected {
            return Err(DbError::Audit(format!(
                "trusted key id {key_id} does not match public key ({expected})"
            )));
        }
        Ok(Self {
            key_id: expected,
            public_key,
        })
    }

    /// Reads one `key_id public_key_hex [label]` entry per line.
    pub fn parse_file(path: &Path) -> Result<Vec<Self>, DbError> {
        let text = std::fs::read_to_string(path)?;
        let mut keys = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let key_id = parts.next().unwrap_or_default();
            let Some(public_key) = parts.next() else {
                return Err(DbError::Audit(format!(
                    "{}:{}: expected `key_id public_key_hex`",
                    path.display(),
                    number + 1
                )));
            };
            let public_key = hex::decode(public_key)
                .map_err(|_| DbError::Audit("trusted key is not valid hex".into()))?;
            keys.push(Self::from_parts(key_id, public_key)?);
        }
        Ok(keys)
    }
}

/// Options for `audit verify`.
#[derive(Debug, Default)]
pub struct AuditVerifyOptions {
    /// Keys supplied by the operator.
    pub trusted_keys: Vec<TrustedAuditKey>,
    /// Fail on any checkpoint without a valid trusted signature.
    pub require_signatures: bool,
    /// Optional JSONL anchor log to cross-check.
    pub anchor_log: Option<PathBuf>,
    /// Label for where trust came from (`trusted-keys`, `configured-key`).
    pub trust_source: Option<String>,
}

/// One signature attached to a checkpoint.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditCheckpointSignature {
    /// Checkpoint id.
    pub checkpoint_id: i64,
    /// Signing-key id.
    pub key_id: String,
    /// Raw 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
    /// Signature time in Unix milliseconds.
    pub signed_at: i64,
    /// Key algorithm (`ed25519`).
    pub algorithm: String,
    /// Raw public key.
    pub public_key: Vec<u8>,
}

/// A signature inside an anchor record or export bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorSignature {
    /// Signing-key id.
    pub key_id: String,
    /// Key algorithm (`ed25519`).
    pub algorithm: String,
    /// Hex public key (informational).
    pub public_key: String,
    /// Hex signature.
    pub signature: String,
}

/// One published checkpoint head (RFC 0014).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorRecord {
    /// Record kind, [`AUDIT_ANCHOR_KIND`].
    pub kind: String,
    /// Checkpoint id.
    pub checkpoint_id: i64,
    /// First sealed entry id.
    pub first_entry_id: i64,
    /// Last sealed entry id.
    pub last_entry_id: i64,
    /// Number of sealed entries.
    pub entry_count: i64,
    /// Merkle root (hex).
    pub merkle_root: String,
    /// Checkpoint header hash (hex).
    pub checkpoint_hash: String,
    /// Checkpoint creation time in Unix milliseconds.
    pub created_at: i64,
    /// Signatures over the checkpoint hash.
    #[serde(default)]
    pub signatures: Vec<AuditAnchorSignature>,
}

/// One pending or completed anchor-outbox row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditAnchorOutboxRow {
    /// Checkpoint id.
    pub checkpoint_id: i64,
    /// Canonical anchor JSON captured at seal time.
    pub payload: String,
    /// Journal append time.
    pub journaled_at: Option<i64>,
    /// HTTP sink delivery time.
    pub delivered_at: Option<i64>,
    /// Failed attempts.
    pub attempts: i64,
    /// Next retry time.
    pub next_attempt_at: i64,
    /// Last error text.
    pub last_error: Option<String>,
}

/// Compact latest-anchor fields reported by verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditAnchorHead {
    /// Checkpoint id.
    pub checkpoint_id: i64,
    /// Last anchored entry id.
    pub last_entry_id: i64,
}

/// Compact checkpoint fields reported by verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCheckpointHead {
    /// Checkpoint id.
    pub id: i64,
    /// Last sealed entry id.
    pub last_entry_id: i64,
    /// Merkle root (hex).
    pub merkle_root: String,
}

/// Result of exporting and pruning an audit prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPruneReport {
    /// Entries written to the export file.
    pub exported: u64,
    /// Last pruned entry id.
    pub pruned_through: i64,
    /// Anchor hash (hex) for the export boundary.
    pub anchor_hash: String,
    /// Checkpoint used for a sealed prune (`None` for the legacy prefix path).
    pub checkpoint_id: Option<i64>,
}

/// One JSONL line in an audit export. `details_raw` preserves the exact
/// string covered by the chain hash; `details` is a convenience view.
#[derive(Serialize)]
struct AuditExportEntry<'a> {
    id: i64,
    ts: i64,
    actor_id: Option<i64>,
    actor: Option<&'a str>,
    action: &'a str,
    subject: &'a str,
    details: Value,
    details_raw: &'a str,
    prev_hash: String,
    hash: String,
}

/// First line of a sealed checkpoint export bundle.
#[derive(Serialize)]
struct AuditCheckpointExport {
    kind: &'static str,
    id: i64,
    first_entry_id: i64,
    last_entry_id: i64,
    entry_count: i64,
    prev_checkpoint_hash: String,
    merkle_root: String,
    checkpoint_hash: String,
    created_at: i64,
    signatures: Vec<AuditAnchorSignature>,
}

/// Header line parsed by `audit verify-export`.
#[derive(Deserialize)]
struct AuditExportHeader {
    kind: String,
    id: i64,
    first_entry_id: i64,
    last_entry_id: i64,
    entry_count: i64,
    prev_checkpoint_hash: String,
    merkle_root: String,
    checkpoint_hash: String,
    created_at: i64,
    #[serde(default)]
    signatures: Vec<AuditAnchorSignature>,
}

/// Entry line parsed by `audit verify-export`.
#[derive(Deserialize)]
struct AuditExportRow {
    id: i64,
    ts: i64,
    actor_id: Option<i64>,
    actor: Option<String>,
    action: String,
    subject: String,
    details_raw: String,
    prev_hash: String,
    hash: String,
}

fn chain_hash(
    prev_hash: &[u8],
    ts: i64,
    actor_id: Option<i64>,
    actor: Option<&str>,
    action: &str,
    subject: &str,
    details: &str,
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_hash);
    hasher.update(b"\n");
    hasher.update(ts.to_string().as_bytes());
    hasher.update(b"\n");
    if let Some(id) = actor_id {
        hasher.update(id.to_string().as_bytes());
    }
    hasher.update(b"\n");
    hasher.update(actor.unwrap_or("").as_bytes());
    hasher.update(b"\n");
    hasher.update(action.as_bytes());
    hasher.update(b"\n");
    hasher.update(subject.as_bytes());
    hasher.update(b"\n");
    hasher.update(details.as_bytes());
    hasher.finalize().as_bytes().to_vec()
}

fn merkle_leaf(entry_hash: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x00]);
    hasher.update(entry_hash);
    hasher.finalize().as_bytes().to_vec()
}

fn merkle_internal(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().as_bytes().to_vec()
}

/// RFC 6962-style root: odd nodes are promoted, not duplicated.
fn merkle_root(entry_hashes: &[Vec<u8>]) -> Option<Vec<u8>> {
    if entry_hashes.is_empty() {
        return None;
    }
    let mut level: Vec<Vec<u8>> = entry_hashes.iter().map(|hash| merkle_leaf(hash)).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if let Some(right) = pair.get(1) {
                next.push(merkle_internal(&pair[0], right));
            } else {
                next.push(pair[0].clone());
            }
        }
        level = next;
    }
    level.pop()
}

fn checkpoint_header_hash(
    prev_checkpoint_hash: &[u8],
    first_entry_id: i64,
    last_entry_id: i64,
    entry_count: i64,
    merkle_root: &[u8],
    created_at: i64,
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kolimi-audit-checkpoint-v1");
    hasher.update(prev_checkpoint_hash);
    hasher.update(&first_entry_id.to_be_bytes());
    hasher.update(&last_entry_id.to_be_bytes());
    hasher.update(&entry_count.to_be_bytes());
    hasher.update(merkle_root);
    hasher.update(&created_at.to_be_bytes());
    hasher.finalize().as_bytes().to_vec()
}

fn audit_key_id(public_key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUDIT_KEY_ID_DOMAIN.as_bytes());
    hasher.update(public_key);
    hex::encode(&hasher.finalize().as_bytes()[..8])
}

fn checkpoint_signature_message(checkpoint_hash: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(AUDIT_SIGNATURE_DOMAIN.len() + checkpoint_hash.len());
    message.extend_from_slice(AUDIT_SIGNATURE_DOMAIN.as_bytes());
    message.extend_from_slice(checkpoint_hash);
    message
}

fn verify_checkpoint_signature(
    public_key: &[u8],
    checkpoint_hash: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(public_key) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    verifying_key
        .verify(&checkpoint_signature_message(checkpoint_hash), &signature)
        .is_ok()
}

/// Inserts the signing key row (once) and a signature for `checkpoint`.
async fn store_checkpoint_signature(
    conn: &mut SqliteConnection,
    checkpoint: &AuditCheckpoint,
    signer: &AuditSigner,
) -> Result<(), DbError> {
    let existing: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT public_key FROM audit_signing_keys WHERE key_id = ?")
            .bind(signer.key_id())
            .fetch_optional(&mut *conn)
            .await?;
    if let Some(existing) = existing {
        if existing != signer.public_key() {
            return Err(DbError::Audit(format!(
                "signing key {} is already registered with a different public key",
                signer.key_id()
            )));
        }
    } else {
        sqlx::query(
            "INSERT INTO audit_signing_keys
                 (key_id, algorithm, public_key, label, created_at, retired_at)
             VALUES (?, 'ed25519', ?, ?, ?, NULL)",
        )
        .bind(signer.key_id())
        .bind(signer.public_key().as_slice())
        .bind(signer.label())
        .bind(now_millis())
        .execute(&mut *conn)
        .await?;
    }
    let signature = signer.sign_hash(&checkpoint.checkpoint_hash)?;
    sqlx::query(
        "INSERT INTO audit_checkpoint_signatures
             (checkpoint_id, key_id, signature, signed_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(checkpoint_id, key_id) DO NOTHING",
    )
    .bind(checkpoint.id)
    .bind(signer.key_id())
    .bind(&signature)
    .bind(now_millis())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Builds the canonical anchor record for a checkpoint from its signatures.
async fn build_anchor_record(
    conn: &mut SqliteConnection,
    checkpoint: &AuditCheckpoint,
) -> Result<AuditAnchorRecord, DbError> {
    let rows = sqlx::query_as::<_, AuditCheckpointSignature>(
        "SELECT s.checkpoint_id, s.key_id, s.signature, s.signed_at,
                k.algorithm, k.public_key
         FROM audit_checkpoint_signatures s
         JOIN audit_signing_keys k ON k.key_id = s.key_id
         WHERE s.checkpoint_id = ?
         ORDER BY s.key_id",
    )
    .bind(checkpoint.id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(AuditAnchorRecord {
        kind: AUDIT_ANCHOR_KIND.to_string(),
        checkpoint_id: checkpoint.id,
        first_entry_id: checkpoint.first_entry_id,
        last_entry_id: checkpoint.last_entry_id,
        entry_count: checkpoint.entry_count,
        merkle_root: hex::encode(&checkpoint.merkle_root),
        checkpoint_hash: hex::encode(&checkpoint.checkpoint_hash),
        created_at: checkpoint.created_at,
        signatures: rows
            .into_iter()
            .map(|row| AuditAnchorSignature {
                key_id: row.key_id,
                algorithm: row.algorithm,
                public_key: hex::encode(&row.public_key),
                signature: hex::encode(&row.signature),
            })
            .collect(),
    })
}

impl Db {
    /// Appends an entry to the audit log, chaining it onto the previous one.
    pub async fn audit_append(
        &self,
        actor_id: Option<i64>,
        actor: Option<&str>,
        action: &str,
        subject: &str,
        details: &Value,
    ) -> Result<(), DbError> {
        let _guard = self.audit_lock.lock().await;
        let mut conn = self.pool.acquire().await?;
        append_chained(&mut conn, actor_id, actor, action, subject, details).await
    }

    /// Appends an audit entry on an existing connection (used to make a
    /// multi-statement operation atomic — see [`Db::record_change`]).
    pub(crate) async fn audit_append_on(
        &self,
        conn: &mut SqliteConnection,
        actor_id: Option<i64>,
        actor: Option<&str>,
        action: &str,
        subject: &str,
        details: &Value,
    ) -> Result<(), DbError> {
        append_chained(conn, actor_id, actor, action, subject, details).await
    }
}

/// Chains and inserts an audit row on `conn` (the caller owns the transaction).
async fn append_chained(
    conn: &mut SqliteConnection,
    actor_id: Option<i64>,
    actor: Option<&str>,
    action: &str,
    subject: &str,
    details: &Value,
) -> Result<(), DbError> {
    let details = details.to_string();
    let ts = now_millis();
    let prev: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await?;
    let prev_hash = prev.unwrap_or_default();
    let hash = chain_hash(&prev_hash, ts, actor_id, actor, action, subject, &details);
    sqlx::query(
        "INSERT INTO audit_log (ts, actor_id, actor, action, subject, details, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(ts)
    .bind(actor_id)
    .bind(actor)
    .bind(action)
    .bind(subject)
    .bind(&details)
    .bind(&prev_hash)
    .bind(&hash)
    .execute(&mut *conn)
    .await?;
    AUDIT_ENTRIES.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

impl Db {
    /// Lists audit entries newest first, optionally before `before` (id).
    pub async fn audit_list(
        &self,
        limit: i64,
        before: Option<i64>,
    ) -> Result<Vec<AuditEntry>, DbError> {
        self.audit_page(AuditPageQuery {
            limit,
            before,
            action: None,
            subject: None,
        })
        .await
    }

    /// Lists audit entries newest first with optional exact-match filters.
    pub async fn audit_page(&self, query: AuditPageQuery<'_>) -> Result<Vec<AuditEntry>, DbError> {
        let limit = query.limit.clamp(1, 1000);
        Ok(sqlx::query_as::<_, AuditEntry>(
            "SELECT * FROM audit_log
             WHERE (? IS NULL OR id < ?)
               AND (? IS NULL OR action = ?)
               AND (? IS NULL OR subject = ?)
             ORDER BY id DESC LIMIT ?",
        )
        .bind(query.before)
        .bind(query.before)
        .bind(query.action)
        .bind(query.action)
        .bind(query.subject)
        .bind(query.subject)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// The current retention anchor, if entries have been pruned.
    pub async fn audit_anchor(&self) -> Result<Option<AuditAnchor>, DbError> {
        Ok(sqlx::query_as::<_, AuditAnchor>(
            "SELECT pruned_through, hash, pruned_entries, updated_at
             FROM audit_anchor WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Checkpoint headers, newest first.
    pub async fn audit_checkpoints(&self, limit: i64) -> Result<Vec<AuditCheckpoint>, DbError> {
        Ok(sqlx::query_as::<_, AuditCheckpoint>(
            "SELECT * FROM audit_checkpoints ORDER BY id DESC LIMIT ?",
        )
        .bind(limit.clamp(1, 10_000))
        .fetch_all(&self.pool)
        .await?)
    }

    /// One checkpoint header.
    pub async fn audit_checkpoint(
        &self,
        checkpoint_id: i64,
    ) -> Result<Option<AuditCheckpoint>, DbError> {
        Ok(
            sqlx::query_as::<_, AuditCheckpoint>("SELECT * FROM audit_checkpoints WHERE id = ?")
                .bind(checkpoint_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// The checkpoint that ends exactly at `entry_id`.
    pub async fn audit_checkpoint_ending_at(
        &self,
        entry_id: i64,
    ) -> Result<Option<AuditCheckpoint>, DbError> {
        Ok(sqlx::query_as::<_, AuditCheckpoint>(
            "SELECT * FROM audit_checkpoints WHERE last_entry_id = ?",
        )
        .bind(entry_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Number of entries after the latest checkpoint or anchor.
    pub async fn audit_unsealed_count(&self) -> Result<i64, DbError> {
        let max_id: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM audit_log")
            .fetch_one(&self.pool)
            .await?;
        let Some(max_id) = max_id else {
            return Ok(0);
        };
        let last_checkpoint: Option<i64> = sqlx::query_scalar(
            "SELECT last_entry_id FROM audit_checkpoints ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        let anchor = self.audit_anchor().await?;
        let from = last_checkpoint
            .map(|last| last + 1)
            .or_else(|| anchor.map(|anchor| anchor.pruned_through + 1))
            .unwrap_or(1);
        Ok((max_id - from + 1).max(0))
    }

    /// Timestamp of the oldest unsealed entry, if any.
    pub async fn audit_oldest_unsealed_ts(&self) -> Result<Option<i64>, DbError> {
        let max_id: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM audit_log")
            .fetch_one(&self.pool)
            .await?;
        let Some(max_id) = max_id else {
            return Ok(None);
        };
        let last_checkpoint: Option<i64> = sqlx::query_scalar(
            "SELECT last_entry_id FROM audit_checkpoints ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        let anchor = self.audit_anchor().await?;
        let from = last_checkpoint
            .map(|last| last + 1)
            .or_else(|| anchor.map(|anchor| anchor.pruned_through + 1))
            .unwrap_or(1);
        if max_id < from {
            return Ok(None);
        }
        Ok(
            sqlx::query_scalar("SELECT MIN(ts) FROM audit_log WHERE id >= ?")
                .bind(from)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    /// Seals up to `max_entries` unsealed entries into one checkpoint.
    ///
    /// Returns `None` when there is no unsealed entry left. The append lock
    /// makes the chosen range stable: appends either land before the maximum
    /// id or wait for the checkpoint transaction.
    pub async fn audit_seal(&self, max_entries: i64) -> Result<Option<AuditCheckpoint>, DbError> {
        self.audit_seal_with(max_entries, None, false).await
    }

    /// Seals up to `max_entries` entries, signs the new checkpoint when a
    /// signer is supplied, and enqueues its anchor record when requested.
    /// The checkpoint, signature, and outbox row commit atomically.
    pub async fn audit_seal_with(
        &self,
        max_entries: i64,
        signer: Option<&AuditSigner>,
        enqueue_anchor: bool,
    ) -> Result<Option<AuditCheckpoint>, DbError> {
        let max_entries = max_entries.clamp(1, AUDIT_CHECKPOINT_BATCH);
        let _guard = self.audit_lock.lock().await;
        let mut tx = self.begin_write().await?;
        let anchor = sqlx::query_as::<_, AuditAnchor>(
            "SELECT pruned_through, hash, pruned_entries, updated_at
             FROM audit_anchor WHERE id = 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let last_checkpoint = sqlx::query_as::<_, AuditCheckpoint>(
            "SELECT * FROM audit_checkpoints ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let from = last_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.last_entry_id + 1)
            .or_else(|| anchor.as_ref().map(|anchor| anchor.pruned_through + 1))
            .unwrap_or(1);
        let max_id: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM audit_log")
            .fetch_one(&mut *tx)
            .await?;
        let Some(max_id) = max_id else {
            return Ok(None);
        };
        if max_id < from {
            return Ok(None);
        }
        let last_entry_id = max_id.min(from + max_entries - 1);
        let rows = sqlx::query_as::<_, AuditEntry>(
            "SELECT * FROM audit_log WHERE id BETWEEN ? AND ? ORDER BY id",
        )
        .bind(from)
        .bind(last_entry_id)
        .fetch_all(&mut *tx)
        .await?;
        if rows.len() as i64 != last_entry_id - from + 1 {
            return Err(DbError::Audit(format!(
                "audit entries are not contiguous between {from} and {last_entry_id}"
            )));
        }

        let mut expected_prev = if from > 1 {
            let prior: Option<Vec<u8>> =
                sqlx::query_scalar("SELECT hash FROM audit_log WHERE id = ?")
                    .bind(from - 1)
                    .fetch_optional(&mut *tx)
                    .await?;
            prior
                .or_else(|| {
                    anchor
                        .as_ref()
                        .filter(|anchor| anchor.pruned_through == from - 1)
                        .map(|anchor| anchor.hash.clone())
                })
                .unwrap_or_else(|| rows[0].prev_hash.clone())
        } else {
            Vec::new()
        };

        let mut entry_hashes = Vec::with_capacity(rows.len());
        for (offset, row) in rows.iter().enumerate() {
            if row.id != from + offset as i64 {
                return Err(DbError::Audit(format!(
                    "audit entry {} is out of order (expected {})",
                    row.id,
                    from + offset as i64
                )));
            }
            let expected = chain_hash(
                &expected_prev,
                row.ts,
                row.actor_id,
                row.actor.as_deref(),
                &row.action,
                &row.subject,
                &row.details,
            );
            if row.prev_hash != expected_prev || row.hash != expected {
                return Err(DbError::Audit(format!(
                    "chain mismatch at audit entry {}; refusing to seal",
                    row.id
                )));
            }
            expected_prev = row.hash.clone();
            entry_hashes.push(row.hash.clone());
        }
        let merkle_root = merkle_root(&entry_hashes)
            .ok_or_else(|| DbError::Audit("cannot seal an empty audit range".into()))?;
        let prev_checkpoint_hash = last_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.checkpoint_hash.clone())
            .unwrap_or_default();
        let created_at = now_millis();
        let checkpoint_hash = checkpoint_header_hash(
            &prev_checkpoint_hash,
            from,
            last_entry_id,
            rows.len() as i64,
            &merkle_root,
            created_at,
        );
        let checkpoint = sqlx::query_as::<_, AuditCheckpoint>(
            "INSERT INTO audit_checkpoints
                 (first_entry_id, last_entry_id, entry_count, prev_checkpoint_hash,
                  merkle_root, checkpoint_hash, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             RETURNING *",
        )
        .bind(from)
        .bind(last_entry_id)
        .bind(rows.len() as i64)
        .bind(&prev_checkpoint_hash)
        .bind(&merkle_root)
        .bind(&checkpoint_hash)
        .bind(created_at)
        .fetch_one(&mut *tx)
        .await?;
        if let Some(signer) = signer {
            store_checkpoint_signature(&mut tx, &checkpoint, signer).await?;
        }
        if enqueue_anchor {
            let record = build_anchor_record(&mut tx, &checkpoint).await?;
            let payload = serde_json::to_string(&record)
                .map_err(|error| DbError::Audit(format!("anchor payload: {error}")))?;
            let now = now_millis();
            sqlx::query(
                "INSERT INTO audit_anchor_outbox
                     (checkpoint_id, payload, journaled_at, delivered_at, attempts,
                      next_attempt_at, last_error)
                 VALUES (?, ?, NULL, NULL, 0, ?, NULL)
                 ON CONFLICT(checkpoint_id) DO UPDATE SET payload = excluded.payload",
            )
            .bind(checkpoint.id)
            .bind(payload)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(Some(checkpoint))
    }

    /// Seals checkpoints while at least `threshold` entries are unsealed.
    pub async fn audit_seal_pending(
        &self,
        threshold: i64,
        batch: i64,
        max_checkpoints: u64,
    ) -> Result<u64, DbError> {
        self.audit_seal_if_due(threshold, 0, batch, max_checkpoints, None, false)
            .await
    }

    /// Seals while the unsealed tail is at least `threshold` entries or its
    /// oldest entry is at least `max_age_millis` old.
    pub async fn audit_seal_if_due(
        &self,
        threshold: i64,
        max_age_millis: i64,
        batch: i64,
        max_checkpoints: u64,
        signer: Option<&AuditSigner>,
        enqueue_anchor: bool,
    ) -> Result<u64, DbError> {
        let mut sealed = 0u64;
        while sealed < max_checkpoints {
            let count = self.audit_unsealed_count().await?;
            if count == 0 {
                break;
            }
            let mut due = count >= threshold.max(1);
            if !due
                && max_age_millis > 0
                && let Some(ts) = self.audit_oldest_unsealed_ts().await?
                && now_millis() - ts >= max_age_millis
            {
                due = true;
            }
            if !due {
                break;
            }
            if self
                .audit_seal_with(batch, signer, enqueue_anchor)
                .await?
                .is_none()
            {
                break;
            }
            sealed += 1;
        }
        Ok(sealed)
    }

    /// Adds signatures to existing checkpoints (backfill or key rotation).
    /// With `all`, only checkpoints lacking a signature from this key are
    /// selected. Returns the number of checkpoints signed.
    pub async fn audit_sign_checkpoints(
        &self,
        checkpoint_id: Option<i64>,
        all: bool,
        signer: &AuditSigner,
    ) -> Result<u64, DbError> {
        let _guard = self.audit_lock.lock().await;
        let checkpoints = if let Some(id) = checkpoint_id {
            sqlx::query_as::<_, AuditCheckpoint>("SELECT * FROM audit_checkpoints WHERE id = ?")
                .bind(id)
                .fetch_all(&self.pool)
                .await?
        } else if all {
            sqlx::query_as::<_, AuditCheckpoint>(
                "SELECT c.* FROM audit_checkpoints c
                 WHERE NOT EXISTS (
                     SELECT 1 FROM audit_checkpoint_signatures s
                     WHERE s.checkpoint_id = c.id AND s.key_id = ?
                 )
                 ORDER BY c.id",
            )
            .bind(signer.key_id())
            .fetch_all(&self.pool)
            .await?
        } else {
            return Err(DbError::Audit("specify --checkpoint ID or --all".into()));
        };
        if checkpoint_id.is_some() && checkpoints.is_empty() {
            return Err(DbError::Audit(format!(
                "no checkpoint {}",
                checkpoint_id.unwrap_or_default()
            )));
        }
        let mut tx = self.begin_write().await?;
        for checkpoint in &checkpoints {
            let recomputed = checkpoint_header_hash(
                &checkpoint.prev_checkpoint_hash,
                checkpoint.first_entry_id,
                checkpoint.last_entry_id,
                checkpoint.entry_count,
                &checkpoint.merkle_root,
                checkpoint.created_at,
            );
            if recomputed != checkpoint.checkpoint_hash {
                return Err(DbError::Audit(format!(
                    "checkpoint {} header hash does not match; refusing to sign",
                    checkpoint.id
                )));
            }
            store_checkpoint_signature(&mut tx, checkpoint, signer).await?;
        }
        tx.commit().await?;
        Ok(checkpoints.len() as u64)
    }

    /// Signatures attached to one checkpoint, with key metadata.
    pub async fn audit_checkpoint_signatures(
        &self,
        checkpoint_id: i64,
    ) -> Result<Vec<AuditCheckpointSignature>, DbError> {
        Ok(sqlx::query_as::<_, AuditCheckpointSignature>(
            "SELECT s.checkpoint_id, s.key_id, s.signature, s.signed_at,
                    k.algorithm, k.public_key
             FROM audit_checkpoint_signatures s
             JOIN audit_signing_keys k ON k.key_id = s.key_id
             WHERE s.checkpoint_id = ?
             ORDER BY s.key_id",
        )
        .bind(checkpoint_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// The canonical anchor record for one checkpoint, or the latest.
    pub async fn audit_anchor_record(
        &self,
        checkpoint_id: Option<i64>,
    ) -> Result<Option<AuditAnchorRecord>, DbError> {
        let checkpoint = match checkpoint_id {
            Some(id) => {
                sqlx::query_as::<_, AuditCheckpoint>("SELECT * FROM audit_checkpoints WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_as::<_, AuditCheckpoint>(
                    "SELECT * FROM audit_checkpoints ORDER BY id DESC LIMIT 1",
                )
                .fetch_optional(&self.pool)
                .await?
            }
        };
        let Some(checkpoint) = checkpoint else {
            return Ok(None);
        };
        let mut conn = self.pool.acquire().await?;
        Ok(Some(build_anchor_record(&mut conn, &checkpoint).await?))
    }

    /// Anchor-outbox rows that still need a configured sink.
    pub async fn audit_anchor_pending(
        &self,
        journal: bool,
        http: bool,
        now: i64,
        limit: i64,
    ) -> Result<Vec<AuditAnchorOutboxRow>, DbError> {
        if !journal && !http {
            return Ok(Vec::new());
        }
        Ok(sqlx::query_as::<_, AuditAnchorOutboxRow>(
            "SELECT checkpoint_id, payload, journaled_at, delivered_at,
                    attempts, next_attempt_at, last_error
             FROM audit_anchor_outbox
             WHERE next_attempt_at <= ?
               AND ((? AND journaled_at IS NULL) OR (? AND delivered_at IS NULL))
             ORDER BY checkpoint_id
             LIMIT ?",
        )
        .bind(now)
        .bind(journal)
        .bind(http)
        .bind(limit.clamp(1, 1000))
        .fetch_all(&self.pool)
        .await?)
    }

    /// Number of rows that still need a configured sink.
    pub async fn audit_anchor_pending_count(
        &self,
        journal: bool,
        http: bool,
    ) -> Result<i64, DbError> {
        if !journal && !http {
            return Ok(0);
        }
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_anchor_outbox
             WHERE (? AND journaled_at IS NULL) OR (? AND delivered_at IS NULL)",
        )
        .bind(journal)
        .bind(http)
        .fetch_one(&self.pool)
        .await?)
    }

    /// All anchor-outbox rows, newest first, for `audit anchors`.
    pub async fn audit_anchor_outbox(
        &self,
        limit: i64,
    ) -> Result<Vec<AuditAnchorOutboxRow>, DbError> {
        Ok(sqlx::query_as::<_, AuditAnchorOutboxRow>(
            "SELECT checkpoint_id, payload, journaled_at, delivered_at,
                    attempts, next_attempt_at, last_error
             FROM audit_anchor_outbox
             ORDER BY checkpoint_id DESC
             LIMIT ?",
        )
        .bind(limit.clamp(1, 10_000))
        .fetch_all(&self.pool)
        .await?)
    }

    /// Marks the journal sink as done for a checkpoint.
    pub async fn audit_anchor_mark_journaled(
        &self,
        checkpoint_id: i64,
        at: i64,
    ) -> Result<(), DbError> {
        sqlx::query("UPDATE audit_anchor_outbox SET journaled_at = ? WHERE checkpoint_id = ?")
            .bind(at)
            .bind(checkpoint_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Marks the HTTP sink as done for a checkpoint.
    pub async fn audit_anchor_mark_delivered(
        &self,
        checkpoint_id: i64,
        at: i64,
    ) -> Result<(), DbError> {
        sqlx::query("UPDATE audit_anchor_outbox SET delivered_at = ? WHERE checkpoint_id = ?")
            .bind(at)
            .bind(checkpoint_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Records a failed attempt and its next retry time.
    pub async fn audit_anchor_mark_failed(
        &self,
        checkpoint_id: i64,
        error: &str,
        next_attempt_at: i64,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE audit_anchor_outbox
             SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?
             WHERE checkpoint_id = ?",
        )
        .bind(next_attempt_at)
        .bind(error)
        .bind(checkpoint_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Exports entries up to `before` as JSONL and prunes them, recording an
    /// anchor so the retained tail still verifies.
    ///
    /// The export is written and fsynced before the delete commits. At least
    /// the newest entry is always retained, so SQLite cannot reuse its id
    /// after the table becomes empty.
    pub async fn audit_export_and_prune(
        &self,
        before: i64,
        to: &Path,
    ) -> Result<AuditPruneReport, DbError> {
        let _guard = self.audit_lock.lock().await;
        if before <= 0 {
            return Err(DbError::Audit(
                "--before must be a positive entry id".into(),
            ));
        }
        if tokio::fs::try_exists(to).await? {
            return Err(DbError::Audit(format!(
                "refusing to overwrite existing export {}",
                to.display()
            )));
        }
        if let Some(parent) = to.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await?;
        }
        let Some(file_name) = to.file_name().and_then(|name| name.to_str()) else {
            return Err(DbError::Audit("export path has no filename".into()));
        };
        let temp = to.with_file_name(format!(".{file_name}.tmp-{}", now_millis()));
        let result = self.audit_export_and_prune_inner(before, to, &temp).await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temp).await;
        }
        result
    }

    async fn audit_export_and_prune_inner(
        &self,
        before: i64,
        to: &Path,
        temp: &Path,
    ) -> Result<AuditPruneReport, DbError> {
        let mut tx = self.begin_write().await?;
        let anchor = sqlx::query_as::<_, AuditAnchor>(
            "SELECT pruned_through, hash, pruned_entries, updated_at
             FROM audit_anchor WHERE id = 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let from = anchor.as_ref().map(|a| a.pruned_through).unwrap_or(0);
        if before <= from {
            return Err(DbError::Audit(format!(
                "entries through {from} were already pruned"
            )));
        }
        let max_id: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM audit_log")
            .fetch_one(&mut *tx)
            .await?;
        let Some(max_id) = max_id else {
            return Err(DbError::Audit("the audit log is empty".into()));
        };
        if before >= max_id {
            return Err(DbError::Audit(format!(
                "refusing to prune the newest entry; use --before less than {max_id}"
            )));
        }

        let mut expected_prev = anchor
            .as_ref()
            .map(|anchor| anchor.hash.clone())
            .unwrap_or_default();
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp)
            .await?;
        let mut exported = 0u64;
        let mut last_id = 0i64;
        let mut last_hash = Vec::new();
        {
            let mut rows = sqlx::query_as::<_, AuditEntry>(
                "SELECT * FROM audit_log WHERE id > ? AND id <= ? ORDER BY id",
            )
            .bind(from)
            .bind(before)
            .fetch(&mut *tx);
            while let Some(row) = rows.next().await {
                let row = row?;
                let expected = chain_hash(
                    &expected_prev,
                    row.ts,
                    row.actor_id,
                    row.actor.as_deref(),
                    &row.action,
                    &row.subject,
                    &row.details,
                );
                if row.prev_hash != expected_prev || row.hash != expected {
                    return Err(DbError::Audit(format!(
                        "chain mismatch at audit entry {}; refusing to prune",
                        row.id
                    )));
                }
                let details = serde_json::from_str(&row.details)
                    .unwrap_or_else(|_| Value::String(row.details.clone()));
                let export = AuditExportEntry {
                    id: row.id,
                    ts: row.ts,
                    actor_id: row.actor_id,
                    actor: row.actor.as_deref(),
                    action: &row.action,
                    subject: &row.subject,
                    details,
                    details_raw: &row.details,
                    prev_hash: hex::encode(&row.prev_hash),
                    hash: hex::encode(&row.hash),
                };
                let mut line = serde_json::to_vec(&export)
                    .map_err(|error| DbError::Audit(error.to_string()))?;
                line.push(b'\n');
                file.write_all(&line).await?;
                exported += 1;
                last_id = row.id;
                last_hash = row.hash.clone();
                expected_prev = row.hash;
            }
        }
        if exported == 0 {
            return Err(DbError::Audit(format!(
                "no audit entries found between {from} and {before}"
            )));
        }
        // The retained tail must link to the anchor we are about to write.
        let next_prev: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT prev_hash FROM audit_log WHERE id > ? ORDER BY id LIMIT 1")
                .bind(before)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(next_prev) = next_prev
            && next_prev != last_hash
        {
            return Err(DbError::Audit(
                "retained audit tail does not link to the pruned prefix".into(),
            ));
        }

        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(temp, to).await?;

        sqlx::query("DELETE FROM audit_log WHERE id <= ?")
            .bind(last_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO audit_anchor (id, pruned_through, hash, pruned_entries, updated_at)
             VALUES (1, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                 pruned_through = excluded.pruned_through,
                 hash = excluded.hash,
                 pruned_entries = audit_anchor.pruned_entries + excluded.pruned_entries,
                 updated_at = excluded.updated_at",
        )
        .bind(last_id)
        .bind(&last_hash)
        .bind(exported as i64)
        .bind(now_millis())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(AuditPruneReport {
            exported,
            pruned_through: last_id,
            anchor_hash: hex::encode(last_hash),
            checkpoint_id: None,
        })
    }

    /// Exports a sealed checkpoint's entries as a JSONL bundle and prunes
    /// them. The checkpoint header remains, with `entries_pruned_at` set.
    pub async fn audit_export_and_prune_checkpoint(
        &self,
        checkpoint_id: i64,
        to: &Path,
    ) -> Result<AuditPruneReport, DbError> {
        let _guard = self.audit_lock.lock().await;
        if tokio::fs::try_exists(to).await? {
            return Err(DbError::Audit(format!(
                "refusing to overwrite existing export {}",
                to.display()
            )));
        }
        if let Some(parent) = to.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await?;
        }
        let Some(file_name) = to.file_name().and_then(|name| name.to_str()) else {
            return Err(DbError::Audit("export path has no filename".into()));
        };
        let temp = to.with_file_name(format!(".{file_name}.tmp-{}", now_millis()));
        let result = self
            .audit_export_and_prune_checkpoint_inner(checkpoint_id, to, &temp)
            .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temp).await;
        }
        result
    }

    async fn audit_export_and_prune_checkpoint_inner(
        &self,
        checkpoint_id: i64,
        to: &Path,
        temp: &Path,
    ) -> Result<AuditPruneReport, DbError> {
        let mut tx = self.begin_write().await?;
        let checkpoint =
            sqlx::query_as::<_, AuditCheckpoint>("SELECT * FROM audit_checkpoints WHERE id = ?")
                .bind(checkpoint_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| DbError::Audit(format!("no checkpoint {checkpoint_id}")))?;
        if checkpoint.entries_pruned_at.is_some() {
            return Err(DbError::Audit(format!(
                "checkpoint {checkpoint_id} was already pruned"
            )));
        }
        let older_unpruned: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM audit_checkpoints
             WHERE id < ? AND entries_pruned_at IS NULL
             ORDER BY id LIMIT 1",
        )
        .bind(checkpoint_id)
        .fetch_optional(&mut *tx)
        .await?;
        if older_unpruned.is_some() {
            return Err(DbError::Audit(
                "prune the oldest unpruned checkpoint first".into(),
            ));
        }
        let max_id: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM audit_log")
            .fetch_one(&mut *tx)
            .await?;
        let Some(max_id) = max_id else {
            return Err(DbError::Audit("the audit log is empty".into()));
        };
        if checkpoint.last_entry_id >= max_id {
            return Err(DbError::Audit(format!(
                "refusing to prune the newest entry; append another audit entry first (last id {max_id})"
            )));
        }
        let rows = sqlx::query_as::<_, AuditEntry>(
            "SELECT * FROM audit_log WHERE id BETWEEN ? AND ? ORDER BY id",
        )
        .bind(checkpoint.first_entry_id)
        .bind(checkpoint.last_entry_id)
        .fetch_all(&mut *tx)
        .await?;
        if rows.len() as i64 != checkpoint.entry_count {
            return Err(DbError::Audit(format!(
                "checkpoint {checkpoint_id} entries are incomplete"
            )));
        }
        let mut expected_prev = if checkpoint.first_entry_id == 1 {
            Vec::new()
        } else {
            rows[0].prev_hash.clone()
        };
        let mut entry_hashes = Vec::with_capacity(rows.len());
        let mut last_hash = Vec::new();
        for (offset, row) in rows.iter().enumerate() {
            if row.id != checkpoint.first_entry_id + offset as i64 {
                return Err(DbError::Audit(format!(
                    "checkpoint {checkpoint_id} range is not contiguous at entry {}",
                    row.id
                )));
            }
            let expected = chain_hash(
                &expected_prev,
                row.ts,
                row.actor_id,
                row.actor.as_deref(),
                &row.action,
                &row.subject,
                &row.details,
            );
            if row.prev_hash != expected_prev || row.hash != expected {
                return Err(DbError::Audit(format!(
                    "chain mismatch at audit entry {}; refusing to prune",
                    row.id
                )));
            }
            expected_prev = row.hash.clone();
            last_hash = row.hash.clone();
            entry_hashes.push(row.hash.clone());
        }
        let root = merkle_root(&entry_hashes)
            .ok_or_else(|| DbError::Audit("checkpoint range is empty".into()))?;
        if root != checkpoint.merkle_root {
            return Err(DbError::Audit(format!(
                "checkpoint {checkpoint_id} Merkle root does not match its entries"
            )));
        }

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp)
            .await?;
        let signature_rows = sqlx::query_as::<_, AuditCheckpointSignature>(
            "SELECT s.checkpoint_id, s.key_id, s.signature, s.signed_at,
                    k.algorithm, k.public_key
             FROM audit_checkpoint_signatures s
             JOIN audit_signing_keys k ON k.key_id = s.key_id
             WHERE s.checkpoint_id = ?
             ORDER BY s.key_id",
        )
        .bind(checkpoint.id)
        .fetch_all(&mut *tx)
        .await?;
        let header = AuditCheckpointExport {
            kind: "kolimi-audit-checkpoint",
            id: checkpoint.id,
            first_entry_id: checkpoint.first_entry_id,
            last_entry_id: checkpoint.last_entry_id,
            entry_count: checkpoint.entry_count,
            prev_checkpoint_hash: hex::encode(&checkpoint.prev_checkpoint_hash),
            merkle_root: hex::encode(&checkpoint.merkle_root),
            checkpoint_hash: hex::encode(&checkpoint.checkpoint_hash),
            created_at: checkpoint.created_at,
            signatures: signature_rows
                .into_iter()
                .map(|row| AuditAnchorSignature {
                    key_id: row.key_id,
                    algorithm: row.algorithm,
                    public_key: hex::encode(&row.public_key),
                    signature: hex::encode(&row.signature),
                })
                .collect(),
        };
        let mut line =
            serde_json::to_vec(&header).map_err(|error| DbError::Audit(error.to_string()))?;
        line.push(b'\n');
        file.write_all(&line).await?;
        for row in &rows {
            let details = serde_json::from_str(&row.details)
                .unwrap_or_else(|_| Value::String(row.details.clone()));
            let export = AuditExportEntry {
                id: row.id,
                ts: row.ts,
                actor_id: row.actor_id,
                actor: row.actor.as_deref(),
                action: &row.action,
                subject: &row.subject,
                details,
                details_raw: &row.details,
                prev_hash: hex::encode(&row.prev_hash),
                hash: hex::encode(&row.hash),
            };
            let mut line =
                serde_json::to_vec(&export).map_err(|error| DbError::Audit(error.to_string()))?;
            line.push(b'\n');
            file.write_all(&line).await?;
        }
        let next_prev: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT prev_hash FROM audit_log WHERE id > ? ORDER BY id LIMIT 1")
                .bind(checkpoint.last_entry_id)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(next_prev) = next_prev
            && next_prev != last_hash
        {
            return Err(DbError::Audit(
                "retained audit tail does not link to the checkpoint".into(),
            ));
        }

        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(temp, to).await?;

        sqlx::query("DELETE FROM audit_log WHERE id <= ?")
            .bind(checkpoint.last_entry_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE audit_checkpoints SET entries_pruned_at = ? WHERE id = ?")
            .bind(now_millis())
            .bind(checkpoint.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO audit_anchor (id, pruned_through, hash, pruned_entries, updated_at)
             VALUES (1, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                 pruned_through = excluded.pruned_through,
                 hash = excluded.hash,
                 pruned_entries = audit_anchor.pruned_entries + excluded.pruned_entries,
                 updated_at = excluded.updated_at",
        )
        .bind(checkpoint.last_entry_id)
        .bind(&last_hash)
        .bind(checkpoint.entry_count)
        .bind(now_millis())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(AuditPruneReport {
            exported: checkpoint.entry_count as u64,
            pruned_through: checkpoint.last_entry_id,
            anchor_hash: hex::encode(last_hash),
            checkpoint_id: Some(checkpoint.id),
        })
    }

    /// Verifies a sealed checkpoint export bundle.
    pub async fn audit_verify_export(&self, path: &Path) -> Result<AuditExportVerify, DbError> {
        self.audit_verify_export_with(path, &[]).await
    }

    /// Verifies a bundle and checks signatures against trusted keys. With no
    /// trusted keys, signatures are checked against their included public
    /// key (self-signed evidence only).
    pub async fn audit_verify_export_with(
        &self,
        path: &Path,
        trusted_keys: &[TrustedAuditKey],
    ) -> Result<AuditExportVerify, DbError> {
        let file = tokio::fs::File::open(path).await?;
        let mut lines = tokio::io::BufReader::new(file).lines();
        let Some(header_line) = lines.next_line().await? else {
            return Err(DbError::Audit("export is empty".into()));
        };
        let header: AuditExportHeader = serde_json::from_str(&header_line)
            .map_err(|error| DbError::Audit(format!("export header: {error}")))?;
        if header.kind != "kolimi-audit-checkpoint" {
            return Err(DbError::Audit("export header is not a checkpoint".into()));
        }
        if header.last_entry_id < header.first_entry_id
            || header.entry_count != header.last_entry_id - header.first_entry_id + 1
        {
            return Err(DbError::Audit("export header range is invalid".into()));
        }
        let prev_checkpoint_hash = hex::decode(&header.prev_checkpoint_hash)
            .map_err(|_| DbError::Audit("export header prev hash is invalid".into()))?;
        let merkle_root_bytes = hex::decode(&header.merkle_root)
            .map_err(|_| DbError::Audit("export header Merkle root is invalid".into()))?;
        let checkpoint_hash = hex::decode(&header.checkpoint_hash)
            .map_err(|_| DbError::Audit("export header hash is invalid".into()))?;
        let recomputed = checkpoint_header_hash(
            &prev_checkpoint_hash,
            header.first_entry_id,
            header.last_entry_id,
            header.entry_count,
            &merkle_root_bytes,
            header.created_at,
        );
        if recomputed != checkpoint_hash {
            return Err(DbError::Audit("export header hash does not match".into()));
        }

        let mut trusted_signatures = 0u64;
        for signature in &header.signatures {
            if signature.algorithm != "ed25519" {
                return Err(DbError::Audit(format!(
                    "export signature {} uses unsupported algorithm {}",
                    signature.key_id, signature.algorithm
                )));
            }
            let public_key = hex::decode(&signature.public_key)
                .map_err(|_| DbError::Audit("export signature public key is invalid".into()))?;
            let bytes = hex::decode(&signature.signature)
                .map_err(|_| DbError::Audit("export signature is invalid hex".into()))?;
            if !verify_checkpoint_signature(&public_key, &checkpoint_hash, &bytes) {
                return Err(DbError::Audit(format!(
                    "export signature {} does not verify",
                    signature.key_id
                )));
            }
            if trusted_keys
                .iter()
                .any(|key| key.key_id == signature.key_id && key.public_key == public_key)
            {
                trusted_signatures += 1;
            }
        }
        if !trusted_keys.is_empty() && trusted_signatures == 0 {
            return Err(DbError::Audit(
                "export has no signature from a trusted key".into(),
            ));
        }

        let mut expected_prev: Option<Vec<u8>> = None;
        let mut entry_hashes = Vec::new();
        let mut count = 0u64;
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let row: AuditExportRow = serde_json::from_str(&line)
                .map_err(|error| DbError::Audit(format!("export entry: {error}")))?;
            if row.id != header.first_entry_id + count as i64 {
                return Err(DbError::Audit(format!(
                    "export entry {} is out of range",
                    row.id
                )));
            }
            let row_hash = hex::decode(&row.hash)
                .map_err(|_| DbError::Audit("export entry hash is invalid".into()))?;
            let row_prev = hex::decode(&row.prev_hash)
                .map_err(|_| DbError::Audit("export entry prev hash is invalid".into()))?;
            if let Some(expected) = &expected_prev
                && &row_prev != expected
            {
                return Err(DbError::Audit(format!(
                    "export entry {} does not link to the previous entry",
                    row.id
                )));
            }
            let computed = chain_hash(
                &row_prev,
                row.ts,
                row.actor_id,
                row.actor.as_deref(),
                &row.action,
                &row.subject,
                &row.details_raw,
            );
            if computed != row_hash {
                return Err(DbError::Audit(format!(
                    "export entry {} hash does not match",
                    row.id
                )));
            }
            expected_prev = Some(row_hash.clone());
            entry_hashes.push(row_hash);
            count += 1;
        }
        if count != header.entry_count as u64 {
            return Err(DbError::Audit(format!(
                "export has {count} entries, expected {}",
                header.entry_count
            )));
        }
        if merkle_root(&entry_hashes).as_deref() != Some(merkle_root_bytes.as_slice()) {
            return Err(DbError::Audit("export Merkle root does not match".into()));
        }
        Ok(AuditExportVerify {
            checkpoint_id: header.id,
            entries: count,
            signatures: header.signatures.len() as u64,
            trusted_signatures,
        })
    }

    /// Recomputes the retained chain, starting at the retention anchor, and
    /// verifies every checkpoint header, its range, and every root whose
    /// entry bodies are still present.
    pub async fn audit_verify(&self) -> Result<AuditVerify, DbError> {
        self.audit_verify_with(AuditVerifyOptions::default()).await
    }

    /// Verification with operator-supplied trust keys and an optional
    /// anchor log (RFC 0014).
    pub async fn audit_verify_with(
        &self,
        options: AuditVerifyOptions,
    ) -> Result<AuditVerify, DbError> {
        let anchor = self.audit_anchor().await?;
        let checkpoints =
            sqlx::query_as::<_, AuditCheckpoint>("SELECT * FROM audit_checkpoints ORDER BY id")
                .fetch_all(&self.pool)
                .await?;
        let mut signatures: HashMap<i64, Vec<AuditCheckpointSignature>> = HashMap::new();
        for row in sqlx::query_as::<_, AuditCheckpointSignature>(
            "SELECT s.checkpoint_id, s.key_id, s.signature, s.signed_at,
                    k.algorithm, k.public_key
             FROM audit_checkpoint_signatures s
             JOIN audit_signing_keys k ON k.key_id = s.key_id
             ORDER BY s.checkpoint_id, s.key_id",
        )
        .fetch_all(&self.pool)
        .await?
        {
            signatures.entry(row.checkpoint_id).or_default().push(row);
        }
        let mut stats = VerifyStats {
            trust_source: options.trust_source.clone().unwrap_or_else(|| {
                if options.trusted_keys.is_empty() {
                    "none".to_string()
                } else {
                    "trusted-keys".to_string()
                }
            }),
            ..VerifyStats::default()
        };
        let mut pruned_checkpoints = 0u64;
        let mut expected_first: Option<i64> = None;
        let mut expected_checkpoint = Vec::new();
        for checkpoint in &checkpoints {
            let pruned = checkpoint.entries_pruned_at.is_some();
            if pruned {
                pruned_checkpoints += 1;
                if anchor
                    .as_ref()
                    .is_none_or(|anchor| anchor.pruned_through < checkpoint.last_entry_id)
                {
                    return Ok(self.audit_verify_result(
                        0,
                        &checkpoints,
                        pruned_checkpoints,
                        Some(checkpoint.first_entry_id),
                        &stats,
                    ));
                }
            } else if anchor
                .as_ref()
                .is_some_and(|anchor| anchor.pruned_through >= checkpoint.last_entry_id)
            {
                // The anchor says these entries are gone, but the checkpoint
                // was never marked pruned.
                return Ok(self.audit_verify_result(
                    0,
                    &checkpoints,
                    pruned_checkpoints,
                    Some(checkpoint.first_entry_id),
                    &stats,
                ));
            }
            let bad_boundary = checkpoint.first_entry_id <= 0
                || checkpoint.last_entry_id < checkpoint.first_entry_id
                || checkpoint.entry_count
                    != checkpoint.last_entry_id - checkpoint.first_entry_id + 1
                || checkpoint.prev_checkpoint_hash != expected_checkpoint
                || expected_first.is_some_and(|first| checkpoint.first_entry_id != first);
            if bad_boundary {
                return Ok(self.audit_verify_result(
                    0,
                    &checkpoints,
                    pruned_checkpoints,
                    Some(checkpoint.first_entry_id),
                    &stats,
                ));
            }
            let recomputed = checkpoint_header_hash(
                &checkpoint.prev_checkpoint_hash,
                checkpoint.first_entry_id,
                checkpoint.last_entry_id,
                checkpoint.entry_count,
                &checkpoint.merkle_root,
                checkpoint.created_at,
            );
            if recomputed != checkpoint.checkpoint_hash {
                return Ok(self.audit_verify_result(
                    0,
                    &checkpoints,
                    pruned_checkpoints,
                    Some(checkpoint.first_entry_id),
                    &stats,
                ));
            }

            let checkpoint_signatures = signatures
                .get(&checkpoint.id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if checkpoint_signatures.is_empty() {
                stats.unsigned_checkpoints += 1;
                if options.require_signatures {
                    return Ok(self.audit_verify_result(
                        0,
                        &checkpoints,
                        pruned_checkpoints,
                        Some(checkpoint.first_entry_id),
                        &stats,
                    ));
                }
            } else {
                stats.signed_checkpoints += 1;
                if !options.trusted_keys.is_empty() {
                    let mut valid = false;
                    for signature in checkpoint_signatures {
                        if signature.algorithm != "ed25519" {
                            stats.signature_errors += 1;
                            return Ok(self.audit_verify_result(
                                0,
                                &checkpoints,
                                pruned_checkpoints,
                                Some(checkpoint.first_entry_id),
                                &stats,
                            ));
                        }
                        let Some(trusted) = options
                            .trusted_keys
                            .iter()
                            .find(|key| key.key_id == signature.key_id)
                        else {
                            stats.untrusted_signatures += 1;
                            continue;
                        };
                        if trusted.public_key != signature.public_key
                            || !verify_checkpoint_signature(
                                &trusted.public_key,
                                &checkpoint.checkpoint_hash,
                                &signature.signature,
                            )
                        {
                            stats.signature_errors += 1;
                            return Ok(self.audit_verify_result(
                                0,
                                &checkpoints,
                                pruned_checkpoints,
                                Some(checkpoint.first_entry_id),
                                &stats,
                            ));
                        }
                        stats.verified_signatures += 1;
                        valid = true;
                    }
                    if options.require_signatures && !valid {
                        return Ok(self.audit_verify_result(
                            0,
                            &checkpoints,
                            pruned_checkpoints,
                            Some(checkpoint.first_entry_id),
                            &stats,
                        ));
                    }
                }
            }

            if checkpoint.entries_pruned_at.is_none() {
                let rows = sqlx::query_as::<_, AuditEntry>(
                    "SELECT * FROM audit_log WHERE id BETWEEN ? AND ? ORDER BY id",
                )
                .bind(checkpoint.first_entry_id)
                .bind(checkpoint.last_entry_id)
                .fetch_all(&self.pool)
                .await?;
                if rows.len() as i64 != checkpoint.entry_count {
                    return Ok(self.audit_verify_result(
                        0,
                        &checkpoints,
                        pruned_checkpoints,
                        Some(checkpoint.first_entry_id),
                        &stats,
                    ));
                }
                let mut expected_prev = if checkpoint.first_entry_id == 1 {
                    Vec::new()
                } else {
                    rows[0].prev_hash.clone()
                };
                let mut entry_hashes = Vec::with_capacity(rows.len());
                for (offset, row) in rows.iter().enumerate() {
                    if row.id != checkpoint.first_entry_id + offset as i64 {
                        return Ok(self.audit_verify_result(
                            0,
                            &checkpoints,
                            pruned_checkpoints,
                            Some(checkpoint.first_entry_id),
                            &stats,
                        ));
                    }
                    let expected = chain_hash(
                        &expected_prev,
                        row.ts,
                        row.actor_id,
                        row.actor.as_deref(),
                        &row.action,
                        &row.subject,
                        &row.details,
                    );
                    if row.prev_hash != expected_prev || row.hash != expected {
                        return Ok(self.audit_verify_result(
                            0,
                            &checkpoints,
                            pruned_checkpoints,
                            Some(row.id),
                            &stats,
                        ));
                    }
                    expected_prev = row.hash.clone();
                    entry_hashes.push(row.hash.clone());
                }
                if merkle_root(&entry_hashes).as_deref() != Some(checkpoint.merkle_root.as_slice())
                {
                    return Ok(self.audit_verify_result(
                        0,
                        &checkpoints,
                        pruned_checkpoints,
                        Some(checkpoint.first_entry_id),
                        &stats,
                    ));
                }
            }
            expected_checkpoint = checkpoint.checkpoint_hash.clone();
            expected_first = Some(checkpoint.last_entry_id + 1);
        }

        let from = anchor.as_ref().map(|a| a.pruned_through).unwrap_or(0);
        let mut expected_prev = anchor
            .as_ref()
            .map(|anchor| anchor.hash.clone())
            .unwrap_or_default();
        let mut rows =
            sqlx::query_as::<_, AuditEntry>("SELECT * FROM audit_log WHERE id > ? ORDER BY id")
                .bind(from)
                .fetch(&self.pool);
        let mut entries = 0;
        while let Some(row) = rows.next().await {
            let row = row?;
            entries += 1;
            let expected = chain_hash(
                &expected_prev,
                row.ts,
                row.actor_id,
                row.actor.as_deref(),
                &row.action,
                &row.subject,
                &row.details,
            );
            if row.prev_hash != expected_prev || row.hash != expected {
                return Ok(self.audit_verify_result(
                    entries,
                    &checkpoints,
                    pruned_checkpoints,
                    Some(row.id),
                    &stats,
                ));
            }
            expected_prev = row.hash.clone();
        }

        if let Some(path) = &options.anchor_log {
            let records = read_anchor_log(path).await?;
            let by_id: HashMap<i64, &AuditCheckpoint> = checkpoints
                .iter()
                .map(|checkpoint| (checkpoint.id, checkpoint))
                .collect();
            let mut seen: HashMap<i64, String> = HashMap::new();
            for record in &records {
                if record.kind != AUDIT_ANCHOR_KIND {
                    return Ok(self.audit_verify_result(
                        entries,
                        &checkpoints,
                        pruned_checkpoints,
                        Some(record.last_entry_id),
                        &stats,
                    ));
                }
                let duplicate = if let Some(previous) = seen.get(&record.checkpoint_id) {
                    if previous != &record.checkpoint_hash {
                        return Ok(self.audit_verify_result(
                            entries,
                            &checkpoints,
                            pruned_checkpoints,
                            Some(record.last_entry_id),
                            &stats,
                        ));
                    }
                    true
                } else {
                    seen.insert(record.checkpoint_id, record.checkpoint_hash.clone());
                    false
                };
                let Some(checkpoint) = by_id.get(&record.checkpoint_id) else {
                    // A published checkpoint is gone locally: truncation or
                    // a rollback to an older snapshot.
                    stats.rollback_detected = true;
                    return Ok(self.audit_verify_result(
                        entries,
                        &checkpoints,
                        pruned_checkpoints,
                        Some(record.last_entry_id),
                        &stats,
                    ));
                };
                let matches = record.first_entry_id == checkpoint.first_entry_id
                    && record.last_entry_id == checkpoint.last_entry_id
                    && record.entry_count == checkpoint.entry_count
                    && record.merkle_root == hex::encode(&checkpoint.merkle_root)
                    && record.checkpoint_hash == hex::encode(&checkpoint.checkpoint_hash)
                    && record.created_at == checkpoint.created_at;
                if !matches {
                    return Ok(self.audit_verify_result(
                        entries,
                        &checkpoints,
                        pruned_checkpoints,
                        Some(record.last_entry_id),
                        &stats,
                    ));
                }
                if !duplicate {
                    stats.anchors_checked += 1;
                }
                if !options.trusted_keys.is_empty() {
                    let mut valid = false;
                    for signature in &record.signatures {
                        if signature.algorithm != "ed25519" {
                            stats.signature_errors += 1;
                            return Ok(self.audit_verify_result(
                                entries,
                                &checkpoints,
                                pruned_checkpoints,
                                Some(record.last_entry_id),
                                &stats,
                            ));
                        }
                        let Ok(public_key) = hex::decode(&signature.public_key) else {
                            stats.signature_errors += 1;
                            return Ok(self.audit_verify_result(
                                entries,
                                &checkpoints,
                                pruned_checkpoints,
                                Some(record.last_entry_id),
                                &stats,
                            ));
                        };
                        let Ok(bytes) = hex::decode(&signature.signature) else {
                            stats.signature_errors += 1;
                            return Ok(self.audit_verify_result(
                                entries,
                                &checkpoints,
                                pruned_checkpoints,
                                Some(record.last_entry_id),
                                &stats,
                            ));
                        };
                        let Some(trusted) = options
                            .trusted_keys
                            .iter()
                            .find(|key| key.key_id == signature.key_id)
                        else {
                            continue;
                        };
                        if trusted.public_key != public_key
                            || !verify_checkpoint_signature(
                                &trusted.public_key,
                                &checkpoint.checkpoint_hash,
                                &bytes,
                            )
                        {
                            stats.signature_errors += 1;
                            return Ok(self.audit_verify_result(
                                entries,
                                &checkpoints,
                                pruned_checkpoints,
                                Some(record.last_entry_id),
                                &stats,
                            ));
                        }
                        valid = true;
                    }
                    if options.require_signatures && !valid {
                        return Ok(self.audit_verify_result(
                            entries,
                            &checkpoints,
                            pruned_checkpoints,
                            Some(record.last_entry_id),
                            &stats,
                        ));
                    }
                }
                let head = AuditAnchorHead {
                    checkpoint_id: record.checkpoint_id,
                    last_entry_id: record.last_entry_id,
                };
                if stats
                    .latest_anchor
                    .as_ref()
                    .is_none_or(|latest| head.last_entry_id > latest.last_entry_id)
                {
                    stats.latest_anchor = Some(head);
                }
            }
            if let Some(latest) = &stats.latest_anchor {
                let local_max: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM audit_log")
                    .fetch_one(&self.pool)
                    .await?;
                if local_max.unwrap_or(0) < latest.last_entry_id {
                    stats.rollback_detected = true;
                    return Ok(self.audit_verify_result(
                        entries,
                        &checkpoints,
                        pruned_checkpoints,
                        Some(latest.last_entry_id),
                        &stats,
                    ));
                }
            }
        }

        Ok(self.audit_verify_result(entries, &checkpoints, pruned_checkpoints, None, &stats))
    }

    fn audit_verify_result(
        &self,
        entries: u64,
        checkpoints: &[AuditCheckpoint],
        pruned_checkpoints: u64,
        first_bad: Option<i64>,
        stats: &VerifyStats,
    ) -> AuditVerify {
        AuditVerify {
            entries,
            checkpoints: checkpoints.len() as u64,
            pruned_checkpoints,
            signed_checkpoints: stats.signed_checkpoints,
            verified_signatures: stats.verified_signatures,
            unsigned_checkpoints: stats.unsigned_checkpoints,
            untrusted_signatures: stats.untrusted_signatures,
            signature_errors: stats.signature_errors,
            anchors_checked: stats.anchors_checked,
            rollback_detected: stats.rollback_detected,
            trust_source: stats.trust_source.clone(),
            latest_anchor: stats.latest_anchor.clone(),
            first_bad,
            latest_checkpoint: checkpoints.last().map(|checkpoint| AuditCheckpointHead {
                id: checkpoint.id,
                last_entry_id: checkpoint.last_entry_id,
                merkle_root: hex::encode(&checkpoint.merkle_root),
            }),
        }
    }
}

/// Accumulates verification counters across early returns.
#[derive(Debug, Default)]
struct VerifyStats {
    signed_checkpoints: u64,
    verified_signatures: u64,
    unsigned_checkpoints: u64,
    untrusted_signatures: u64,
    signature_errors: u64,
    anchors_checked: u64,
    rollback_detected: bool,
    latest_anchor: Option<AuditAnchorHead>,
    trust_source: String,
}

/// Reads a JSONL anchor log.
pub async fn read_anchor_log(path: &Path) -> Result<Vec<AuditAnchorRecord>, DbError> {
    let file = tokio::fs::File::open(path).await?;
    let mut lines = tokio::io::BufReader::new(file).lines();
    let mut records = Vec::new();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        records.push(
            serde_json::from_str(&line)
                .map_err(|error| DbError::Audit(format!("anchor log: {error}")))?,
        );
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use serde_json::{Value, json};

    use super::{AuditSigner, AuditVerifyOptions, TrustedAuditKey};
    use crate::Db;

    async fn db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn appends_chain_and_verify() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        db.audit_append(
            Some(user.id),
            None,
            "file.upsert",
            "/a.txt",
            &json!({"size": 3}),
        )
        .await
        .unwrap();
        db.audit_append(None, Some("cli"), "user.add", "bob", &json!({}))
            .await
            .unwrap();
        db.audit_append(Some(user.id), None, "auth.login", "alice", &json!({}))
            .await
            .unwrap();

        let verify = db.audit_verify().await.unwrap();
        assert_eq!(
            verify,
            crate::audit::AuditVerify {
                entries: 3,
                checkpoints: 0,
                pruned_checkpoints: 0,
                signed_checkpoints: 0,
                verified_signatures: 0,
                unsigned_checkpoints: 0,
                untrusted_signatures: 0,
                signature_errors: 0,
                anchors_checked: 0,
                rollback_detected: false,
                trust_source: "none".into(),
                latest_anchor: None,
                first_bad: None,
                latest_checkpoint: None,
            }
        );

        let list = db.audit_list(10, None).await.unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].action, "auth.login");
        assert_eq!(list[2].action, "file.upsert");
        assert!(list[0].prev_hash == list[1].hash);

        let older = db.audit_list(10, Some(list[1].id)).await.unwrap();
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].action, "file.upsert");
    }

    #[tokio::test]
    async fn pages_can_filter_by_action_and_subject() {
        let (_dir, db) = db().await;
        db.audit_append(None, Some("cli"), "group.add", "team", &json!({}))
            .await
            .unwrap();
        db.audit_append(None, Some("cli"), "group.add", "ops", &json!({}))
            .await
            .unwrap();
        db.audit_append(None, Some("cli"), "user.add", "team", &json!({}))
            .await
            .unwrap();

        let groups = db
            .audit_page(crate::audit::AuditPageQuery {
                limit: 10,
                before: None,
                action: Some("group.add"),
                subject: None,
            })
            .await
            .unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|entry| entry.action == "group.add"));

        let team = db
            .audit_page(crate::audit::AuditPageQuery {
                limit: 10,
                before: None,
                action: None,
                subject: Some("team"),
            })
            .await
            .unwrap();
        assert_eq!(team.len(), 2);
        assert!(team.iter().all(|entry| entry.subject == "team"));

        let first_page = db
            .audit_page(crate::audit::AuditPageQuery {
                limit: 1,
                before: None,
                action: Some("group.add"),
                subject: None,
            })
            .await
            .unwrap();
        assert_eq!(first_page.len(), 1);
        assert_eq!(first_page[0].subject, "ops");
        let second_page = db
            .audit_page(crate::audit::AuditPageQuery {
                limit: 10,
                before: Some(first_page[0].id),
                action: Some("group.add"),
                subject: None,
            })
            .await
            .unwrap();
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].subject, "team");
    }

    #[tokio::test]
    async fn tampering_breaks_the_chain() {
        let (_dir, db) = db().await;
        db.audit_append(None, Some("cli"), "user.add", "alice", &json!({}))
            .await
            .unwrap();
        db.audit_append(None, Some("cli"), "user.add", "bob", &json!({}))
            .await
            .unwrap();
        db.audit_append(None, Some("cli"), "user.add", "carol", &json!({}))
            .await
            .unwrap();
        assert_eq!(db.audit_verify().await.unwrap().first_bad, None);

        sqlx::query("UPDATE audit_log SET subject = 'mallory' WHERE id = 2")
            .execute(db.pool())
            .await
            .unwrap();
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.first_bad, Some(2));
        assert_eq!(verify.entries, 2);
    }

    #[tokio::test]
    async fn deleting_an_entry_breaks_the_chain() {
        let (_dir, db) = db().await;
        for name in ["a", "b", "c"] {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM audit_log WHERE id = 2")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(db.audit_verify().await.unwrap().first_bad, Some(3));
    }

    #[tokio::test]
    async fn export_and_prune_records_an_anchor_that_verifies() {
        let (dir, db) = db().await;
        for name in ["a", "b", "c", "d", "e"] {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
        let path = dir.path().join("audit.jsonl");
        let report = db.audit_export_and_prune(3, &path).await.unwrap();
        assert_eq!(report.exported, 3);
        assert_eq!(report.pruned_through, 3);
        assert_eq!(report.anchor_hash.len(), 64);

        let export = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(export.lines().count(), 3);
        let first: Value = serde_json::from_str(export.lines().next().unwrap()).unwrap();
        assert_eq!(first["subject"], "a");
        assert_eq!(first["hash"].as_str().unwrap().len(), 64);
        assert!(first["details_raw"].is_string());

        let anchor = db.audit_anchor().await.unwrap().unwrap();
        assert_eq!(anchor.pruned_through, 3);
        assert_eq!(anchor.pruned_entries, 3);
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.entries, 2);
        assert_eq!(verify.first_bad, None);

        db.audit_append(None, Some("cli"), "user.add", "f", &json!({}))
            .await
            .unwrap();
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.entries, 3);
        assert_eq!(verify.first_bad, None);
    }

    #[tokio::test]
    async fn prune_refuses_newest_entry_and_existing_export() {
        let (dir, db) = db().await;
        for name in ["a", "b"] {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "keep me").unwrap();
        assert!(db.audit_export_and_prune(1, &path).await.is_err());
        std::fs::remove_file(&path).unwrap();

        // Keeping the newest row is mandatory.
        assert!(db.audit_export_and_prune(2, &path).await.is_err());
        assert!(db.audit_anchor().await.unwrap().is_none());
        assert_eq!(db.audit_list(10, None).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn prune_refuses_a_tampered_prefix() {
        let (dir, db) = db().await;
        for name in ["a", "b", "c"] {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
        sqlx::query("UPDATE audit_log SET subject = 'mallory' WHERE id = 2")
            .execute(db.pool())
            .await
            .unwrap();
        let path = dir.path().join("audit.jsonl");
        assert!(db.audit_export_and_prune(2, &path).await.is_err());
        assert!(db.audit_anchor().await.unwrap().is_none());
        assert_eq!(db.audit_list(10, None).await.unwrap().len(), 3);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn verify_checks_the_tail_against_the_anchor() {
        let (dir, db) = db().await;
        for name in ["a", "b", "c", "d"] {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
        let path = dir.path().join("audit.jsonl");
        db.audit_export_and_prune(2, &path).await.unwrap();
        sqlx::query("UPDATE audit_log SET subject = 'mallory' WHERE id = 3")
            .execute(db.pool())
            .await
            .unwrap();
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.first_bad, Some(3));
    }

    async fn append_entries(db: &Db, names: &[&str]) {
        for name in names {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn seal_batches_are_contiguous_and_verify() {
        let (_dir, db) = db().await;
        append_entries(&db, &["a", "b", "c", "d", "e"]).await;

        let first = db.audit_seal(2).await.unwrap().unwrap();
        assert_eq!((first.first_entry_id, first.last_entry_id), (1, 2));
        assert_eq!(first.entry_count, 2);
        assert!(first.prev_checkpoint_hash.is_empty());
        assert_eq!(first.merkle_root.len(), 32);
        assert_eq!(first.checkpoint_hash.len(), 32);

        let second = db.audit_seal(2).await.unwrap().unwrap();
        assert_eq!((second.first_entry_id, second.last_entry_id), (3, 4));
        assert_eq!(second.prev_checkpoint_hash, first.checkpoint_hash);

        let third = db.audit_seal(2).await.unwrap().unwrap();
        assert_eq!((third.first_entry_id, third.last_entry_id), (5, 5));
        assert_eq!(third.prev_checkpoint_hash, second.checkpoint_hash);
        assert!(db.audit_seal(2).await.unwrap().is_none());

        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.first_bad, None);
        assert_eq!(verify.entries, 5);
        assert_eq!(verify.checkpoints, 3);
        assert_eq!(verify.pruned_checkpoints, 0);
        let latest = verify.latest_checkpoint.unwrap();
        assert_eq!(latest.id, third.id);
        assert_eq!(latest.last_entry_id, 5);
        assert_eq!(latest.merkle_root, hex::encode(&third.merkle_root));
    }

    #[tokio::test]
    async fn seal_pending_respects_the_threshold() {
        let (_dir, db) = db().await;
        append_entries(&db, &["a", "b", "c", "d", "e"]).await;
        // 5 unsealed: seal 2, leaving 3 (still >= 3), then seal 2, leaving 1.
        assert_eq!(db.audit_seal_pending(3, 2, 10).await.unwrap(), 2);
        assert_eq!(db.audit_unsealed_count().await.unwrap(), 1);
        assert_eq!(db.audit_checkpoints(10).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn tampered_checkpoint_header_or_root_breaks_verification() {
        let (_dir, db) = db().await;
        append_entries(&db, &["a", "b", "c"]).await;
        let checkpoint = db.audit_seal(10).await.unwrap().unwrap();

        sqlx::query("UPDATE audit_checkpoints SET merkle_root = ? WHERE id = ?")
            .bind(vec![9u8; 32])
            .bind(checkpoint.id)
            .execute(db.pool())
            .await
            .unwrap();
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.first_bad, Some(1));

        // Restore the root, then break the hash instead.
        sqlx::query("UPDATE audit_checkpoints SET merkle_root = ? WHERE id = ?")
            .bind(&checkpoint.merkle_root)
            .bind(checkpoint.id)
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE audit_checkpoints SET checkpoint_hash = ? WHERE id = ?")
            .bind(vec![7u8; 32])
            .bind(checkpoint.id)
            .execute(db.pool())
            .await
            .unwrap();
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.first_bad, Some(1));
    }

    #[tokio::test]
    async fn tampered_sealed_entry_breaks_verification_and_sealing() {
        let (_dir, db) = db().await;
        append_entries(&db, &["a", "b", "c"]).await;
        db.audit_seal(10).await.unwrap().unwrap();
        sqlx::query("UPDATE audit_log SET subject = 'mallory' WHERE id = 2")
            .execute(db.pool())
            .await
            .unwrap();
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.first_bad, Some(2));

        // A tampered unsealed range must not be sealed either.
        let (_dir2, db2) = db_with_entries(&["a", "b", "c"]).await;
        sqlx::query("UPDATE audit_log SET subject = 'mallory' WHERE id = 2")
            .execute(db2.pool())
            .await
            .unwrap();
        assert!(db2.audit_seal(10).await.is_err());
    }

    async fn db_with_entries(names: &[&str]) -> (tempfile::TempDir, Db) {
        let (dir, db) = db().await;
        append_entries(&db, names).await;
        (dir, db)
    }

    #[tokio::test]
    async fn prune_checkpoint_exports_a_bundle_and_keeps_the_header_chain() {
        let (dir, db) = db().await;
        append_entries(&db, &["a", "b", "c", "d", "e"]).await;
        let checkpoint = db.audit_seal(10).await.unwrap().unwrap();
        // Keep one newer entry so the newest row is never pruned.
        append_entries(&db, &["tail"]).await;

        let path = dir.path().join("audit-checkpoint.jsonl");
        let report = db
            .audit_export_and_prune_checkpoint(checkpoint.id, &path)
            .await
            .unwrap();
        assert_eq!(report.exported, 5);
        assert_eq!(report.pruned_through, 5);
        assert_eq!(report.checkpoint_id, Some(checkpoint.id));

        let export = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = export.lines().collect();
        assert_eq!(lines.len(), 6, "header plus five entries");
        let header: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(header["kind"], "kolimi-audit-checkpoint");
        assert_eq!(header["id"], checkpoint.id);
        assert_eq!(header["entry_count"], 5);

        let export_verify = db.audit_verify_export(&path).await.unwrap();
        assert_eq!(export_verify.checkpoint_id, checkpoint.id);
        assert_eq!(export_verify.entries, 5);

        let stored = db.audit_checkpoint(checkpoint.id).await.unwrap().unwrap();
        assert!(stored.entries_pruned_at.is_some());
        assert_eq!(stored.checkpoint_hash, checkpoint.checkpoint_hash);

        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.first_bad, None);
        assert_eq!(verify.entries, 1);
        assert_eq!(verify.checkpoints, 1);
        assert_eq!(verify.pruned_checkpoints, 1);

        assert!(
            db.audit_export_and_prune_checkpoint(checkpoint.id, &path)
                .await
                .is_err(),
            "already-pruned checkpoint"
        );
    }

    #[tokio::test]
    async fn verify_export_rejects_entry_root_and_header_tampering() {
        let (dir, db) = db().await;
        append_entries(&db, &["a", "b", "c"]).await;
        let checkpoint = db.audit_seal(10).await.unwrap().unwrap();
        append_entries(&db, &["tail"]).await;
        let path = dir.path().join("bundle.jsonl");
        db.audit_export_and_prune_checkpoint(checkpoint.id, &path)
            .await
            .unwrap();
        assert!(db.audit_verify_export(&path).await.is_ok());

        let original = tokio::fs::read_to_string(&path).await.unwrap();
        let mut lines: Vec<String> = original.lines().map(str::to_string).collect();

        // Changed entry body.
        let mut entry: Value = serde_json::from_str(&lines[1]).unwrap();
        entry["subject"] = json!("mallory");
        lines[1] = entry.to_string();
        tokio::fs::write(&path, lines.join("\n") + "\n")
            .await
            .unwrap();
        assert!(db.audit_verify_export(&path).await.is_err());

        // Changed header root.
        let mut header: Value = serde_json::from_str(original.lines().next().unwrap()).unwrap();
        header["merkle_root"] = json!("00".repeat(32));
        let mut tampered = vec![header.to_string()];
        tampered.extend(original.lines().skip(1).map(str::to_string));
        tokio::fs::write(&path, tampered.join("\n") + "\n")
            .await
            .unwrap();
        assert!(db.audit_verify_export(&path).await.is_err());

        // Changed header hash.
        let mut header: Value = serde_json::from_str(original.lines().next().unwrap()).unwrap();
        header["checkpoint_hash"] = json!("00".repeat(32));
        let mut tampered = vec![header.to_string()];
        tampered.extend(original.lines().skip(1).map(str::to_string));
        tokio::fs::write(&path, tampered.join("\n") + "\n")
            .await
            .unwrap();
        assert!(db.audit_verify_export(&path).await.is_err());
    }

    fn trusted(signer: &AuditSigner) -> TrustedAuditKey {
        TrustedAuditKey::from_parts(signer.key_id(), signer.public_key().to_vec()).unwrap()
    }

    #[tokio::test]
    async fn signing_key_round_trips_and_refuses_weak_permissions() {
        let (dir, _db) = db().await;
        let path = dir.path().join("audit-signing.key");
        let signer = AuditSigner::generate(&path, Some("test")).unwrap();
        let loaded = AuditSigner::load(&path).unwrap();
        assert_eq!(loaded.key_id(), signer.key_id());
        assert_eq!(loaded.public_key(), signer.public_key());
        assert!(AuditSigner::generate(&path, None).is_err(), "no overwrite");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(AuditSigner::load(&path).is_err(), "group-readable key");
        }
    }

    #[tokio::test]
    async fn signed_checkpoints_verify_only_against_pinned_keys() {
        let (dir, db) = db().await;
        append_entries(&db, &["a", "b", "c"]).await;
        let signer = AuditSigner::generate(&dir.path().join("key"), None).unwrap();
        let checkpoint = db
            .audit_seal_with(10, Some(&signer), false)
            .await
            .unwrap()
            .unwrap();

        let unsigned = db.audit_verify().await.unwrap();
        assert_eq!(unsigned.signed_checkpoints, 1);
        assert_eq!(unsigned.verified_signatures, 0);
        assert_eq!(unsigned.trust_source, "none");

        let verify = db
            .audit_verify_with(AuditVerifyOptions {
                trusted_keys: vec![trusted(&signer)],
                require_signatures: true,
                ..AuditVerifyOptions::default()
            })
            .await
            .unwrap();
        assert_eq!(verify.first_bad, None);
        assert_eq!(verify.verified_signatures, 1);
        assert_eq!(verify.trust_source, "trusted-keys");

        let other = AuditSigner::generate(&dir.path().join("other"), None).unwrap();
        let verify = db
            .audit_verify_with(AuditVerifyOptions {
                trusted_keys: vec![trusted(&other)],
                require_signatures: true,
                ..AuditVerifyOptions::default()
            })
            .await
            .unwrap();
        assert_eq!(verify.first_bad, Some(1));
        assert_eq!(verify.untrusted_signatures, 1);

        // A corrupted signature fails even with the right key.
        sqlx::query("UPDATE audit_checkpoint_signatures SET signature = ? WHERE checkpoint_id = ?")
            .bind(vec![0u8; 64])
            .bind(checkpoint.id)
            .execute(db.pool())
            .await
            .unwrap();
        let verify = db
            .audit_verify_with(AuditVerifyOptions {
                trusted_keys: vec![trusted(&signer)],
                require_signatures: true,
                ..AuditVerifyOptions::default()
            })
            .await
            .unwrap();
        assert_eq!(verify.first_bad, Some(1));
        assert_eq!(verify.signature_errors, 1);
    }

    #[tokio::test]
    async fn swapping_the_stored_public_key_does_not_fool_a_pinned_key() {
        let (dir, db) = db().await;
        append_entries(&db, &["a", "b"]).await;
        let signer = AuditSigner::generate(&dir.path().join("key"), None).unwrap();
        db.audit_seal_with(10, Some(&signer), false)
            .await
            .unwrap()
            .unwrap();
        let attacker = AuditSigner::generate(&dir.path().join("attacker"), None).unwrap();
        sqlx::query("UPDATE audit_signing_keys SET public_key = ? WHERE key_id = ?")
            .bind(attacker.public_key().as_slice())
            .bind(signer.key_id())
            .execute(db.pool())
            .await
            .unwrap();
        let verify = db
            .audit_verify_with(AuditVerifyOptions {
                trusted_keys: vec![trusted(&signer)],
                require_signatures: true,
                ..AuditVerifyOptions::default()
            })
            .await
            .unwrap();
        assert!(verify.first_bad.is_some());
        assert!(verify.signature_errors > 0);
    }

    #[tokio::test]
    async fn sign_backfills_and_is_idempotent() {
        let (dir, db) = db().await;
        append_entries(&db, &["a", "b"]).await;
        db.audit_seal(10).await.unwrap().unwrap();
        let signer = AuditSigner::generate(&dir.path().join("key"), None).unwrap();
        assert_eq!(
            db.audit_sign_checkpoints(None, true, &signer)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            db.audit_sign_checkpoints(None, true, &signer)
                .await
                .unwrap(),
            0
        );
        let verify = db
            .audit_verify_with(AuditVerifyOptions {
                trusted_keys: vec![trusted(&signer)],
                ..AuditVerifyOptions::default()
            })
            .await
            .unwrap();
        assert_eq!(verify.signed_checkpoints, 1);
        assert_eq!(verify.verified_signatures, 1);
    }

    #[tokio::test]
    async fn seal_age_trigger_seals_a_small_tail() {
        let (_dir, db) = db().await;
        append_entries(&db, &["a"]).await;
        assert_eq!(
            db.audit_seal_if_due(1024, 0, 4096, 10, None, false)
                .await
                .unwrap(),
            0
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert_eq!(
            db.audit_seal_if_due(1024, 1, 4096, 10, None, false)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn anchor_records_are_enqueued_and_verify_against_the_chain() {
        let (dir, db) = db().await;
        append_entries(&db, &["a", "b", "c"]).await;
        let signer = AuditSigner::generate(&dir.path().join("key"), None).unwrap();
        let checkpoint = db
            .audit_seal_with(10, Some(&signer), true)
            .await
            .unwrap()
            .unwrap();
        let outbox = db.audit_anchor_outbox(10).await.unwrap();
        assert_eq!(outbox.len(), 1);
        assert!(outbox[0].journaled_at.is_none());
        assert!(outbox[0].payload.contains("kolimi-audit-anchor-v1"));

        let record = db.audit_anchor_record(None).await.unwrap().unwrap();
        assert_eq!(record.checkpoint_id, checkpoint.id);
        assert_eq!(record.signatures.len(), 1);
        assert_eq!(record.signatures[0].key_id, signer.key_id());

        let path = dir.path().join("anchors.jsonl");
        tokio::fs::write(&path, serde_json::to_string(&record).unwrap() + "\n")
            .await
            .unwrap();
        let verify = db
            .audit_verify_with(AuditVerifyOptions {
                trusted_keys: vec![trusted(&signer)],
                anchor_log: Some(path.clone()),
                ..AuditVerifyOptions::default()
            })
            .await
            .unwrap();
        assert_eq!(verify.first_bad, None);
        assert_eq!(verify.anchors_checked, 1);
        assert!(!verify.rollback_detected);
        assert_eq!(
            verify.latest_anchor.unwrap().last_entry_id,
            checkpoint.last_entry_id
        );

        // An anchor for a checkpoint the local database does not have means
        // the local history was rolled back or truncated.
        let mut missing = record;
        missing.checkpoint_id = checkpoint.id + 100;
        let path = dir.path().join("stale.jsonl");
        tokio::fs::write(&path, serde_json::to_string(&missing).unwrap() + "\n")
            .await
            .unwrap();
        let verify = db
            .audit_verify_with(AuditVerifyOptions {
                anchor_log: Some(path),
                ..AuditVerifyOptions::default()
            })
            .await
            .unwrap();
        assert!(verify.rollback_detected);
        assert!(verify.first_bad.is_some());
    }

    #[tokio::test]
    async fn export_bundles_carry_and_verify_signatures() {
        let (dir, db) = db().await;
        append_entries(&db, &["a", "b", "c"]).await;
        let signer = AuditSigner::generate(&dir.path().join("key"), None).unwrap();
        let checkpoint = db
            .audit_seal_with(10, Some(&signer), false)
            .await
            .unwrap()
            .unwrap();
        append_entries(&db, &["tail"]).await;
        let path = dir.path().join("bundle.jsonl");
        db.audit_export_and_prune_checkpoint(checkpoint.id, &path)
            .await
            .unwrap();

        let verify = db
            .audit_verify_export_with(&path, &[trusted(&signer)])
            .await
            .unwrap();
        assert_eq!(verify.signatures, 1);
        assert_eq!(verify.trusted_signatures, 1);

        let other = AuditSigner::generate(&dir.path().join("other"), None).unwrap();
        assert!(
            db.audit_verify_export_with(&path, &[trusted(&other)])
                .await
                .is_err()
        );
    }
}
