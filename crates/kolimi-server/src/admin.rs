//! Administrative account recovery.
//!
//! The CLI's `user recover` command is the documented, audited path for
//! restoring access to an account whose owner has lost their credentials
//! (every passkey *and* the recovery code, or a forgotten password with
//! TOTP still enabled). Recovery is a **privileged** action: the operator
//! must verify the user's identity out-of-band before running it (see
//! `docs/operations.md`). It sets a new password, drops the account's live
//! sessions, and by default clears TOTP so the new password alone works.
//!
//! The operation is factored out of the binary so it is covered by tests.

use kolimi_db::Db;

/// What a recovery changed, for reporting and audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
    /// Whether TOTP was cleared.
    pub totp_disabled: bool,
    /// Number of passkeys removed.
    pub passkeys_removed: u64,
    /// Number of live sessions dropped.
    pub sessions_dropped: u64,
}

/// Restores access to `username`.
///
/// Sets `password_hash` as the new password, drops all of the account's
/// sessions, clears TOTP unless `keep_totp`, and removes every passkey when
/// `remove_passkeys`. The caller supplies the already-hashed password and is
/// responsible for out-of-band identity verification.
pub async fn recover_user(
    db: &Db,
    username: &str,
    password_hash: &str,
    keep_totp: bool,
    remove_passkeys: bool,
) -> Result<Recovery, kolimi_db::DbError> {
    let user = db
        .find_user(username)
        .await?
        .ok_or_else(|| kolimi_db::DbError::NotFound(format!("user {username}")))?;

    db.set_password(username, password_hash).await?;

    if !keep_totp {
        db.clear_totp(user.id).await?;
    }

    let mut passkeys_removed = 0u64;
    if remove_passkeys {
        for passkey in db.list_passkeys(user.id).await? {
            if db.delete_passkey(user.id, passkey.id).await.is_ok() {
                passkeys_removed += 1;
            }
        }
    }

    let sessions_dropped = db.delete_user_sessions(user.id).await?;

    db.audit_append(
        Some(user.id),
        Some("cli"),
        "user.recover",
        username,
        &serde_json::json!({
            "totp_disabled": !keep_totp,
            "passkeys_removed": passkeys_removed,
            "sessions_dropped": sessions_dropped,
        }),
    )
    .await?;

    Ok(Recovery {
        totp_disabled: !keep_totp,
        passkeys_removed,
        sessions_dropped,
    })
}
