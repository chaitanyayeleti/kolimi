//! Short-lived re-authentication tokens for sensitive account changes.
//!
//! A session cookie proves that a browser was logged in at some point; it
//! does not prove that the person holding the cookie can still pass the
//! account's password or second factor. Passkey registration/removal and
//! keyring replacement are credential-management operations, so they require
//! a fresh proof of presence. The proof is exchanged for a single-use,
//! five-minute token bound to one user.

#![allow(clippy::result_large_err)]

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use kolimi_auth::token;
use serde_json::json;

use crate::AppState;

/// Header carrying a re-authentication token.
pub const REAUTH_HEADER: &str = "x-reauth-token";
/// Lifetime of an issued token.
pub const REAUTH_TTL: Duration = Duration::from_secs(5 * 60);
/// Upper bound on outstanding tokens across all users.
const MAX_TOKENS: usize = 4096;

struct Entry {
    user_id: i64,
    expires: Instant,
}

/// In-memory store of single-use re-authentication tokens, keyed by hash.
pub struct ReauthTokens {
    inner: Mutex<HashMap<[u8; 32], Entry>>,
}

impl ReauthTokens {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Issues a token for `user_id`. Returns `None` when randomness fails.
    pub fn issue(&self, user_id: i64) -> Option<String> {
        let token = token::new_session_token().ok()?;
        let hash = token::hash_token(&token);
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, entry| entry.expires > now);
        while map.len() >= MAX_TOKENS {
            let Some(evict) = map.keys().next().copied() else {
                break;
            };
            map.remove(&evict);
        }
        map.insert(
            hash,
            Entry {
                user_id,
                expires: now + REAUTH_TTL,
            },
        );
        Some(token)
    }

    /// Consumes a token, returning whether it was valid for `user_id`.
    pub fn consume(&self, token: &str, user_id: i64) -> bool {
        let hash = token::hash_token(token);
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        matches!(
            map.remove(&hash),
            Some(entry) if entry.user_id == user_id && entry.expires > now
        )
    }
}

impl Default for ReauthTokens {
    fn default() -> Self {
        Self::new()
    }
}

/// Requires and consumes a valid re-authentication token.
///
/// Returns a ready-to-send 403 response when the header is missing or stale.
pub fn require(state: &AppState, user_id: i64, headers: &HeaderMap) -> Result<(), Response> {
    let Some(token) = headers
        .get(REAUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|token| !token.is_empty())
    else {
        return Err(reauth_required());
    };
    if state.reauth.consume(token, user_id) {
        Ok(())
    } else {
        Err(reauth_required())
    }
}

fn reauth_required() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "re-authentication required; confirm your password and, if enabled, a two-factor code"
        })),
    )
        .into_response()
}
