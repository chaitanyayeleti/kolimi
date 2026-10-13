//! RFC 4918 class 2 locking (`LOCK`/`UNLOCK`) backed by an in-process store.
//!
//! Locks are keyed by path and scoped per owner. They are ephemeral: they
//! expire after their timeout and do not survive a restart (clients re-lock
//! on reconnect). A single shared lock manager is attached as a request
//! extension by the server.
#![allow(clippy::result_large_err)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Lock scope (RFC 4918 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Only the token holder may write.
    Exclusive,
    /// Several holders may write.
    Shared,
}

/// A held lock.
#[derive(Debug, Clone, PartialEq)]
pub struct Lock {
    /// `opaquelocktoken:...` URI.
    pub token: String,
    /// Exclusive or shared.
    pub scope: Scope,
    /// Raw inner XML of the `<owner>` element, echoed in `lockdiscovery`.
    pub owner_xml: Option<String>,
    /// Whether the lock applies to the whole subtree.
    pub depth_infinity: bool,
    /// Advertised timeout in seconds.
    pub timeout_secs: u64,
    expires_at: Instant,
}

impl Lock {
    fn is_live(&self, now: Instant) -> bool {
        self.expires_at > now
    }

    /// Renders the `<d:timeout>` value.
    pub fn timeout_header(&self) -> String {
        format!("Second-{}", self.timeout_secs)
    }
}

/// Why a lock operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum LockError {
    /// The resource is already locked incompatibly (`423 Locked`).
    Conflict,
    /// No matching lock (bad token, or already gone).
    NotFound,
}

const MIN_TIMEOUT: u64 = 60;
const DEFAULT_TIMEOUT: u64 = 3600;
const MAX_TIMEOUT: u64 = 604_800;

/// Shared, thread-safe lock store.
#[derive(Clone, Default)]
pub struct LockManager {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    locks: HashMap<String, Vec<(i64, Lock)>>,
    counter: u64,
}

impl LockManager {
    /// Creates an empty lock manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquires a new lock on `path`.
    pub fn lock(
        &self,
        owner: i64,
        path: &str,
        scope: Scope,
        owner_xml: Option<String>,
        depth_infinity: bool,
        timeout_secs: u64,
    ) -> Result<Lock, LockError> {
        let now = Instant::now();
        let timeout = clamp_timeout(timeout_secs);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.purge(now);
        if inner.conflicts(path, scope) {
            return Err(LockError::Conflict);
        }
        let token = new_token(&mut inner.counter, owner, path);
        let lock = Lock {
            token,
            scope,
            owner_xml,
            depth_infinity,
            timeout_secs: timeout,
            expires_at: now + Duration::from_secs(timeout),
        };
        inner
            .locks
            .entry(path.to_string())
            .or_default()
            .push((owner, lock.clone()));
        Ok(lock)
    }

    /// Refreshes an existing lock identified by `token`.
    ///
    /// The token may be presented at any URI within the lock's scope, so a
    /// lock on a collection can be refreshed through a member (RFC 4918
    /// §9.10.2, "indirect refresh").
    pub fn refresh(
        &self,
        owner: i64,
        path: &str,
        token: &str,
        timeout_secs: u64,
    ) -> Result<Lock, LockError> {
        let now = Instant::now();
        let timeout = clamp_timeout(timeout_secs);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.purge(now);
        let root = inner
            .find_covering_root(owner, path, token)
            .ok_or(LockError::NotFound)?;
        let Some(entries) = inner.locks.get_mut(&root) else {
            return Err(LockError::NotFound);
        };
        let Some((_, lock)) = entries
            .iter_mut()
            .find(|(who, lock)| *who == owner && lock.token == token)
        else {
            return Err(LockError::NotFound);
        };
        lock.timeout_secs = timeout;
        lock.expires_at = now + Duration::from_secs(timeout);
        Ok(lock.clone())
    }

    /// Removes the lock identified by `token`.
    pub fn unlock(&self, owner: i64, path: &str, token: &str) -> Result<(), LockError> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.purge(now);
        let Some(entries) = inner.locks.get_mut(path) else {
            return Err(LockError::NotFound);
        };
        let before = entries.len();
        entries.retain(|(who, lock)| !(*who == owner && lock.token == token));
        if entries.len() == before {
            return Err(LockError::NotFound);
        }
        if entries.is_empty() {
            inner.locks.remove(path);
        }
        Ok(())
    }

    /// Active locks that apply to `path` (direct and covering ancestors).
    pub fn discover(&self, owner: i64, path: &str) -> Vec<Lock> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.purge(now);
        inner.covering(owner, path).into_iter().cloned().collect()
    }

    /// Whether a write to `path` is permitted with the supplied lock tokens.
    pub fn authorize(&self, owner: i64, path: &str, tokens: &[String]) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.purge(now);
        let covering = inner.covering(owner, path);
        covering.is_empty() || covering.iter().any(|lock| tokens.contains(&lock.token))
    }

    /// Tokens of the locks that govern writes to `path`.
    pub fn covering_tokens(&self, owner: i64, path: &str) -> Vec<String> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.purge(now);
        inner
            .covering(owner, path)
            .into_iter()
            .map(|lock| lock.token.clone())
            .collect()
    }
}

impl Inner {
    fn purge(&mut self, now: Instant) {
        self.locks.retain(|_, entries| {
            entries.retain(|(_, lock)| lock.is_live(now));
            !entries.is_empty()
        });
    }

    /// Locks that govern writes to `path`: an exact lock, a depth-infinity
    /// ancestor lock, or a lock on a descendant (when locking a collection).
    fn covering(&self, owner: i64, path: &str) -> Vec<&Lock> {
        let mut found = Vec::new();
        for (locked, entries) in &self.locks {
            for (who, lock) in entries {
                if *who != owner {
                    continue;
                }
                if covers(locked, lock, path) {
                    found.push(lock);
                }
            }
        }
        found
    }

    /// The root path of the owner's lock with `token` that covers `path`.
    fn find_covering_root(&self, owner: i64, path: &str, token: &str) -> Option<String> {
        for (locked, entries) in &self.locks {
            for (who, lock) in entries {
                if *who == owner && lock.token == token && covers(locked, lock, path) {
                    return Some(locked.clone());
                }
            }
        }
        None
    }

    fn conflicts(&self, path: &str, scope: Scope) -> bool {
        self.locks.iter().any(|(locked, entries)| {
            entries.iter().any(|(_, lock)| {
                covers(locked, lock, path)
                    && (lock.scope == Scope::Exclusive || scope == Scope::Exclusive)
            })
        })
    }
}

/// Whether the lock rooted at `locked` governs `path`.
fn covers(locked: &str, lock: &Lock, path: &str) -> bool {
    locked == path
        || (lock.depth_infinity && is_ancestor(locked, path))
        || is_ancestor(path, locked)
}

/// Whether `ancestor` is a strict ancestor path of `path`.
fn is_ancestor(ancestor: &str, path: &str) -> bool {
    if ancestor == "/" {
        return path != "/";
    }
    path.strip_prefix(ancestor)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn clamp_timeout(timeout_secs: u64) -> u64 {
    match timeout_secs {
        0 => DEFAULT_TIMEOUT,
        value => value.clamp(MIN_TIMEOUT, MAX_TIMEOUT),
    }
}

fn new_token(counter: &mut u64, owner: i64, path: &str) -> String {
    *counter = counter.wrapping_add(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut buf = Vec::new();
    buf.extend_from_slice(&owner.to_le_bytes());
    buf.extend_from_slice(path.as_bytes());
    buf.extend_from_slice(&counter.to_le_bytes());
    buf.extend_from_slice(&nanos.to_le_bytes());
    format!("opaquelocktoken:{}", blake3::hash(&buf).to_hex())
}

/// Parses the state tokens from an RFC 4918 `If` header.
///
/// Every `<...>` value that is not an absolute resource URL (a tagged-list
/// resource) is treated as a state token; `Not` and entity-tag conditions are
/// ignored by this implementation.
pub fn if_tokens(header: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut rest = header;
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('>') else {
            break;
        };
        let token = &after[..end];
        let lower = token.to_ascii_lowercase();
        if !token.is_empty() && !lower.starts_with("http://") && !lower.starts_with("https://") {
            tokens.push(token.to_string());
        }
        rest = &after[end + 1..];
    }
    tokens
}

/// Parses a `Timeout` header into seconds (`0` = unspecified).
pub fn parse_timeout(header: &str) -> u64 {
    for part in header.split(',') {
        let part = part.trim();
        if let Some(seconds) = part.strip_prefix("Second-") {
            return seconds.trim().parse().unwrap_or(0);
        }
        if part.eq_ignore_ascii_case("Infinite") {
            return MAX_TIMEOUT;
        }
    }
    0
}

/// Strips angle brackets from a `Lock-Token` header value.
pub fn lock_token_value(header: &str) -> String {
    header
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

/// One condition inside an `If` header list.
enum Condition {
    Token { negated: bool, value: String },
    Etag { negated: bool, value: String },
}

/// Evaluates an RFC 4918 `If` header against the resource's current ETag and
/// the lock tokens that hold it.
///
/// Only untagged lists (applying to the request URI) are evaluated, which is
/// what write clients use; tagged resource lists are ignored. The header is
/// satisfied when at least one list is true, and a list is a conjunction of
/// its token and entity-tag conditions (`Not` negates a condition).
pub fn evaluate_if(header: &str, current_etag: Option<&str>, covering: &[String]) -> bool {
    for group in if_groups(header) {
        let conditions = parse_conditions(&group);
        if !conditions.is_empty()
            && conditions.iter().all(|condition| match condition {
                Condition::Token { negated, value } => {
                    covering.iter().any(|token| token == value) != *negated
                }
                Condition::Etag { negated, value } => {
                    (current_etag == Some(value.as_str())) != *negated
                }
            })
        {
            return true;
        }
    }
    false
}

fn if_groups(header: &str) -> Vec<String> {
    let mut groups = Vec::new();
    let mut rest = header;
    while let Some(start) = rest.find('(') {
        let after = &rest[start + 1..];
        let Some(end) = after.find(')') else {
            break;
        };
        groups.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    groups
}

fn parse_conditions(group: &str) -> Vec<Condition> {
    let mut conditions = Vec::new();
    let mut negated = false;
    let mut rest = group;
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        if let Some(after) = rest.strip_prefix("Not")
            && (after.is_empty()
                || after.starts_with(char::is_whitespace)
                || after.starts_with('<')
                || after.starts_with('['))
        {
            negated = true;
            rest = after;
            continue;
        }
        if let Some(after) = rest.strip_prefix('<')
            && let Some(end) = after.find('>')
        {
            conditions.push(Condition::Token {
                negated,
                value: after[..end].to_string(),
            });
            negated = false;
            rest = &after[end + 1..];
            continue;
        }
        if let Some(after) = rest.strip_prefix('[')
            && let Some(end) = after.find(']')
        {
            conditions.push(Condition::Etag {
                negated,
                value: after[..end].to_string(),
            });
            negated = false;
            rest = &after[end + 1..];
            continue;
        }
        match rest.find(char::is_whitespace) {
            Some(pos) => rest = &rest[pos..],
            None => break,
        }
    }
    conditions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_conflicts_but_shared_coexists() {
        let locks = LockManager::new();
        locks
            .lock(1, "/a", Scope::Exclusive, None, true, 3600)
            .unwrap();
        assert_eq!(
            locks.lock(1, "/a", Scope::Shared, None, true, 3600),
            Err(LockError::Conflict)
        );
        assert_eq!(
            locks.lock(1, "/a", Scope::Exclusive, None, true, 3600),
            Err(LockError::Conflict)
        );

        let shared = LockManager::new();
        shared
            .lock(1, "/b", Scope::Shared, None, false, 3600)
            .unwrap();
        shared
            .lock(1, "/b", Scope::Shared, None, false, 3600)
            .unwrap();
    }

    #[test]
    fn infinity_lock_covers_descendants() {
        let locks = LockManager::new();
        let lock = locks
            .lock(1, "/a", Scope::Exclusive, None, true, 3600)
            .unwrap();
        assert!(!locks.authorize(1, "/a/b/c.txt", &[]));
        assert!(locks.authorize(1, "/a/b/c.txt", std::slice::from_ref(&lock.token)));
        assert!(locks.authorize(1, "/other", &[]));
    }

    #[test]
    fn shallow_lock_covers_only_itself() {
        let locks = LockManager::new();
        locks
            .lock(1, "/a", Scope::Exclusive, None, false, 3600)
            .unwrap();
        assert!(locks.authorize(1, "/a/b", &[]));
        assert!(!locks.authorize(1, "/a", &[]));
    }

    #[test]
    fn unlock_requires_matching_token() {
        let locks = LockManager::new();
        let lock = locks
            .lock(1, "/a", Scope::Exclusive, None, false, 3600)
            .unwrap();
        assert_eq!(
            locks.unlock(1, "/a", "opaquelocktoken:nope"),
            Err(LockError::NotFound)
        );
        assert_eq!(locks.unlock(1, "/a", &lock.token), Ok(()));
    }

    #[test]
    fn evaluates_etag_and_not_conditions() {
        let covering = vec!["opaquelocktoken:abc".to_string()];
        let etag = "\"v1\"";
        assert!(evaluate_if(
            "(<opaquelocktoken:abc>)",
            Some(etag),
            &covering
        ));
        assert!(!evaluate_if(
            "(<opaquelocktoken:nope>)",
            Some(etag),
            &covering
        ));
        // litmus fail_complex_cond_put: matching token but corrupted ETag.
        let complex = "(<opaquelocktoken:abc> [\"bad\"]) (Not <DAV:no-lock> [\"bad\"])";
        assert!(!evaluate_if(complex, Some(etag), &covering));
        assert!(evaluate_if(
            "(<opaquelocktoken:abc> [\"v1\"])",
            Some(etag),
            &covering
        ));
    }

    #[test]
    fn parses_if_and_timeout() {
        let header = "(<opaquelocktoken:abc> <urn:other:x>) Not <opaquelocktoken:def>";
        assert_eq!(
            if_tokens(header),
            vec![
                "opaquelocktoken:abc".to_string(),
                "urn:other:x".to_string(),
                "opaquelocktoken:def".to_string()
            ]
        );
        // Tagged-list resource URLs are not state tokens.
        let tagged = "<http://host/dav/a> (<opaquelocktoken:abc>)";
        assert_eq!(if_tokens(tagged), vec!["opaquelocktoken:abc".to_string()]);
        assert_eq!(parse_timeout("Second-120"), 120);
        assert_eq!(parse_timeout("Infinite"), MAX_TIMEOUT);
        assert_eq!(parse_timeout("garbage"), 0);
        assert_eq!(lock_token_value("<opaquelocktoken:x>"), "opaquelocktoken:x");
    }
}
