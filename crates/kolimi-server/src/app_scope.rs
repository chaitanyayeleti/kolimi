//! Protocol-level scopes for app passwords.
//!
//! Scopes are deliberately coarse: a token is for a class of client (files,
//! calendars, contacts, or sync), not for an individual folder. The matrix is
//! deny-by-default, so a route added later requires an explicit decision.
//!
//! Full access remains `*` for backward compatibility with tokens created
//! before scopes existed and for clients that genuinely need account
//! management.

use std::collections::BTreeSet;

use axum::http::Method;

/// Scopes accepted by the API.
pub const VALID_SCOPES: &[&str] = &[
    "*",
    "files:read",
    "files:write",
    "caldav:read",
    "caldav:write",
    "carddav:read",
    "carddav:write",
    "sync",
];

/// A parsed, normalized scope set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeSet {
    full: bool,
    scopes: BTreeSet<&'static str>,
}

impl ScopeSet {
    /// Full account access (`*`).
    pub fn full() -> Self {
        Self {
            full: true,
            scopes: BTreeSet::new(),
        }
    }

    /// Parses a stored value: `*`, a comma-separated list, or a JSON array.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("scopes must not be empty".to_string());
        }
        let values: Vec<String> = if raw.starts_with('[') {
            serde_json::from_str::<Vec<String>>(raw)
                .map_err(|_| "scopes must be a JSON array of strings".to_string())?
        } else {
            raw.split(',')
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect()
        };
        Self::from_values(values)
    }

    /// Builds a set from user/API-provided values.
    pub fn from_values(values: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut set = Self::default();
        for value in values {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let canonical = VALID_SCOPES
                .iter()
                .copied()
                .find(|known| *known == value)
                .ok_or_else(|| format!("unknown scope: {value}"))?;
            if canonical == "*" {
                return Ok(Self::full());
            }
            set.scopes.insert(canonical);
        }
        if set.scopes.is_empty() {
            return Err("scopes must include at least one scope".to_string());
        }
        Ok(set)
    }

    /// The storage representation (`*` or a comma-separated list).
    pub fn to_storage(&self) -> String {
        if self.full {
            "*".to_string()
        } else {
            self.scopes.iter().copied().collect::<Vec<_>>().join(",")
        }
    }

    /// Whether this token has unrestricted account access.
    pub fn is_full(&self) -> bool {
        self.full
    }

    /// Whether the set contains a scope, with write implying read.
    pub fn allows(&self, scope: &str) -> bool {
        if self.full {
            return true;
        }
        if self.scopes.contains(scope) {
            return true;
        }
        match scope {
            "files:read" => self.scopes.contains("files:write"),
            "caldav:read" => self.scopes.contains("caldav:write"),
            "carddav:read" => self.scopes.contains("carddav:write"),
            _ => false,
        }
    }

    fn any_dav_read(&self) -> bool {
        self.allows("files:read") || self.allows("caldav:read") || self.allows("carddav:read")
    }

    fn files(&self, write: bool) -> bool {
        if write {
            self.allows("files:write")
        } else {
            self.allows("files:read")
        }
    }

    fn calendar(&self, write: bool) -> bool {
        if write {
            self.allows("caldav:write")
        } else {
            self.allows("caldav:read")
        }
    }

    fn contacts(&self, write: bool) -> bool {
        if write {
            self.allows("carddav:write")
        } else {
            self.allows("carddav:read")
        }
    }

    fn sync(&self) -> bool {
        self.allows("sync")
    }
}

/// Authentication proof attached to a request made with an app password.
///
/// Session and account-password requests do not carry this extension and keep
/// full access. Handlers that need to know which token was used can read it.
#[derive(Clone, Debug)]
pub struct AppPasswordAuth {
    /// App-password row id.
    pub id: i64,
    /// Parsed scopes.
    pub scopes: ScopeSet,
}

/// Whether `method` is a read/safe method for scope purposes.
fn safe_method(method: &Method) -> bool {
    matches!(
        method.as_str(),
        "GET" | "HEAD" | "OPTIONS" | "PROPFIND" | "REPORT"
    )
}

/// Whether a scoped token may call `path` with `method`.
///
/// Deny-by-default: anything not listed needs `*`.
pub fn authorize_scope(method: &Method, path: &str, scopes: &ScopeSet) -> bool {
    if scopes.is_full() {
        return true;
    }
    let write = !safe_method(method);
    if write
        && !matches!(
            method.as_str(),
            "PUT"
                | "POST"
                | "PATCH"
                | "DELETE"
                | "MKCOL"
                | "MKCALENDAR"
                | "MOVE"
                | "COPY"
                | "PROPPATCH"
                | "LOCK"
                | "UNLOCK"
        )
    {
        return false;
    }

    // WebDAV. Calendar/address-book trees get their own scope; principal and
    // well-known discovery is shared by every DAV client.
    if path == "/dav" || path == "/dav/" {
        return !write && scopes.any_dav_read();
    }
    if path.starts_with("/dav/calendars") {
        return scopes.calendar(write);
    }
    if path.starts_with("/dav/addressbooks") {
        return scopes.contacts(write);
    }
    if path.starts_with("/dav/principals") {
        return !write && scopes.any_dav_read();
    }
    if path == "/dav" || path.starts_with("/dav/") {
        return scopes.files(write);
    }
    if path == "/.well-known/caldav" {
        return !write && scopes.calendar(false);
    }
    if path == "/.well-known/carddav" {
        return !write && scopes.contacts(false);
    }

    // Identity probes and version are harmless read-only calls used by
    // clients to confirm credentials.
    if matches!(
        path,
        "/api/me" | "/api/me/usage" | "/api/version" | "/version"
    ) {
        return !write;
    }
    // A device must always be able to revoke the token it authenticated with.
    if method == Method::DELETE && path == "/api/me/app-passwords/current" {
        return true;
    }

    if path == "/api/browse"
        || path == "/api/search"
        || path == "/api/preview"
        || path == "/api/files/info"
        || path == "/api/files/manifest"
        || path.starts_with("/api/files/key")
        || path.starts_with("/api/files/share-key")
    {
        return !write && (scopes.files(false) || scopes.sync());
    }
    if path == "/api/files/encrypt" || path == "/api/files/move" {
        return write && (scopes.files(true) || scopes.sync());
    }
    if path == "/api/files" {
        return write && (scopes.files(true) || scopes.sync());
    }

    if path.starts_with("/api/chunks") {
        return if write {
            scopes.files(true) || scopes.sync()
        } else {
            scopes.files(false) || scopes.sync()
        };
    }
    if path.starts_with("/api/sync") {
        return !write && (scopes.files(false) || scopes.sync());
    }
    if path.starts_with("/api/trash") || path.starts_with("/api/versions") {
        return if write {
            scopes.files(true) || scopes.sync()
        } else {
            scopes.files(false) || scopes.sync()
        };
    }

    // Encryption/keyring/MLS and share metadata are all part of the sync
    // transport. Sharing itself is allowed so a sync client can maintain the
    // MLS groups that govern encrypted shared folders.
    if path.starts_with("/api/e2ee") || path.starts_with("/api/mls") {
        return scopes.sync();
    }
    if path.starts_with("/api/shares") || path.starts_with("/api/groups") {
        return scopes.sync();
    }

    // Account administration, credentials, and token management need full
    // access.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(values: &[&str]) -> ScopeSet {
        ScopeSet::from_values(values.iter().map(|value| value.to_string())).unwrap()
    }

    #[test]
    fn parses_storage_forms_and_rejects_unknown() {
        assert!(ScopeSet::parse("*").unwrap().is_full());
        assert_eq!(
            ScopeSet::parse("files:read,sync").unwrap().to_storage(),
            "files:read,sync"
        );
        assert_eq!(
            ScopeSet::parse(r#"["caldav:write"]"#).unwrap().to_storage(),
            "caldav:write"
        );
        assert!(ScopeSet::parse("files:nope").is_err());
        assert!(ScopeSet::parse("").is_err());
    }

    #[test]
    fn write_implies_read() {
        let files = set(&["files:write"]);
        assert!(files.allows("files:read"));
        assert!(files.allows("files:write"));
        assert!(!files.allows("sync"));
        let calendars = set(&["caldav:write"]);
        assert!(calendars.allows("caldav:read"));
        assert!(!calendars.allows("carddav:read"));
    }

    #[test]
    fn file_scope_cannot_reach_accounts_or_shares() {
        let files = set(&["files:read"]);
        assert!(authorize_scope(&Method::GET, "/api/browse", &files));
        assert!(authorize_scope(&Method::GET, "/dav/docs/a.txt", &files));
        assert!(!authorize_scope(&Method::GET, "/api/users", &files));
        assert!(!authorize_scope(&Method::DELETE, "/api/shares/1", &files));
        assert!(!authorize_scope(&Method::PUT, "/api/files/encrypt", &files));
        assert!(authorize_scope(
            &Method::PUT,
            "/api/files/encrypt",
            &set(&["files:write"])
        ));
    }

    #[test]
    fn calendar_scope_is_limited_to_calendars() {
        let calendars = set(&["caldav:read"]);
        assert!(authorize_scope(
            &Method::from_bytes(b"PROPFIND").unwrap(),
            "/dav/calendars/alice/",
            &calendars
        ));
        assert!(!authorize_scope(
            &Method::GET,
            "/dav/addressbooks/alice/",
            &calendars
        ));
        assert!(!authorize_scope(
            &Method::PUT,
            "/dav/calendars/alice/event.ics",
            &calendars
        ));
        assert!(authorize_scope(
            &Method::PUT,
            "/dav/calendars/alice/event.ics",
            &set(&["caldav:write"])
        ));
    }

    #[test]
    fn sync_scope_covers_transport_and_share_metadata() {
        let sync = set(&["sync"]);
        assert!(authorize_scope(&Method::GET, "/api/e2ee/keyring", &sync));
        assert!(authorize_scope(
            &Method::POST,
            "/api/mls/key-packages",
            &sync
        ));
        assert!(authorize_scope(&Method::GET, "/api/shares/owned", &sync));
        assert!(authorize_scope(&Method::PUT, "/api/files", &sync));
        assert!(!authorize_scope(&Method::GET, "/api/users", &sync));
        assert!(!authorize_scope(&Method::PUT, "/dav/docs/a.txt", &sync));
    }

    #[test]
    fn deny_by_default_and_unknown_methods() {
        let files = set(&["files:write"]);
        assert!(!authorize_scope(&Method::GET, "/api/unknown", &files));
        assert!(!authorize_scope(
            &Method::from_bytes(b"BREW").unwrap(),
            "/api/browse",
            &files
        ));
        assert!(authorize_scope(
            &Method::from_bytes(b"BREW").unwrap(),
            "/api/browse",
            &ScopeSet::full()
        ));
    }

    #[test]
    fn device_can_always_revoke_itself() {
        let calendar = set(&["caldav:read"]);
        assert!(authorize_scope(
            &Method::DELETE,
            "/api/me/app-passwords/current",
            &calendar
        ));
        assert!(!authorize_scope(
            &Method::DELETE,
            "/api/me/app-passwords/3",
            &calendar
        ));
    }
}
