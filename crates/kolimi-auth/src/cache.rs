use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Builds a cache key for a credential pair, without retaining the password.
/// The username is lowercased so `Alice` and `alice` share lockout/cache
/// state (SQLite matches usernames `COLLATE NOCASE`).
pub fn credential_cache_key(username: &str, password: &str) -> String {
    format!(
        "{}:{}",
        username.to_lowercase(),
        hex::encode(blake3::hash(password.as_bytes()).as_bytes())
    )
}

/// A bounded, short-lived cache mapping opaque keys to user ids.
///
/// Used to avoid running Argon2id on every WebDAV request that carries
/// Basic credentials: clients like rclone authenticate on every request.
pub struct CredentialCache {
    inner: Mutex<HashMap<String, (i64, i64, Instant)>>,
    ttl: Duration,
    capacity: usize,
}

impl CredentialCache {
    /// Creates a cache with the given TTL and entry cap.
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            capacity: capacity.max(1),
        }
    }

    /// Returns the cached `(user_id, credentials_version)` for `key` if fresh.
    pub fn get(&self, key: &str) -> Option<(i64, i64)> {
        let mut map = self.inner.lock().ok()?;
        let (user_id, version, inserted) = map.get(key).copied()?;
        if inserted.elapsed() >= self.ttl {
            map.remove(key);
            return None;
        }
        Some((user_id, version))
    }

    /// Caches `(user_id, credentials_version)` under `key`, evicting stale or
    /// arbitrary entries when over capacity.
    pub fn insert(&self, key: String, user_id: i64, credentials_version: i64) {
        let Ok(mut map) = self.inner.lock() else {
            return;
        };
        map.insert(key, (user_id, credentials_version, Instant::now()));
        if map.len() > self.capacity {
            let ttl = self.ttl;
            map.retain(|_, (_, _, inserted)| inserted.elapsed() < ttl);
        }
        while map.len() > self.capacity {
            let Some(evict) = map.keys().next().cloned() else {
                break;
            };
            map.remove(&evict);
        }
    }

    /// Removes everything (used on password change and in tests).
    pub fn clear(&self) {
        if let Ok(mut map) = self.inner.lock() {
            map.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::*;

    #[test]
    fn credential_keys_hide_the_password() {
        let key = credential_cache_key("alice", "hunter2");
        assert!(key.starts_with("alice:"));
        assert!(!key.contains("hunter2"));
        assert_ne!(key, credential_cache_key("alice", "hunter3"));
    }

    #[test]
    fn stores_and_expires() {
        // Freshness is checked with a long TTL so an unlucky scheduling
        // delay on a busy CI runner cannot expire the entry before read.
        let cache = CredentialCache::new(Duration::from_secs(60), 16);
        cache.insert("k".to_string(), 42, 0);
        assert_eq!(cache.get("k"), Some((42, 0)));

        // Expiry is checked separately with a short TTL and a sleep well
        // beyond it.
        let expiring = CredentialCache::new(Duration::from_millis(20), 16);
        expiring.insert("k".to_string(), 42, 0);
        sleep(Duration::from_millis(200));
        assert_eq!(expiring.get("k"), None);
    }

    #[test]
    fn respects_capacity() {
        let cache = CredentialCache::new(Duration::from_secs(60), 2);
        cache.insert("a".to_string(), 1, 0);
        cache.insert("b".to_string(), 2, 0);
        cache.insert("c".to_string(), 3, 0);
        let present = ["a", "b", "c"]
            .iter()
            .filter(|k| cache.get(k).is_some())
            .count();
        assert!(present <= 2);
    }

    #[test]
    fn clear_empties_everything() {
        let cache = CredentialCache::new(Duration::from_secs(60), 16);
        cache.insert("k".to_string(), 42, 0);
        cache.clear();
        assert_eq!(cache.get("k"), None);
    }
}
