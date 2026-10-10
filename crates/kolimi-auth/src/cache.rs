use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Builds a cache key for a credential pair, without retaining the password.
pub fn credential_cache_key(username: &str, password: &str) -> String {
    format!(
        "{username}:{}",
        hex::encode(blake3::hash(password.as_bytes()).as_bytes())
    )
}

/// A bounded, short-lived cache mapping opaque keys to user ids.
///
/// Used to avoid running Argon2id on every WebDAV request that carries
/// Basic credentials: clients like rclone authenticate on every request.
pub struct CredentialCache {
    inner: Mutex<HashMap<String, (i64, Instant)>>,
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

    /// Returns the cached user id for `key` if present and fresh.
    pub fn get(&self, key: &str) -> Option<i64> {
        let mut map = self.inner.lock().ok()?;
        let (user_id, inserted) = map.get(key).copied()?;
        if inserted.elapsed() >= self.ttl {
            map.remove(key);
            return None;
        }
        Some(user_id)
    }

    /// Caches `user_id` under `key`, evicting stale or arbitrary entries
    /// when over capacity.
    pub fn insert(&self, key: String, user_id: i64) {
        let Ok(mut map) = self.inner.lock() else {
            return;
        };
        map.insert(key, (user_id, Instant::now()));
        if map.len() > self.capacity {
            let ttl = self.ttl;
            map.retain(|_, (_, inserted)| inserted.elapsed() < ttl);
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
        let cache = CredentialCache::new(Duration::from_millis(20), 16);
        cache.insert("k".to_string(), 42);
        assert_eq!(cache.get("k"), Some(42));
        sleep(Duration::from_millis(30));
        assert_eq!(cache.get("k"), None);
    }

    #[test]
    fn respects_capacity() {
        let cache = CredentialCache::new(Duration::from_secs(60), 2);
        cache.insert("a".to_string(), 1);
        cache.insert("b".to_string(), 2);
        cache.insert("c".to_string(), 3);
        let present = ["a", "b", "c"]
            .iter()
            .filter(|k| cache.get(k).is_some())
            .count();
        assert!(present <= 2);
    }

    #[test]
    fn clear_empties_everything() {
        let cache = CredentialCache::new(Duration::from_secs(60), 16);
        cache.insert("k".to_string(), 42);
        cache.clear();
        assert_eq!(cache.get("k"), None);
    }
}
