use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Tracks failed authentication attempts per key and locks the key out
/// after `max_failures` failures within a rolling `window`.
pub struct FailedAuthTracker {
    inner: Mutex<HashMap<String, Entry>>,
    max_failures: u32,
    window: Duration,
    lockout: Duration,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    first_failure: Instant,
    locked_until: Option<Instant>,
}

impl FailedAuthTracker {
    /// Creates a tracker that locks a key out for `lockout` after
    /// `max_failures` in `window`.
    pub fn new(max_failures: u32, window: Duration, lockout: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_failures: max_failures.max(1),
            window,
            lockout,
        }
    }

    /// Returns the remaining lockout duration, or `None` if not locked.
    pub fn check(&self, key: &str) -> Option<Duration> {
        let now = Instant::now();
        let mut map = self.inner.lock().ok()?;
        let entry = map.get(key)?;
        match entry.locked_until {
            Some(until) if until > now => Some(until - now),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    /// Records a failed attempt, locking the key out once the threshold is hit.
    pub fn record_failure(&self, key: &str) {
        let now = Instant::now();
        let Ok(mut map) = self.inner.lock() else {
            return;
        };
        if map.len() > 10_000 {
            map.retain(|_, entry| {
                entry.locked_until.is_some_and(|until| until > now)
                    || now.duration_since(entry.first_failure) < self.window
            });
        }
        let entry = map.entry(key.to_string()).or_insert(Entry {
            failures: 0,
            first_failure: now,
            locked_until: None,
        });
        if now.duration_since(entry.first_failure) > self.window {
            entry.failures = 0;
            entry.first_failure = now;
        }
        entry.failures += 1;
        if entry.failures >= self.max_failures {
            entry.locked_until = Some(now + self.lockout);
        }
    }

    /// Clears failure state for a key after a successful authentication.
    pub fn record_success(&self, key: &str) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::*;

    #[test]
    fn locks_out_after_threshold() {
        let tracker = FailedAuthTracker::new(3, Duration::from_secs(60), Duration::from_secs(60));
        assert!(tracker.check("alice").is_none());
        tracker.record_failure("alice");
        tracker.record_failure("alice");
        assert!(tracker.check("alice").is_none());
        tracker.record_failure("alice");
        assert!(tracker.check("alice").is_some());
    }

    #[test]
    fn success_clears_failures() {
        let tracker = FailedAuthTracker::new(2, Duration::from_secs(60), Duration::from_secs(60));
        tracker.record_failure("alice");
        tracker.record_success("alice");
        tracker.record_failure("alice");
        assert!(tracker.check("alice").is_none());
    }

    #[test]
    fn lockout_expires() {
        let tracker = FailedAuthTracker::new(1, Duration::from_secs(60), Duration::from_millis(20));
        tracker.record_failure("alice");
        assert!(tracker.check("alice").is_some());
        sleep(Duration::from_millis(30));
        assert!(tracker.check("alice").is_none());
    }

    #[test]
    fn keys_are_independent() {
        let tracker = FailedAuthTracker::new(1, Duration::from_secs(60), Duration::from_secs(60));
        tracker.record_failure("alice");
        assert!(tracker.check("alice").is_some());
        assert!(tracker.check("bob").is_none());
    }
}
