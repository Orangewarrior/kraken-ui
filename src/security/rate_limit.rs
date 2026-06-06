use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// A small in-memory failure counter with temporary lockout, used to slow down
/// online password guessing and credential stuffing.
///
/// The throttle is keyed by an opaque string so the caller can track attempts
/// per client IP *and* per account independently. Failures accumulate inside a
/// sliding window; once `max_failures` is reached the key is locked for
/// `lockout`. A successful authentication clears the key.
///
/// State is process-local. For a multi-replica deployment this should be backed
/// by a shared store, but even process-local throttling closes the unbounded
/// online-guessing window that existed before.
#[derive(Debug)]
pub struct LoginThrottle {
    entries: Mutex<HashMap<String, Attempt>>,
    max_failures: u32,
    window: Duration,
    lockout: Duration,
}

#[derive(Debug)]
struct Attempt {
    failures: u32,
    window_started: Instant,
    locked_until: Option<Instant>,
}

impl LoginThrottle {
    pub fn new(max_failures: u32, window: Duration, lockout: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_failures,
            window,
            lockout,
        }
    }

    /// A sensible default: 5 failures within 5 minutes locks the key for 15
    /// minutes.
    pub fn with_defaults() -> Self {
        Self::new(5, Duration::from_secs(5 * 60), Duration::from_secs(15 * 60))
    }

    /// Returns the remaining lockout duration if the key is currently locked.
    pub fn locked_for(&self, key: &str) -> Option<Duration> {
        self.locked_for_at(key, Instant::now())
    }

    /// Records a failed attempt and returns the resulting lockout, if any.
    pub fn record_failure(&self, key: &str) -> Option<Duration> {
        self.record_failure_at(key, Instant::now())
    }

    /// Clears all recorded failures for the key after a successful login.
    pub fn record_success(&self, key: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(key);
        }
    }

    fn locked_for_at(&self, key: &str, now: Instant) -> Option<Duration> {
        let mut entries = self.entries.lock().ok()?;
        let attempt = entries.get(key)?;
        match attempt.locked_until {
            Some(until) if until > now => Some(until - now),
            Some(_) => {
                // The lockout has elapsed; drop the stale record.
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    fn record_failure_at(&self, key: &str, now: Instant) -> Option<Duration> {
        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return None,
        };
        prune(&mut entries, now);

        let attempt = entries.entry(key.to_owned()).or_insert(Attempt {
            failures: 0,
            window_started: now,
            locked_until: None,
        });

        if let Some(until) = attempt.locked_until {
            if until > now {
                return Some(until - now);
            }
            // Lockout elapsed: start a fresh window.
            attempt.failures = 0;
            attempt.window_started = now;
            attempt.locked_until = None;
        }

        if now.duration_since(attempt.window_started) > self.window {
            attempt.failures = 0;
            attempt.window_started = now;
        }

        attempt.failures += 1;
        if attempt.failures >= self.max_failures {
            attempt.locked_until = Some(now + self.lockout);
            return Some(self.lockout);
        }
        None
    }
}

/// Drops entries that are neither locked nor inside their failure window, so the
/// map cannot grow without bound under churn.
fn prune(entries: &mut HashMap<String, Attempt>, now: Instant) {
    entries.retain(|_, attempt| match attempt.locked_until {
        Some(until) => until > now,
        None => now.duration_since(attempt.window_started) <= Duration::from_secs(3600),
    });
}

#[cfg(test)]
mod tests {
    use super::LoginThrottle;
    use std::time::{Duration, Instant};

    #[test]
    fn locks_after_reaching_the_failure_threshold() {
        let throttle = LoginThrottle::new(3, Duration::from_secs(60), Duration::from_secs(120));
        let now = Instant::now();
        assert!(throttle.record_failure_at("ip", now).is_none());
        assert!(throttle.record_failure_at("ip", now).is_none());
        let lockout = throttle.record_failure_at("ip", now);
        assert_eq!(lockout, Some(Duration::from_secs(120)));
        assert!(throttle.locked_for_at("ip", now).is_some());
    }

    #[test]
    fn success_clears_recorded_failures() {
        let throttle = LoginThrottle::new(3, Duration::from_secs(60), Duration::from_secs(120));
        let now = Instant::now();
        throttle.record_failure_at("ip", now);
        throttle.record_success("ip");
        assert!(throttle.locked_for_at("ip", now).is_none());
    }

    #[test]
    fn lockout_expires_after_the_window() {
        let throttle = LoginThrottle::new(1, Duration::from_secs(60), Duration::from_secs(10));
        let now = Instant::now();
        assert!(throttle.record_failure_at("ip", now).is_some());
        let later = now + Duration::from_secs(11);
        assert!(throttle.locked_for_at("ip", later).is_none());
    }
}
