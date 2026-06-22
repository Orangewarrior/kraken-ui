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
/// State is process-local and intentionally cheap. The application pairs it with
/// a persistent GCRA authentication limiter when request rate limiting is
/// enabled, so replicas share broad login pressure while this structure keeps
/// short local lockouts simple.
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

/// Counts authentication failures per account across *all* source IPs, without
/// ever locking — locking is `LoginThrottle`'s job and is keyed by IP, precisely
/// so a victim cannot be locked out from addresses they do not control. This
/// monitor exists only for detection: when one account's failures cross
/// `alert_threshold` inside `window`, [`Self::note_failure`] returns `true` once
/// so the caller can raise an audit event. It surfaces distributed guessing that
/// per-IP throttling, by design, cannot see.
#[derive(Debug)]
pub struct AccountFailureMonitor {
    entries: Mutex<HashMap<String, AccountFailures>>,
    window: Duration,
    alert_threshold: u32,
}

#[derive(Debug)]
struct AccountFailures {
    count: u32,
    window_started: Instant,
    alerted: bool,
}

impl AccountFailureMonitor {
    pub fn new(window: Duration, alert_threshold: u32) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            window,
            alert_threshold,
        }
    }

    /// A sensible default: alert once an account accumulates 50 failures within 15
    /// minutes, regardless of how many addresses they come from.
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(15 * 60), 50)
    }

    /// Records a failure for `account` and returns `true` exactly once: when the
    /// alert threshold is first crossed inside the current window.
    pub fn note_failure(&self, account: &str) -> bool {
        self.note_failure_at(account, Instant::now())
    }

    fn note_failure_at(&self, account: &str, now: Instant) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        // Keep the map bounded: drop accounts whose window has elapsed.
        entries.retain(|_, failures| now.duration_since(failures.window_started) <= self.window);
        let failures = entries
            .entry(account.to_owned())
            .or_insert(AccountFailures {
                count: 0,
                window_started: now,
                alerted: false,
            });
        if now.duration_since(failures.window_started) > self.window {
            *failures = AccountFailures {
                count: 0,
                window_started: now,
                alerted: false,
            };
        }
        failures.count += 1;
        if failures.count >= self.alert_threshold && !failures.alerted {
            failures.alerted = true;
            return true;
        }
        false
    }
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

    use super::AccountFailureMonitor;

    #[test]
    fn account_monitor_alerts_once_at_the_threshold() {
        let monitor = AccountFailureMonitor::new(Duration::from_secs(600), 3);
        let now = Instant::now();
        assert!(!monitor.note_failure_at("admin", now));
        assert!(!monitor.note_failure_at("admin", now));
        // The third failure crosses the threshold and fires exactly once.
        assert!(monitor.note_failure_at("admin", now));
        assert!(!monitor.note_failure_at("admin", now));
    }

    #[test]
    fn account_monitor_resets_after_the_window() {
        let monitor = AccountFailureMonitor::new(Duration::from_secs(60), 2);
        let now = Instant::now();
        assert!(!monitor.note_failure_at("admin", now));
        // A failure after the window starts a fresh count, so no alert yet.
        let later = now + Duration::from_secs(61);
        assert!(!monitor.note_failure_at("admin", later));
    }
}
