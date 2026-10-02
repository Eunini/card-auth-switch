//! Circuit breaker in front of the issuer.
//!
//! Closed: every authorization goes to the issuer with a deadline.
//! Open: after `threshold` consecutive outages, skip the issuer entirely
//! and stand in immediately (no cardholder waits for a dead dependency).
//! After `open_for`, one request is let through (half-open); success
//! closes the circuit. A background health probe also closes it.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Circuit {
    failures: AtomicU32,
    threshold: u32,
    open_for: Duration,
    open_until: Mutex<Option<Instant>>,
    open: AtomicBool,
}

impl Circuit {
    pub fn new(threshold: u32, open_for: Duration) -> Self {
        Self {
            failures: AtomicU32::new(0),
            threshold: threshold.max(1),
            open_for,
            open_until: Mutex::new(None),
            open: AtomicBool::new(false),
        }
    }

    /// May a live request be attempted now?
    pub fn allow(&self) -> bool {
        if !self.open.load(Ordering::Acquire) {
            return true;
        }
        let mut g = self.open_until.lock().expect("circuit lock");
        match *g {
            Some(t) if Instant::now() >= t => {
                // Half-open: let one probe through, push the window forward.
                *g = Some(Instant::now() + self.open_for);
                true
            }
            _ => false,
        }
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    pub fn success(&self) {
        self.failures.store(0, Ordering::Release);
        if self.open.swap(false, Ordering::AcqRel) {
            *self.open_until.lock().expect("circuit lock") = None;
            tracing::info!("issuer circuit CLOSED (issuer reachable again)");
        }
    }

    pub fn failure(&self) {
        let n = self.failures.fetch_add(1, Ordering::AcqRel) + 1;
        if n >= self.threshold && !self.open.swap(true, Ordering::AcqRel) {
            *self.open_until.lock().expect("circuit lock") = Some(Instant::now() + self.open_for);
            tracing::warn!(failures = n, "issuer circuit OPEN: standing in");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_after_threshold_and_half_opens() {
        let c = Circuit::new(2, Duration::from_millis(30));
        assert!(c.allow());
        c.failure();
        assert!(c.allow());
        c.failure();
        assert!(c.is_open());
        assert!(!c.allow());
        std::thread::sleep(Duration::from_millis(35));
        assert!(c.allow(), "half-open probe");
        assert!(!c.allow(), "only one probe per window");
        c.success();
        assert!(!c.is_open());
        assert!(c.allow());
    }
}
