//! Circuit breaker for MCP server connections.
//!
//! State machine: Closed → Open → HalfOpen
//! - Tracks consecutive errors within a time window
//! - Exponential backoff with jitter on recovery
//! - Configurable thresholds and timeouts
//!
//! See `docs/architecture.md` section 8.11 for circuit breaker specification.

use std::time::{Duration, Instant};

use steward_types::actions::{CircuitBreakerMetrics, CircuitState};
use steward_types::config::CircuitBreakerConfig;
use steward_types::traits::CircuitBreaker;

/// Circuit breaker implementation for MCP server connections.
///
/// Manages the Closed → Open → HalfOpen state machine with exponential
/// backoff and jitter on recovery timeouts.
///
/// # Thread Safety
///
/// The struct itself requires `&mut self` per the trait contract. For concurrent
/// access, wrap in `std::sync::Mutex` or `tokio::sync::Mutex`.
pub struct McpCircuitBreaker {
    config: CircuitBreakerConfig,
    current_state: CircuitState,
    /// Timestamps of consecutive failures within the error window.
    failure_timestamps: Vec<Instant>,
    /// Number of consecutive successful probes in HalfOpen state.
    consecutive_probe_successes: u32,
    /// When the circuit last transitioned to Open state.
    opened_at: Option<Instant>,
    /// When the current state was entered.
    state_entered_at: Instant,
    /// Number of consecutive trips (used for exponential backoff).
    consecutive_trips: u32,
    /// Total recorded successes.
    total_successes: u64,
    /// Total recorded failures.
    total_failures: u64,
    /// Total number of times the circuit tripped open.
    trips_count: u64,
}

impl McpCircuitBreaker {
    /// Create a new circuit breaker with the given configuration.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            current_state: CircuitState::Closed,
            failure_timestamps: Vec::new(),
            consecutive_probe_successes: 0,
            opened_at: None,
            state_entered_at: Instant::now(),
            consecutive_trips: 0,
            total_successes: 0,
            total_failures: 0,
            trips_count: 0,
        }
    }

    /// Get a snapshot of current metrics.
    pub fn metrics(&self) -> CircuitBreakerMetrics {
        CircuitBreakerMetrics {
            total_successes: self.total_successes,
            total_failures: self.total_failures,
            time_in_current_state_ms: self.state_entered_at.elapsed().as_millis() as u64,
            trips_count: self.trips_count,
            current_state: self.current_state,
        }
    }

    /// Calculate the current recovery timeout with exponential backoff and jitter.
    ///
    /// Base timeout doubles for each consecutive trip, capped at `max_recovery_backoff`.
    /// Jitter adds ±25% randomness to prevent thundering herd.
    fn recovery_timeout(&self) -> Duration {
        let base = Duration::from_secs(self.config.recovery_timeout_secs);
        let max = Duration::from_secs(self.config.max_recovery_backoff_secs);

        // Exponential backoff: base * 2^(consecutive_trips - 1), capped
        let shift = self.consecutive_trips.saturating_sub(1).min(63);
        let multiplier: u32 = 1u64
            .checked_shl(shift)
            .unwrap_or(u64::MAX)
            .min(u32::MAX as u64) as u32;
        let backoff = base.saturating_mul(multiplier);
        let capped = backoff.min(max);

        // Jitter: ±25% using simple deterministic-ish variance from failure count
        // For real jitter we use the lower bits of the current time
        let jitter_range = capped.as_millis() as u64 / 4; // 25%
        if jitter_range == 0 {
            return capped;
        }
        let jitter_source = self.state_entered_at.elapsed().as_nanos() as u64;
        let jitter_offset = jitter_source % (jitter_range * 2);
        let jitter_signed = jitter_offset as i64 - jitter_range as i64;

        let result_ms = capped.as_millis() as i64 + jitter_signed;
        Duration::from_millis(result_ms.max(1) as u64)
    }

    /// Check if the recovery timeout has elapsed since the circuit opened.
    fn recovery_timeout_elapsed(&self) -> bool {
        match self.opened_at {
            Some(opened) => opened.elapsed() >= self.recovery_timeout(),
            None => false,
        }
    }

    /// Transition to a new state, updating bookkeeping.
    fn transition_to(&mut self, new_state: CircuitState) {
        self.current_state = new_state;
        self.state_entered_at = Instant::now();

        match new_state {
            CircuitState::Open => {
                self.opened_at = Some(Instant::now());
                self.consecutive_probe_successes = 0;
            }
            CircuitState::HalfOpen => {
                self.consecutive_probe_successes = 0;
            }
            CircuitState::Closed => {
                self.failure_timestamps.clear();
                self.consecutive_trips = 0;
                self.consecutive_probe_successes = 0;
                self.opened_at = None;
            }
        }
    }

    /// Prune failure timestamps outside the error window.
    fn prune_old_failures(&mut self) {
        let window = Duration::from_secs(self.config.error_window_secs);
        let cutoff = Instant::now() - window;
        self.failure_timestamps.retain(|ts| *ts >= cutoff);
    }
}

impl CircuitBreaker for McpCircuitBreaker {
    fn record_success(&mut self) {
        self.total_successes += 1;

        match self.current_state {
            CircuitState::Closed => {
                // Reset failure tracking on success in closed state.
                self.failure_timestamps.clear();
            }
            CircuitState::HalfOpen => {
                self.consecutive_probe_successes += 1;
                if self.consecutive_probe_successes >= self.config.recovery_probes {
                    tracing::info!(
                        probes = self.consecutive_probe_successes,
                        "circuit breaker recovered, transitioning to Closed"
                    );
                    self.transition_to(CircuitState::Closed);
                }
            }
            CircuitState::Open => {
                // Successes in Open state are unexpected (shouldn't happen as calls
                // should be rejected), but treat as recovery signal.
                tracing::warn!("unexpected success recorded while circuit is Open");
            }
        }
    }

    fn record_failure(&mut self) {
        self.total_failures += 1;

        match self.current_state {
            CircuitState::Closed => {
                self.prune_old_failures();
                self.failure_timestamps.push(Instant::now());

                if self.failure_timestamps.len() as u32 >= self.config.error_threshold {
                    self.consecutive_trips += 1;
                    self.trips_count += 1;
                    tracing::warn!(
                        failures = self.failure_timestamps.len(),
                        threshold = self.config.error_threshold,
                        trips = self.trips_count,
                        "circuit breaker tripped, transitioning to Open"
                    );
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure during probing sends us back to Open with increased backoff.
                self.consecutive_trips += 1;
                self.trips_count += 1;
                tracing::warn!(
                    consecutive_trips = self.consecutive_trips,
                    "probe failure in HalfOpen, transitioning back to Open with backoff"
                );
                self.transition_to(CircuitState::Open);
            }
            CircuitState::Open => {
                // Already open, just count the failure.
                tracing::debug!("failure recorded while circuit is already Open");
            }
        }
    }

    fn state(&self) -> CircuitState {
        // Check for automatic Open → HalfOpen transition based on timeout.
        if self.current_state == CircuitState::Open && self.recovery_timeout_elapsed() {
            // We can't mutate self here since state() takes &self.
            // Return HalfOpen to signal the transition should happen.
            // The actual state update occurs on the next attempt_probe() or
            // record_success()/record_failure() call.
            return CircuitState::HalfOpen;
        }
        self.current_state
    }

    fn attempt_probe(&mut self) -> bool {
        // First, handle automatic Open → HalfOpen transition.
        if self.current_state == CircuitState::Open && self.recovery_timeout_elapsed() {
            tracing::info!(
                recovery_timeout_secs = self.config.recovery_timeout_secs,
                consecutive_trips = self.consecutive_trips,
                "recovery timeout elapsed, transitioning to HalfOpen"
            );
            self.transition_to(CircuitState::HalfOpen);
        }

        match self.current_state {
            CircuitState::HalfOpen => {
                // Allow probe if we haven't yet reached the required number of probes.
                self.consecutive_probe_successes < self.config.recovery_probes
            }
            CircuitState::Closed => {
                // Circuit is healthy, no probing needed — normal calls proceed.
                false
            }
            CircuitState::Open => {
                // Still in cooldown, no probes allowed.
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            error_threshold: 3,
            error_window_secs: 10,
            latency_threshold_secs: 5,
            recovery_timeout_secs: 2,
            recovery_probes: 2,
            max_recovery_backoff_secs: 60,
        }
    }

    #[test]
    fn test_initial_state_is_closed() {
        let cb = McpCircuitBreaker::new(default_config());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_normal_operation_stays_closed() {
        let mut cb = McpCircuitBreaker::new(default_config());

        // Recording successes keeps circuit closed.
        for _ in 0..10 {
            cb.record_success();
        }
        assert_eq!(cb.state(), CircuitState::Closed);

        let metrics = cb.metrics();
        assert_eq!(metrics.total_successes, 10);
        assert_eq!(metrics.total_failures, 0);
        assert_eq!(metrics.trips_count, 0);
    }

    #[test]
    fn test_failures_below_threshold_stay_closed() {
        let mut cb = McpCircuitBreaker::new(default_config());

        // 2 failures is below threshold of 3.
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_transition_to_open_after_threshold_errors() {
        let mut cb = McpCircuitBreaker::new(default_config());

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure(); // Hits threshold of 3
        assert_eq!(cb.state(), CircuitState::Open);

        let metrics = cb.metrics();
        assert_eq!(metrics.trips_count, 1);
        assert_eq!(metrics.total_failures, 3);
    }

    #[test]
    fn test_calls_rejected_in_open_state() {
        let mut cb = McpCircuitBreaker::new(default_config());

        // Trip the circuit.
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Open);

        // Probes should not be allowed while in Open state (timeout hasn't elapsed).
        assert!(!cb.attempt_probe());
    }

    #[test]
    fn test_success_clears_failure_count() {
        let mut cb = McpCircuitBreaker::new(default_config());

        cb.record_failure();
        cb.record_failure();
        // A success should clear the failure tracking.
        cb.record_success();
        // Now another failure should start fresh.
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_automatic_transition_to_half_open_after_timeout() {
        let config = CircuitBreakerConfig {
            recovery_timeout_secs: 0, // Immediate recovery for testing
            ..default_config()
        };
        let mut cb = McpCircuitBreaker::new(config);

        // Trip the circuit.
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.current_state, CircuitState::Open);

        // With 0-second timeout, state() should report HalfOpen immediately.
        // (The actual internal transition happens on attempt_probe.)
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // attempt_probe should transition and allow a probe.
        assert!(cb.attempt_probe());
        assert_eq!(cb.current_state, CircuitState::HalfOpen);
    }

    #[test]
    fn test_successful_recovery_half_open_to_closed() {
        let config = CircuitBreakerConfig {
            recovery_timeout_secs: 0,
            recovery_probes: 2,
            ..default_config()
        };
        let mut cb = McpCircuitBreaker::new(config);

        // Trip the circuit.
        for _ in 0..3 {
            cb.record_failure();
        }

        // Transition to HalfOpen via attempt_probe.
        assert!(cb.attempt_probe());
        assert_eq!(cb.current_state, CircuitState::HalfOpen);

        // First successful probe.
        cb.record_success();
        assert_eq!(cb.current_state, CircuitState::HalfOpen); // Need 2 probes

        // Second successful probe — should close the circuit.
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);

        let metrics = cb.metrics();
        assert_eq!(metrics.trips_count, 1);
    }

    #[test]
    fn test_failed_recovery_half_open_to_open_with_increased_backoff() {
        let config = CircuitBreakerConfig {
            recovery_timeout_secs: 0,
            recovery_probes: 2,
            ..default_config()
        };
        let mut cb = McpCircuitBreaker::new(config);

        // First trip.
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.trips_count, 1);
        let first_trip_consecutive = cb.consecutive_trips;

        // Transition to HalfOpen.
        assert!(cb.attempt_probe());
        assert_eq!(cb.current_state, CircuitState::HalfOpen);

        // Probe fails — goes back to Open.
        cb.record_failure();
        assert_eq!(cb.current_state, CircuitState::Open);
        assert_eq!(cb.trips_count, 2);
        // consecutive_trips should have incremented.
        assert!(cb.consecutive_trips > first_trip_consecutive);
    }

    #[test]
    fn test_exponential_backoff_calculation() {
        let config = CircuitBreakerConfig {
            recovery_timeout_secs: 10,
            max_recovery_backoff_secs: 300,
            ..default_config()
        };
        let mut cb = McpCircuitBreaker::new(config);

        // No trips yet — base timeout.
        assert_eq!(cb.consecutive_trips, 0);
        // With 0 consecutive trips, multiplier = 2^(0-1) but saturating_sub makes it 0,
        // so 2^0 = 1 => 10s base.
        let timeout_0 = cb.recovery_timeout();
        // Should be around 10s (±25% jitter).
        assert!(
            timeout_0.as_secs() >= 7 && timeout_0.as_secs() <= 13,
            "expected ~10s, got {:?}",
            timeout_0
        );

        // After first trip.
        cb.consecutive_trips = 1;
        let timeout_1 = cb.recovery_timeout();
        // multiplier = 2^(1-1) = 1 => 10s base.
        assert!(
            timeout_1.as_secs() >= 7 && timeout_1.as_secs() <= 13,
            "expected ~10s, got {:?}",
            timeout_1
        );

        // After second trip.
        cb.consecutive_trips = 2;
        let timeout_2 = cb.recovery_timeout();
        // multiplier = 2^(2-1) = 2 => 20s.
        assert!(
            timeout_2.as_secs() >= 15 && timeout_2.as_secs() <= 25,
            "expected ~20s, got {:?}",
            timeout_2
        );

        // After third trip.
        cb.consecutive_trips = 3;
        let timeout_3 = cb.recovery_timeout();
        // multiplier = 2^(3-1) = 4 => 40s.
        assert!(
            timeout_3.as_secs() >= 30 && timeout_3.as_secs() <= 50,
            "expected ~40s, got {:?}",
            timeout_3
        );
    }

    #[test]
    fn test_backoff_capped_at_max() {
        let config = CircuitBreakerConfig {
            recovery_timeout_secs: 10,
            max_recovery_backoff_secs: 30,
            ..default_config()
        };
        let mut cb = McpCircuitBreaker::new(config);

        // Many trips — should be capped at 30s.
        cb.consecutive_trips = 10;
        let timeout = cb.recovery_timeout();
        // 10 * 2^9 = 5120s, but capped at 30s (±25% jitter).
        assert!(
            timeout.as_secs() <= 38, // 30 + 25%
            "expected capped at ~30s, got {:?}",
            timeout
        );
    }

    #[test]
    fn test_failures_outside_error_window_ignored() {
        let config = CircuitBreakerConfig {
            error_threshold: 3,
            error_window_secs: 1, // 1-second window
            ..default_config()
        };
        let mut cb = McpCircuitBreaker::new(config);

        cb.record_failure();
        cb.record_failure();

        // Wait for the error window to expire.
        std::thread::sleep(Duration::from_millis(1100));

        // This failure is within the window, but the old ones expired.
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_metrics_snapshot() {
        let mut cb = McpCircuitBreaker::new(default_config());

        cb.record_success();
        cb.record_success();
        cb.record_failure();

        let metrics = cb.metrics();
        assert_eq!(metrics.total_successes, 2);
        assert_eq!(metrics.total_failures, 1);
        assert_eq!(metrics.trips_count, 0);
        assert_eq!(metrics.current_state, CircuitState::Closed);
        // time_in_current_state_ms is non-negative by type (u64), just verify it exists.
        let _ = metrics.time_in_current_state_ms;
    }

    #[test]
    fn test_probe_not_allowed_in_closed_state() {
        let mut cb = McpCircuitBreaker::new(default_config());
        assert!(!cb.attempt_probe());
    }

    #[test]
    fn test_consecutive_trips_reset_on_full_recovery() {
        let config = CircuitBreakerConfig {
            recovery_timeout_secs: 0,
            recovery_probes: 1,
            ..default_config()
        };
        let mut cb = McpCircuitBreaker::new(config);

        // Trip once.
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.consecutive_trips, 1);

        // Recover.
        assert!(cb.attempt_probe());
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.consecutive_trips, 0);
    }

    #[test]
    fn test_concurrent_access_with_mutex() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let config = CircuitBreakerConfig {
            error_threshold: 10_000, // Higher than total failures so we don't trip.
            ..default_config()
        };
        let cb = Arc::new(Mutex::new(McpCircuitBreaker::new(config)));

        let mut handles = Vec::new();

        // Spawn threads that record successes.
        for _ in 0..4 {
            let cb_clone = Arc::clone(&cb);
            handles.push(thread::spawn(move || {
                for _ in 0..250 {
                    cb_clone.lock().unwrap().record_success();
                }
            }));
        }

        // Spawn threads that record failures.
        for _ in 0..4 {
            let cb_clone = Arc::clone(&cb);
            handles.push(thread::spawn(move || {
                for _ in 0..250 {
                    cb_clone.lock().unwrap().record_failure();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let cb = cb.lock().unwrap();
        let metrics = cb.metrics();
        assert_eq!(metrics.total_successes, 1000);
        assert_eq!(metrics.total_failures, 1000);
        // Circuit stays closed because error_threshold (10_000) was never reached:
        // successes interleave with failures, clearing failure_timestamps each time.
        // Even without clearing, 1000 total failures < 10_000 threshold.
        assert_eq!(metrics.current_state, CircuitState::Closed);
    }

    #[test]
    fn test_full_lifecycle() {
        let config = CircuitBreakerConfig {
            error_threshold: 2,
            recovery_timeout_secs: 0,
            recovery_probes: 1,
            ..default_config()
        };
        let mut cb = McpCircuitBreaker::new(config);

        // Phase 1: Normal operation.
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);

        // Phase 2: Trip the circuit.
        cb.record_failure();
        cb.record_failure();
        // Internal state is Open, but state() returns HalfOpen because
        // recovery_timeout is 0s so it has already elapsed.
        assert_eq!(cb.current_state, CircuitState::Open);
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Phase 3: Probe and recover.
        assert!(cb.attempt_probe());
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);

        // Phase 4: Trip again.
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::HalfOpen); // 0s timeout

        // Phase 5: Probe fails — back to Open.
        assert!(cb.attempt_probe());
        cb.record_failure();
        assert_eq!(cb.current_state, CircuitState::Open);

        let metrics = cb.metrics();
        assert_eq!(metrics.trips_count, 3); // Two initial trips + one from failed probe
        assert_eq!(metrics.total_successes, 3);
        assert_eq!(metrics.total_failures, 5);
    }
}
