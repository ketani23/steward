Read docs/architecture.md section 8.11 (Connection Lifecycle and Circuit Breaker).
Read crates/steward-types/src/traits.rs for the CircuitBreaker trait.

Implement the circuit breaker in crates/steward-tools/src/mcp/circuit_breaker.rs.

Requirements:
- Implement the CircuitBreaker trait from steward-types
- Three states: Closed (healthy), Open (broken), HalfOpen (testing recovery)
- Configuration (from manifest YAML): error_threshold, error_window (duration),
  latency_threshold (duration), recovery_timeout (duration), recovery_probes (count),
  max_recovery_backoff (duration)
- Closed → Open: when consecutive errors in the error window exceed threshold
- Open → HalfOpen: after recovery_timeout elapses
- HalfOpen → Closed: after recovery_probes consecutive successes
- HalfOpen → Open: on any failure during probing
- Exponential backoff with jitter on recovery_timeout (capped at max_recovery_backoff)
- record_success() and record_failure() update internal state
- state() returns current CircuitState
- attempt_probe() returns true if a probe call should be allowed (HalfOpen state,
  and probe slot available)
- Thread-safe: use AtomicU64 or Mutex for state updates
- Include a method to get metrics: total_successes, total_failures,
  time_in_current_state, trips_count

Write tests:
- Test normal operation (closed state, recording successes)
- Test transition to open after threshold errors
- Test that calls are rejected in open state
- Test automatic transition to half-open after timeout
- Test successful recovery (half-open → closed)
- Test failed recovery (half-open → open with increased backoff)
- Test exponential backoff calculation with jitter
- Test concurrent access from multiple threads

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-tools` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(tools): implement circuit breaker with exponential backoff and concurrent access"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(tools): implement circuit breaker" --body "Implements CircuitBreaker trait with three-state machine (Closed/Open/HalfOpen), exponential backoff with jitter, thread-safe state updates, and metrics." --base main`
