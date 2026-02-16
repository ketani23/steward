//! Circuit breaker for MCP server connections.
//!
//! State machine: Closed → Open → HalfOpen
//! - Tracks consecutive errors within a time window
//! - Exponential backoff with jitter on recovery
//! - Configurable thresholds and timeouts
//!
//! See `docs/architecture.md` section 8.11 for circuit breaker specification.

// TODO: Implement CircuitBreaker trait from steward-types
