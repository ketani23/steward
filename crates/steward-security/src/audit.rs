//! Audit logger implementation.
//!
//! Append-only audit logging backed by PostgreSQL:
//! - Every action, decision, and blocked attempt is logged
//! - No updates or deletes permitted
//! - Supports filtered queries by time range, event type, outcome
//! - Secrets are redacted before storage via LeakDetector
//!
//! See `docs/architecture.md` Ring 3 (Audit & Observability) for full requirements.

// TODO: Implement AuditLogger trait from steward-types
