# TASK-1.3: Audit Logger

**Branch:** `feat/audit-logger`
**Crate:** `steward-security`
**File:** `crates/steward-security/src/audit.rs`

## Instructions

1. Read `docs/architecture.md` sections on Ring 3 (Audit & Observability) for full requirements.
2. Read `crates/steward-types/src/traits.rs` for the `AuditLogger` trait you must implement.
3. Read `crates/steward-types/src/actions.rs` for `AuditEvent`, `AuditEventType`, `AuditFilter`, and `ActionOutcome` types.
4. Implement the audit logger in `crates/steward-security/src/audit.rs`.
5. Write comprehensive tests.
6. Verify with `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test -p steward-security`.
7. Commit, push, and create a PR.

## Requirements

- Implement the `AuditLogger` trait from `steward-types`
- Create two implementations:

### `InMemoryAuditLogger` (for testing and development)
- Stores events in a `Vec<AuditEvent>` behind an `Arc<RwLock<...>>`
- Implements the full `AuditLogger` trait
- Useful as a mock in tests for other modules

### `PostgresAuditLogger` (production)
- PostgreSQL-backed using `sqlx` (async)
- Append-only: the `log` method must INSERT only, never UPDATE or DELETE
- Create SQL migration strings as constants in the module (do NOT use sqlx::migrate! macro — just store the SQL as a `const &str` and provide a `pub async fn run_migrations(pool: &PgPool)` function)
- Table schema for `audit_events`:
  - `id` UUID PRIMARY KEY
  - `timestamp` TIMESTAMPTZ NOT NULL
  - `event_type` TEXT NOT NULL
  - `action_json` JSONB
  - `guardian_verdict_json` JSONB
  - `permission_tier` TEXT
  - `outcome` JSONB NOT NULL
  - `metadata` JSONB NOT NULL DEFAULT '{}'
- Add indexes: `btree` on `timestamp`, `btree` on `event_type`, composite on `(event_type, timestamp)`
- The `query` method supports filtering by: time range, event type, outcome, tool name (via JSON path on action_json), with limit
- Accept a `LeakDetector` trait object (`Arc<dyn LeakDetector>`) as a constructor dependency — redact secrets in parameters before logging
- Constructor takes a `sqlx::PgPool`

## Tests

### Unit tests (in-module, always run)
- Test `InMemoryAuditLogger`: log events, query them back, verify append-only behavior
- Test serialization/deserialization of `AuditEvent` to/from JSON
- Test query filters on in-memory logger (time range, event type, tool name)
- Test that multiple events are stored in order
- Test with a mock `LeakDetector` that redacts known patterns

### Integration tests (gated behind `DATABASE_URL` env var)
- Mark with `#[ignore]` attribute — only run when `DATABASE_URL` is set
- Test against real PostgreSQL: insert events, query them back
- Test that redaction is applied before storage
- Test query filters return correct subsets
- Test concurrent logging from multiple tasks

## Completion

After implementation and all tests pass:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test -p steward-security
git add -A
git commit -m "feat(security): implement audit logger with in-memory and PostgreSQL backends"
git push -u origin feat/audit-logger
gh pr create --title "feat(security): implement audit logger" --body "## Summary
- Implements AuditLogger trait with two backends: InMemoryAuditLogger and PostgresAuditLogger
- Append-only logging with secret redaction via LeakDetector
- Query support with filters (time range, event type, tool name)
- SQL migration for audit_events table with indexes

## Test plan
- [x] cargo fmt --all
- [x] cargo clippy -- -D warnings
- [x] cargo test -p steward-security (unit tests pass)
- [ ] Integration tests require DATABASE_URL (run with docker-compose)"
```
