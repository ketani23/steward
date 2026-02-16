//! Memory workspace implementation.
//!
//! PostgreSQL-backed persistent memory storage:
//! - Store and retrieve memory entries with provenance metadata
//! - Trust score management
//! - Immutable core memory tier protection
//! - Vector embedding storage via pgvector
//!
//! See `docs/architecture.md` section 5.4 for full requirements.

// TODO: Implement MemoryStore trait from steward-types
