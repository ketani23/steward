//! Hybrid memory search implementation.
//!
//! Combines PostgreSQL full-text search with pgvector similarity search,
//! fused using Reciprocal Rank Fusion (RRF):
//! - Full-text search via tsvector/tsquery
//! - Vector similarity via pgvector cosine distance
//! - RRF scoring: score = sum(1 / (k + rank_i))
//! - Trust score weighting on combined results
//!
//! See `docs/architecture.md` section 5.4 for full requirements.

// TODO: Implement MemorySearch trait from steward-types
