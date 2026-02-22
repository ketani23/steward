Read docs/architecture.md section 5.4 (Memory System with Provenance).
Read crates/steward-types/src/traits.rs for the MemorySearch trait.

Implement hybrid search in crates/steward-memory/src/search.rs.

Requirements:
- Implement the MemorySearch trait from steward-types
- Hybrid search combining PostgreSQL full-text search (tsvector/tsquery) with
  pgvector similarity search, fused using Reciprocal Rank Fusion (RRF)
- RRF formula: score = sum(1 / (k + rank_i)) where k=60 (standard constant)
  and rank_i is the rank from each retrieval method
- Full-text search: use ts_rank with websearch_to_tsquery for natural language queries
- Vector search: cosine similarity against pgvector embeddings
  (assumes embedding is pre-computed and passed as parameter — do NOT implement
  embedding generation here, just accept Vec<f32>)
- Results include: memory entry, combined RRF score, individual FTS rank,
  individual vector rank
- Trust score weighting: multiply RRF score by trust_score to penalize
  low-trust memories in ranking
- Configurable: FTS weight vs vector weight, k constant, max results
- Store SQL migrations as const strings in the module (do NOT use sqlx::migrate! macro
  since there is no migrations directory). The workspace.rs module handles table creation;
  this module should create any additional indexes or views it needs.

Write tests:
- Integration tests requiring DATABASE_URL (gate with #[ignore])
- Test FTS search returns relevant results
- Test vector search returns similar entries
- Test RRF fusion ranks combined results correctly
- Test trust score weighting penalizes low-trust entries
- Test empty results
- Test with limit parameter
- Also write unit tests for the RRF calculation logic that don't require a database

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-memory` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(memory): implement hybrid FTS + vector search with RRF fusion"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(memory): implement hybrid memory search" --body "Implements MemorySearch trait with hybrid FTS + pgvector search, Reciprocal Rank Fusion scoring, trust score weighting, and configurable search parameters." --base main`
