Read docs/architecture.md section 5.4 (Memory System with Provenance).
Read crates/steward-types/src/traits.rs for the MemoryStore trait.

Implement the memory store in crates/steward-memory/src/workspace.rs.

Requirements:
- Implement the MemoryStore trait from steward-types
- PostgreSQL-backed using sqlx with the pgvector extension
- Create SQL migrations for the memory_entries table:
  id (UUID PK), content (TEXT), provenance (TEXT enum), trust_score (FLOAT),
  embedding (vector(1536)), created_at (TIMESTAMPTZ), updated_at (TIMESTAMPTZ),
  metadata (JSONB)
- Add indexes: vector index (ivfflat or hnsw) on embedding, GIN index on
  content for full-text search, btree index on created_at and trust_score
- store() inserts a new entry (generate UUID if id is None)
- get() retrieves by ID
- update_trust() updates the trust_score for an entry
- Include a method for bulk retrieval: get_by_provenance(provenance, limit)
- Immutable core memory tier: entries with provenance=UserInstruction and
  trust_score=1.0 cannot be modified except by explicit user commands
  (enforce at the store level — reject update_trust for these entries)
- Store SQL migrations as const strings in the module (do NOT use sqlx::migrate! macro
  since there is no migrations directory). Run migrations in the constructor.

Write tests:
- Integration tests that require DATABASE_URL env var (gate with #[ignore])
- Test store and retrieve round-trip
- Test provenance filtering
- Test trust score updates
- Test immutable core memory protection
- Test that vector embeddings are stored and retrievable
- Also write unit tests that don't require a database where possible

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-memory` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(memory): implement PostgreSQL memory store with pgvector and provenance"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(memory): implement memory store" --body "Implements MemoryStore trait with PostgreSQL + pgvector backing, SQL migrations, provenance filtering, trust scores, and immutable core memory protection." --base main`
