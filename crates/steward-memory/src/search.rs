//! Hybrid memory search implementation.
//!
//! Combines PostgreSQL full-text search with pgvector similarity search,
//! fused using Reciprocal Rank Fusion (RRF):
//! - Full-text search via tsvector/tsquery with `websearch_to_tsquery`
//! - Vector similarity via pgvector cosine distance
//! - RRF scoring: `score = sum(weight_i / (k + rank_i))`
//! - Trust score weighting on combined results
//!
//! See `docs/architecture.md` section 5.4 for full requirements.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use steward_types::actions::{MemoryEntry, MemoryId, MemoryProvenance, MemorySearchResult};
use steward_types::errors::StewardError;
use steward_types::traits::MemorySearch;

// ============================================================
// SQL Migrations
// ============================================================

/// SQL migrations for the search module.
///
/// Creates indexes needed for hybrid search. The `memories` table itself
/// is created by the workspace module — this only adds search-specific indexes.
pub const SEARCH_MIGRATIONS: &str = "\
CREATE INDEX IF NOT EXISTS idx_memories_fts \
ON memories USING GIN (to_tsvector('english', content));\
";

/// Additional migration for pgvector HNSW index.
///
/// Separated because HNSW indexes require pgvector extension and a populated table.
/// The `IF NOT EXISTS` clause makes this safe to run multiple times.
pub const VECTOR_INDEX_MIGRATION: &str = "\
CREATE INDEX IF NOT EXISTS idx_memories_embedding_hnsw \
ON memories USING hnsw (embedding vector_cosine_ops) \
WITH (m = 16, ef_construction = 64);\
";

// ============================================================
// Configuration
// ============================================================

/// Configuration for hybrid memory search.
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Weight multiplier for FTS contribution in RRF scoring.
    /// Default: 1.0
    pub fts_weight: f64,
    /// Weight multiplier for vector search contribution in RRF scoring.
    /// Default: 1.0
    pub vector_weight: f64,
    /// RRF constant k. Higher values reduce the impact of high rankings.
    /// Default: 60 (standard value from the RRF paper).
    pub rrf_k: usize,
    /// Maximum number of candidates to fetch from each search method
    /// before fusion. Should be >= the expected limit parameter.
    /// Default: 100.
    pub candidate_limit: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            fts_weight: 1.0,
            vector_weight: 1.0,
            rrf_k: 60,
            candidate_limit: 100,
        }
    }
}

// ============================================================
// Embedding Provider
// ============================================================

/// Trait for generating vector embeddings from text queries.
///
/// Implementations provide the embedding model. This module does not
/// implement embedding generation — it only consumes pre-computed vectors.
#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    /// Generate an embedding vector for the given text.
    async fn embed(&self, text: &str) -> Result<Vec<f32>, StewardError>;
}

// ============================================================
// RRF Computation (pure logic, no database)
// ============================================================

/// Intermediate RRF score accumulator for a single candidate.
#[derive(Debug, Clone)]
struct RrfAccumulator {
    /// Accumulated RRF score before trust weighting.
    rrf_score: f64,
    /// Rank from full-text search (1-based), if found.
    fts_rank: Option<usize>,
    /// Rank from vector search (1-based), if found.
    vector_rank: Option<usize>,
}

impl Default for RrfAccumulator {
    fn default() -> Self {
        Self {
            rrf_score: 0.0,
            fts_rank: None,
            vector_rank: None,
        }
    }
}

/// Compute a single RRF contribution: `weight / (k + rank)`.
pub(crate) fn rrf_score_component(k: usize, rank: usize, weight: f64) -> f64 {
    weight / (k as f64 + rank as f64)
}

/// Fuse FTS and vector ranked lists using Reciprocal Rank Fusion.
///
/// Each input is a list of `(MemoryId, 1-based rank)` pairs.
/// Returns a map from MemoryId to accumulated RRF scores.
pub(crate) fn compute_rrf(
    fts_ranked: &[(MemoryId, usize)],
    vector_ranked: &[(MemoryId, usize)],
    k: usize,
    fts_weight: f64,
    vector_weight: f64,
) -> HashMap<MemoryId, (f64, Option<usize>, Option<usize>)> {
    let mut scores: HashMap<MemoryId, RrfAccumulator> = HashMap::new();

    for &(id, rank) in fts_ranked {
        let entry = scores.entry(id).or_default();
        entry.rrf_score += rrf_score_component(k, rank, fts_weight);
        entry.fts_rank = Some(rank);
    }

    for &(id, rank) in vector_ranked {
        let entry = scores.entry(id).or_default();
        entry.rrf_score += rrf_score_component(k, rank, vector_weight);
        entry.vector_rank = Some(rank);
    }

    scores
        .into_iter()
        .map(|(id, acc)| (id, (acc.rrf_score, acc.fts_rank, acc.vector_rank)))
        .collect()
}

// ============================================================
// Helper Functions
// ============================================================

/// Convert a `Vec<f32>` to pgvector text representation: `[0.1,0.2,0.3]`.
fn vec_to_pgvector(v: &[f32]) -> String {
    let inner: String = v
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("[{inner}]")
}

/// Parse pgvector text representation back to `Vec<f32>`.
fn pgvector_to_vec(s: &str) -> Result<Vec<f32>, StewardError> {
    let trimmed = s.trim_start_matches('[').trim_end_matches(']');
    if trimmed.is_empty() {
        return Ok(vec![]);
    }
    trimmed
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<f32>()
                .map_err(|e| StewardError::Memory(format!("failed to parse embedding: {e}")))
        })
        .collect()
}

/// Parse a database string into a `MemoryProvenance` enum.
fn provenance_from_str(s: &str) -> MemoryProvenance {
    match s {
        "user_instruction" => MemoryProvenance::UserInstruction,
        "agent_observation" => MemoryProvenance::AgentObservation,
        "external_content" => MemoryProvenance::ExternalContent,
        "tool_result" => MemoryProvenance::ToolResult,
        other => {
            tracing::warn!(
                provenance = other,
                "unknown provenance value, defaulting to AgentObservation"
            );
            MemoryProvenance::AgentObservation
        }
    }
}

// ============================================================
// Database Row Extraction
// ============================================================

/// Candidate entry extracted from a database query row.
struct SearchCandidate {
    id: Uuid,
    content: String,
    provenance: String,
    trust_score: f64,
    created_at: DateTime<Utc>,
    embedding_text: Option<String>,
}

/// Extract a `SearchCandidate` from a `sqlx::postgres::PgRow`.
fn candidate_from_row(row: &sqlx::postgres::PgRow) -> Result<SearchCandidate, StewardError> {
    Ok(SearchCandidate {
        id: row
            .try_get("id")
            .map_err(|e| StewardError::Database(format!("missing column 'id': {e}")))?,
        content: row
            .try_get("content")
            .map_err(|e| StewardError::Database(format!("missing column 'content': {e}")))?,
        provenance: row
            .try_get("provenance")
            .map_err(|e| StewardError::Database(format!("missing column 'provenance': {e}")))?,
        trust_score: row
            .try_get("trust_score")
            .map_err(|e| StewardError::Database(format!("missing column 'trust_score': {e}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| StewardError::Database(format!("missing column 'created_at': {e}")))?,
        embedding_text: row
            .try_get("embedding_text")
            .map_err(|e| StewardError::Database(format!("missing column 'embedding_text': {e}")))?,
    })
}

/// Convert a `SearchCandidate` into a `MemoryEntry`.
fn candidate_to_entry(c: SearchCandidate) -> Result<MemoryEntry, StewardError> {
    let embedding = c
        .embedding_text
        .as_deref()
        .map(pgvector_to_vec)
        .transpose()?;
    Ok(MemoryEntry {
        id: Some(c.id),
        content: c.content,
        provenance: provenance_from_str(&c.provenance),
        trust_score: c.trust_score,
        created_at: c.created_at,
        embedding,
    })
}

// ============================================================
// HybridMemorySearch
// ============================================================

/// Hybrid full-text + vector memory search with Reciprocal Rank Fusion.
///
/// Combines PostgreSQL full-text search (tsvector/tsquery) with pgvector
/// cosine similarity search. Results are fused using RRF scoring and
/// weighted by trust scores to penalize low-trust memories.
pub struct HybridMemorySearch {
    pool: PgPool,
    config: SearchConfig,
    embedding_provider: Option<Arc<dyn EmbeddingProvider>>,
}

impl HybridMemorySearch {
    /// Create a new hybrid search instance.
    ///
    /// # Arguments
    /// * `pool` - PostgreSQL connection pool
    /// * `config` - Search configuration (weights, k, candidate limit)
    /// * `embedding_provider` - Optional provider for converting query text to vectors.
    ///   If `None`, only full-text search is used.
    pub fn new(
        pool: PgPool,
        config: SearchConfig,
        embedding_provider: Option<Arc<dyn EmbeddingProvider>>,
    ) -> Self {
        Self {
            pool,
            config,
            embedding_provider,
        }
    }

    /// Run search-specific database migrations (indexes).
    ///
    /// Should be called after the workspace module has created the memories table.
    pub async fn run_migrations(&self) -> Result<(), StewardError> {
        sqlx::query(SEARCH_MIGRATIONS)
            .execute(&self.pool)
            .await
            .map_err(|e| StewardError::Database(format!("FTS index migration failed: {e}")))?;

        sqlx::query(VECTOR_INDEX_MIGRATION)
            .execute(&self.pool)
            .await
            .map_err(|e| StewardError::Database(format!("vector index migration failed: {e}")))?;

        tracing::info!("search indexes created successfully");
        Ok(())
    }

    /// Perform full-text search using `websearch_to_tsquery`.
    ///
    /// Returns candidates ranked by `ts_rank` score.
    async fn fts_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<SearchCandidate>, StewardError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                content,
                provenance,
                trust_score,
                created_at,
                embedding::text as embedding_text
            FROM memories
            WHERE to_tsvector('english', content) @@ websearch_to_tsquery('english', $1)
            ORDER BY ts_rank(to_tsvector('english', content), websearch_to_tsquery('english', $1)) DESC
            LIMIT $2
            "#,
        )
        .bind(query)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StewardError::Database(format!("FTS search failed: {e}")))?;

        rows.iter().map(candidate_from_row).collect()
    }

    /// Perform vector similarity search using cosine distance.
    ///
    /// Returns candidates ranked by cosine similarity (highest first).
    async fn vector_search(
        &self,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<SearchCandidate>, StewardError> {
        let embedding_str = vec_to_pgvector(embedding);

        let rows = sqlx::query(
            r#"
            SELECT
                id,
                content,
                provenance,
                trust_score,
                created_at,
                embedding::text as embedding_text
            FROM memories
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> $1::vector
            LIMIT $2
            "#,
        )
        .bind(&embedding_str)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StewardError::Database(format!("vector search failed: {e}")))?;

        rows.iter().map(candidate_from_row).collect()
    }

    /// Search with a pre-computed embedding vector.
    ///
    /// Use this when you already have the query embedding and don't need
    /// the embedding provider. If `query_embedding` is `None`, only FTS is used.
    pub async fn search_with_embedding(
        &self,
        query: &str,
        query_embedding: Option<&[f32]>,
        limit: usize,
    ) -> Result<Vec<MemorySearchResult>, StewardError> {
        let effective_limit = limit.min(self.config.candidate_limit);
        let candidate_limit = self.config.candidate_limit;

        // Run FTS search
        let fts_rows = self.fts_search(query, candidate_limit).await?;

        // Run vector search if embedding is available
        let vector_rows = if let Some(emb) = query_embedding {
            self.vector_search(emb, candidate_limit).await?
        } else {
            Vec::new()
        };

        // Build ranked lists (1-based ranks)
        let fts_ranked: Vec<(MemoryId, usize)> = fts_rows
            .iter()
            .enumerate()
            .map(|(i, c)| (c.id, i + 1))
            .collect();

        let vector_ranked: Vec<(MemoryId, usize)> = vector_rows
            .iter()
            .enumerate()
            .map(|(i, c)| (c.id, i + 1))
            .collect();

        // Compute RRF scores
        let rrf_scores = compute_rrf(
            &fts_ranked,
            &vector_ranked,
            self.config.rrf_k,
            self.config.fts_weight,
            self.config.vector_weight,
        );

        // Build a lookup of entries by ID, converting candidates to MemoryEntry
        let mut entries: HashMap<MemoryId, MemoryEntry> = HashMap::new();

        for candidate in fts_rows {
            let id = candidate.id;
            if let std::collections::hash_map::Entry::Vacant(e) = entries.entry(id) {
                e.insert(candidate_to_entry(candidate)?);
            }
        }

        for candidate in vector_rows {
            let id = candidate.id;
            if let std::collections::hash_map::Entry::Vacant(e) = entries.entry(id) {
                e.insert(candidate_to_entry(candidate)?);
            }
        }

        // Assemble results with trust-weighted scores
        let mut results: Vec<MemorySearchResult> = rrf_scores
            .into_iter()
            .filter_map(|(id, (rrf_score, fts_rank, vector_rank))| {
                entries.remove(&id).map(|entry| {
                    let trust_weighted = rrf_score * entry.trust_score;
                    MemorySearchResult {
                        entry,
                        score: trust_weighted,
                        fts_rank,
                        vector_rank,
                    }
                })
            })
            .collect();

        // Sort by trust-weighted score descending
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        results.truncate(effective_limit);
        Ok(results)
    }
}

#[async_trait]
impl MemorySearch for HybridMemorySearch {
    async fn search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MemorySearchResult>, StewardError> {
        let embedding = if let Some(provider) = &self.embedding_provider {
            match provider.embed(query).await {
                Ok(emb) => Some(emb),
                Err(e) => {
                    tracing::warn!(error = %e, "embedding provider failed, falling back to FTS-only");
                    None
                }
            }
        } else {
            None
        };

        self.search_with_embedding(query, embedding.as_deref(), limit)
            .await
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --------------------------------------------------------
    // Unit tests for RRF computation (no database required)
    // --------------------------------------------------------

    #[test]
    fn test_rrf_score_component_basic() {
        // score = weight / (k + rank)
        let score = rrf_score_component(60, 1, 1.0);
        let expected = 1.0 / 61.0;
        assert!((score - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rrf_score_component_with_weight() {
        let score = rrf_score_component(60, 1, 2.0);
        let expected = 2.0 / 61.0;
        assert!((score - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rrf_score_component_high_rank() {
        // Rank 100 with k=60 should yield a small score
        let score = rrf_score_component(60, 100, 1.0);
        let expected = 1.0 / 160.0;
        assert!((score - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_rrf_fts_only() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let fts = vec![(id1, 1), (id2, 2)];
        let vector: Vec<(MemoryId, usize)> = vec![];

        let scores = compute_rrf(&fts, &vector, 60, 1.0, 1.0);

        assert_eq!(scores.len(), 2);
        let (score1, fts_rank1, vec_rank1) = scores[&id1];
        assert!((score1 - 1.0 / 61.0).abs() < f64::EPSILON);
        assert_eq!(fts_rank1, Some(1));
        assert_eq!(vec_rank1, None);

        let (score2, fts_rank2, vec_rank2) = scores[&id2];
        assert!((score2 - 1.0 / 62.0).abs() < f64::EPSILON);
        assert_eq!(fts_rank2, Some(2));
        assert_eq!(vec_rank2, None);
    }

    #[test]
    fn test_compute_rrf_vector_only() {
        let id1 = Uuid::new_v4();
        let fts: Vec<(MemoryId, usize)> = vec![];
        let vector = vec![(id1, 3)];

        let scores = compute_rrf(&fts, &vector, 60, 1.0, 1.0);

        assert_eq!(scores.len(), 1);
        let (score, fts_rank, vec_rank) = scores[&id1];
        assert!((score - 1.0 / 63.0).abs() < f64::EPSILON);
        assert_eq!(fts_rank, None);
        assert_eq!(vec_rank, Some(3));
    }

    #[test]
    fn test_compute_rrf_both_methods() {
        let id1 = Uuid::new_v4();
        let fts = vec![(id1, 1)];
        let vector = vec![(id1, 2)];

        let scores = compute_rrf(&fts, &vector, 60, 1.0, 1.0);

        assert_eq!(scores.len(), 1);
        let (score, fts_rank, vec_rank) = scores[&id1];
        let expected = 1.0 / 61.0 + 1.0 / 62.0;
        assert!((score - expected).abs() < f64::EPSILON);
        assert_eq!(fts_rank, Some(1));
        assert_eq!(vec_rank, Some(2));
    }

    #[test]
    fn test_compute_rrf_mixed_overlap() {
        // id1 appears in both, id2 only in FTS, id3 only in vector
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();

        let fts = vec![(id1, 1), (id2, 2)];
        let vector = vec![(id3, 1), (id1, 2)];

        let scores = compute_rrf(&fts, &vector, 60, 1.0, 1.0);

        assert_eq!(scores.len(), 3);

        // id1: FTS rank 1 + vector rank 2
        let (score1, _, _) = scores[&id1];
        let expected1 = 1.0 / 61.0 + 1.0 / 62.0;
        assert!((score1 - expected1).abs() < f64::EPSILON);

        // id2: FTS rank 2 only
        let (score2, fts2, vec2) = scores[&id2];
        assert!((score2 - 1.0 / 62.0).abs() < f64::EPSILON);
        assert_eq!(fts2, Some(2));
        assert_eq!(vec2, None);

        // id3: vector rank 1 only
        let (score3, fts3, vec3) = scores[&id3];
        assert!((score3 - 1.0 / 61.0).abs() < f64::EPSILON);
        assert_eq!(fts3, None);
        assert_eq!(vec3, Some(1));
    }

    #[test]
    fn test_compute_rrf_with_different_weights() {
        let id1 = Uuid::new_v4();
        let fts = vec![(id1, 1)];
        let vector = vec![(id1, 1)];

        // FTS weight 2.0, vector weight 0.5
        let scores = compute_rrf(&fts, &vector, 60, 2.0, 0.5);

        let (score, _, _) = scores[&id1];
        let expected = 2.0 / 61.0 + 0.5 / 61.0;
        assert!((score - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_rrf_with_different_k() {
        let id1 = Uuid::new_v4();
        let fts = vec![(id1, 1)];
        let vector: Vec<(MemoryId, usize)> = vec![];

        let scores_k60 = compute_rrf(&fts, &vector, 60, 1.0, 1.0);
        let scores_k10 = compute_rrf(&fts, &vector, 10, 1.0, 1.0);

        let (s60, _, _) = scores_k60[&id1];
        let (s10, _, _) = scores_k10[&id1];

        // Lower k gives higher scores (more sensitive to ranking)
        assert!(s10 > s60);
        assert!((s60 - 1.0 / 61.0).abs() < f64::EPSILON);
        assert!((s10 - 1.0 / 11.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compute_rrf_empty_inputs() {
        let fts: Vec<(MemoryId, usize)> = vec![];
        let vector: Vec<(MemoryId, usize)> = vec![];

        let scores = compute_rrf(&fts, &vector, 60, 1.0, 1.0);
        assert!(scores.is_empty());
    }

    #[test]
    fn test_trust_score_weighting() {
        // Simulate trust weighting: rrf_score * trust_score
        let rrf_score: f64 = 1.0 / 61.0;
        let high_trust: f64 = 1.0;
        let low_trust: f64 = 0.3;

        let high_trust_final = rrf_score * high_trust;
        let low_trust_final = rrf_score * low_trust;

        assert!(high_trust_final > low_trust_final);
        assert!((high_trust_final - rrf_score).abs() < f64::EPSILON);
        assert!((low_trust_final - rrf_score * 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rrf_ranking_order() {
        // Verify that items appearing in both methods rank higher
        let id_both = Uuid::new_v4();
        let id_fts_only = Uuid::new_v4();
        let id_vec_only = Uuid::new_v4();

        let fts = vec![(id_both, 2), (id_fts_only, 1)];
        let vector = vec![(id_both, 2), (id_vec_only, 1)];

        let scores = compute_rrf(&fts, &vector, 60, 1.0, 1.0);

        let (score_both, _, _) = scores[&id_both];
        let (score_fts, _, _) = scores[&id_fts_only];
        let (score_vec, _, _) = scores[&id_vec_only];

        // Item in both methods should score higher even at rank 2
        // than items at rank 1 in only one method
        assert!(score_both > score_fts);
        assert!(score_both > score_vec);
    }

    // --------------------------------------------------------
    // Helper function tests
    // --------------------------------------------------------

    #[test]
    fn test_vec_to_pgvector() {
        let v = vec![0.1, 0.2, 0.3];
        let result = vec_to_pgvector(&v);
        assert_eq!(result, "[0.1,0.2,0.3]");
    }

    #[test]
    fn test_vec_to_pgvector_empty() {
        let v: Vec<f32> = vec![];
        let result = vec_to_pgvector(&v);
        assert_eq!(result, "[]");
    }

    #[test]
    fn test_pgvector_to_vec() {
        let result = pgvector_to_vec("[0.1,0.2,0.3]").unwrap();
        assert_eq!(result, vec![0.1, 0.2, 0.3]);
    }

    #[test]
    fn test_pgvector_to_vec_empty() {
        let result = pgvector_to_vec("[]").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_pgvector_to_vec_invalid() {
        let result = pgvector_to_vec("[abc]");
        assert!(result.is_err());
    }

    #[test]
    fn test_provenance_from_str_all_variants() {
        assert_eq!(
            provenance_from_str("user_instruction"),
            MemoryProvenance::UserInstruction
        );
        assert_eq!(
            provenance_from_str("agent_observation"),
            MemoryProvenance::AgentObservation
        );
        assert_eq!(
            provenance_from_str("external_content"),
            MemoryProvenance::ExternalContent
        );
        assert_eq!(
            provenance_from_str("tool_result"),
            MemoryProvenance::ToolResult
        );
    }

    #[test]
    fn test_provenance_from_str_unknown_defaults() {
        let result = provenance_from_str("unknown_value");
        assert_eq!(result, MemoryProvenance::AgentObservation);
    }

    // --------------------------------------------------------
    // Integration tests (require PostgreSQL + pgvector)
    // --------------------------------------------------------

    /// Helper to get a database pool from DATABASE_URL env var.
    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    /// SQL to create the memories table for tests.
    /// In production, this is handled by workspace.rs.
    const TEST_TABLE_SQL: &str = "\
CREATE EXTENSION IF NOT EXISTS vector;\
\n\
CREATE TABLE IF NOT EXISTS memories (\
    id UUID PRIMARY KEY,\
    content TEXT NOT NULL,\
    provenance TEXT NOT NULL DEFAULT 'agent_observation',\
    trust_score DOUBLE PRECISION NOT NULL DEFAULT 0.5,\
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\
    embedding vector(3)\
);\
";

    /// Insert a test memory entry.
    async fn insert_test_memory(
        pool: &PgPool,
        id: Uuid,
        content: &str,
        provenance: &str,
        trust_score: f64,
        embedding: Option<&[f32]>,
    ) {
        let embedding_str = embedding.map(vec_to_pgvector);

        sqlx::query(
            r#"
            INSERT INTO memories (id, content, provenance, trust_score, embedding)
            VALUES ($1, $2, $3, $4, $5::vector)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(id)
        .bind(content)
        .bind(provenance)
        .bind(trust_score)
        .bind(embedding_str)
        .execute(pool)
        .await
        .unwrap();
    }

    /// Clean up the test table.
    async fn cleanup(pool: &PgPool) {
        sqlx::query("DROP TABLE IF EXISTS memories")
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_fts_search_returns_relevant_results() {
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };
        cleanup(&pool).await;
        sqlx::query(TEST_TABLE_SQL).execute(&pool).await.unwrap();

        let search = HybridMemorySearch::new(pool.clone(), SearchConfig::default(), None);
        search.run_migrations().await.unwrap();

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();

        insert_test_memory(
            &pool,
            id1,
            "The Rust programming language is fast and safe",
            "user_instruction",
            1.0,
            None,
        )
        .await;
        insert_test_memory(
            &pool,
            id2,
            "Python is great for data science and machine learning",
            "agent_observation",
            0.8,
            None,
        )
        .await;
        insert_test_memory(
            &pool,
            id3,
            "Rust provides memory safety without garbage collection",
            "tool_result",
            0.9,
            None,
        )
        .await;

        let results = search.search("Rust programming", 10).await.unwrap();

        assert!(!results.is_empty());
        // Both Rust-related entries should appear
        let result_ids: Vec<Uuid> = results.iter().filter_map(|r| r.entry.id).collect();
        assert!(result_ids.contains(&id1));
        assert!(result_ids.contains(&id3));
        // All results should have FTS rank
        for result in &results {
            assert!(result.fts_rank.is_some());
        }

        cleanup(&pool).await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_vector_search_returns_similar_entries() {
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };
        cleanup(&pool).await;
        sqlx::query(TEST_TABLE_SQL).execute(&pool).await.unwrap();

        let search = HybridMemorySearch::new(pool.clone(), SearchConfig::default(), None);
        search.run_migrations().await.unwrap();

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();

        // Embeddings: id1 and id3 are similar (close vectors), id2 is different
        insert_test_memory(
            &pool,
            id1,
            "entry one",
            "user_instruction",
            1.0,
            Some(&[0.9, 0.1, 0.0]),
        )
        .await;
        insert_test_memory(
            &pool,
            id2,
            "entry two",
            "agent_observation",
            0.8,
            Some(&[0.0, 0.0, 1.0]),
        )
        .await;
        insert_test_memory(
            &pool,
            id3,
            "entry three",
            "tool_result",
            0.9,
            Some(&[0.85, 0.15, 0.05]),
        )
        .await;

        // Query with embedding close to id1 and id3
        let query_embedding = vec![0.9, 0.1, 0.0];
        let results = search
            .search_with_embedding("entry", Some(&query_embedding), 10)
            .await
            .unwrap();

        assert!(!results.is_empty());
        // id1 should be the closest match (or very close to it)
        let first_id = results[0].entry.id.unwrap();
        assert!(first_id == id1 || first_id == id3);
        // All should have vector rank since we passed an embedding
        for result in &results {
            assert!(result.vector_rank.is_some());
        }

        cleanup(&pool).await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_rrf_fusion_ranks_combined_results() {
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };
        cleanup(&pool).await;
        sqlx::query(TEST_TABLE_SQL).execute(&pool).await.unwrap();

        let search = HybridMemorySearch::new(pool.clone(), SearchConfig::default(), None);
        search.run_migrations().await.unwrap();

        let id_both = Uuid::new_v4();
        let id_fts = Uuid::new_v4();
        let id_vec = Uuid::new_v4();

        // id_both: relevant text AND close embedding
        insert_test_memory(
            &pool,
            id_both,
            "Rust memory safety is important for systems programming",
            "user_instruction",
            1.0,
            Some(&[0.9, 0.1, 0.0]),
        )
        .await;
        // id_fts: relevant text but distant embedding
        insert_test_memory(
            &pool,
            id_fts,
            "Rust programming offers zero-cost abstractions",
            "user_instruction",
            1.0,
            Some(&[0.0, 0.0, 1.0]),
        )
        .await;
        // id_vec: irrelevant text but close embedding
        insert_test_memory(
            &pool,
            id_vec,
            "The weather today is sunny and warm",
            "agent_observation",
            1.0,
            Some(&[0.85, 0.15, 0.0]),
        )
        .await;

        let query_embedding = vec![0.9, 0.1, 0.0];
        let results = search
            .search_with_embedding("Rust programming", Some(&query_embedding), 10)
            .await
            .unwrap();

        assert!(!results.is_empty());

        // id_both should rank highest because it appears in both FTS and vector results
        let first = &results[0];
        assert_eq!(first.entry.id.unwrap(), id_both);
        assert!(first.fts_rank.is_some());
        assert!(first.vector_rank.is_some());

        cleanup(&pool).await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_trust_score_weighting_penalizes_low_trust() {
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };
        cleanup(&pool).await;
        sqlx::query(TEST_TABLE_SQL).execute(&pool).await.unwrap();

        let search = HybridMemorySearch::new(pool.clone(), SearchConfig::default(), None);
        search.run_migrations().await.unwrap();

        let id_trusted = Uuid::new_v4();
        let id_untrusted = Uuid::new_v4();

        // Same content, different trust scores
        insert_test_memory(
            &pool,
            id_trusted,
            "Rust compiler catches bugs at compile time",
            "user_instruction",
            1.0,
            None,
        )
        .await;
        insert_test_memory(
            &pool,
            id_untrusted,
            "Rust compiler catches bugs at compile time early",
            "external_content",
            0.1,
            None,
        )
        .await;

        let results = search.search("Rust compiler bugs", 10).await.unwrap();

        assert!(results.len() >= 2);

        // Find both entries in results
        let trusted_result = results.iter().find(|r| r.entry.id == Some(id_trusted));
        let untrusted_result = results.iter().find(|r| r.entry.id == Some(id_untrusted));

        assert!(trusted_result.is_some());
        assert!(untrusted_result.is_some());

        // Trusted entry should have a higher score
        assert!(trusted_result.unwrap().score > untrusted_result.unwrap().score);

        cleanup(&pool).await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_empty_results() {
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };
        cleanup(&pool).await;
        sqlx::query(TEST_TABLE_SQL).execute(&pool).await.unwrap();

        let search = HybridMemorySearch::new(pool.clone(), SearchConfig::default(), None);
        search.run_migrations().await.unwrap();

        // No data inserted — search should return empty
        let results = search.search("nonexistent query", 10).await.unwrap();
        assert!(results.is_empty());

        cleanup(&pool).await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_search_with_limit() {
        let pool = match test_pool().await {
            Some(p) => p,
            None => return,
        };
        cleanup(&pool).await;
        sqlx::query(TEST_TABLE_SQL).execute(&pool).await.unwrap();

        let search = HybridMemorySearch::new(pool.clone(), SearchConfig::default(), None);
        search.run_migrations().await.unwrap();

        // Insert several entries with matching content
        for i in 0..5 {
            let id = Uuid::new_v4();
            let content = format!("Rust programming concept number {i} is about safety");
            insert_test_memory(&pool, id, &content, "user_instruction", 1.0, None).await;
        }

        // Limit to 2 results
        let results = search.search("Rust programming safety", 2).await.unwrap();
        assert!(results.len() <= 2);

        // Limit to 10 (should return all 5)
        let results = search.search("Rust programming safety", 10).await.unwrap();
        assert_eq!(results.len(), 5);

        cleanup(&pool).await;
    }
}
