//! Memory workspace implementation.
//!
//! PostgreSQL-backed persistent memory storage:
//! - Store and retrieve memory entries with provenance metadata
//! - Trust score management
//! - Immutable core memory tier protection
//! - Vector embedding storage via pgvector
//!
//! See `docs/architecture.md` section 5.4 for full requirements.

use async_trait::async_trait;
use pgvector::Vector;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};
use tracing::info;
use uuid::Uuid;

use steward_types::actions::{MemoryEntry, MemoryId, MemoryProvenance};
use steward_types::errors::StewardError;
use steward_types::traits::MemoryStore;

// ============================================================
// SQL Migrations (run in constructor, not via sqlx::migrate!)
// ============================================================

const MIGRATION_CREATE_EXTENSION: &str = "CREATE EXTENSION IF NOT EXISTS vector";

const MIGRATION_CREATE_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS memory_entries (\
    id UUID PRIMARY KEY, \
    content TEXT NOT NULL, \
    provenance TEXT NOT NULL, \
    trust_score DOUBLE PRECISION NOT NULL DEFAULT 0.0, \
    embedding vector(1536), \
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb\
)";

const MIGRATION_VECTOR_INDEX: &str = "\
CREATE INDEX IF NOT EXISTS idx_memory_embedding \
ON memory_entries USING hnsw (embedding vector_cosine_ops)";

const MIGRATION_FTS_INDEX: &str = "\
CREATE INDEX IF NOT EXISTS idx_memory_content_fts \
ON memory_entries USING gin (to_tsvector('english', content))";

const MIGRATION_CREATED_AT_INDEX: &str = "\
CREATE INDEX IF NOT EXISTS idx_memory_created_at \
ON memory_entries (created_at)";

const MIGRATION_TRUST_SCORE_INDEX: &str = "\
CREATE INDEX IF NOT EXISTS idx_memory_trust_score \
ON memory_entries (trust_score)";

// ============================================================
// PgMemoryStore
// ============================================================

/// PostgreSQL-backed memory store with pgvector for embeddings.
///
/// Implements the [`MemoryStore`] trait with:
/// - Provenance-tagged storage (UserInstruction, AgentObservation, etc.)
/// - Trust score management with immutable core memory protection
/// - Vector embedding storage via the pgvector extension
/// - Bulk retrieval by provenance via [`get_by_provenance`](Self::get_by_provenance)
pub struct PgMemoryStore {
    pool: PgPool,
}

impl PgMemoryStore {
    /// Create a new memory store, connecting to PostgreSQL at the given URL.
    ///
    /// Runs schema migrations on construction to ensure the table and indexes exist.
    pub async fn new(database_url: &str) -> Result<Self, StewardError> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|e| StewardError::Database(format!("connection failed: {e}")))?;
        Self::from_pool(pool).await
    }

    /// Create a memory store from an existing connection pool.
    ///
    /// Runs schema migrations on construction.
    pub async fn from_pool(pool: PgPool) -> Result<Self, StewardError> {
        let store = Self { pool };
        store.run_migrations().await?;
        Ok(store)
    }

    /// Run all schema migrations.
    async fn run_migrations(&self) -> Result<(), StewardError> {
        let migrations = [
            MIGRATION_CREATE_EXTENSION,
            MIGRATION_CREATE_TABLE,
            MIGRATION_VECTOR_INDEX,
            MIGRATION_FTS_INDEX,
            MIGRATION_CREATED_AT_INDEX,
            MIGRATION_TRUST_SCORE_INDEX,
        ];

        for sql in migrations {
            sqlx::query(sql)
                .execute(&self.pool)
                .await
                .map_err(|e| StewardError::Database(format!("migration failed: {e}")))?;
        }

        info!("memory store migrations applied successfully");
        Ok(())
    }

    /// Retrieve entries filtered by provenance, ordered by newest first.
    ///
    /// Returns up to `limit` entries matching the given provenance type.
    pub async fn get_by_provenance(
        &self,
        provenance: MemoryProvenance,
        limit: i64,
    ) -> Result<Vec<MemoryEntry>, StewardError> {
        let rows = sqlx::query(
            "SELECT id, content, provenance, trust_score, embedding, created_at \
             FROM memory_entries WHERE provenance = $1 \
             ORDER BY created_at DESC LIMIT $2",
        )
        .bind(provenance_to_str(provenance))
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StewardError::Database(e.to_string()))?;

        rows.into_iter().map(row_to_entry).collect()
    }
}

#[async_trait]
impl MemoryStore for PgMemoryStore {
    async fn store(&self, entry: MemoryEntry) -> Result<MemoryId, StewardError> {
        let id = entry.id.unwrap_or_else(Uuid::new_v4);
        let embedding: Option<Vector> = entry.embedding.map(Vector::from);

        sqlx::query(
            "INSERT INTO memory_entries \
             (id, content, provenance, trust_score, embedding, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW())",
        )
        .bind(id)
        .bind(&entry.content)
        .bind(provenance_to_str(entry.provenance))
        .bind(entry.trust_score)
        .bind(embedding.as_ref())
        .bind(entry.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StewardError::Database(format!("store failed: {e}")))?;

        Ok(id)
    }

    async fn get(&self, id: &MemoryId) -> Result<Option<MemoryEntry>, StewardError> {
        let row = sqlx::query(
            "SELECT id, content, provenance, trust_score, embedding, created_at \
             FROM memory_entries WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StewardError::Database(e.to_string()))?;

        row.map(row_to_entry).transpose()
    }

    async fn update_trust(&self, id: &MemoryId, score: f64) -> Result<(), StewardError> {
        // Fetch provenance and current trust to check immutability
        let row = sqlx::query("SELECT provenance, trust_score FROM memory_entries WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StewardError::Database(e.to_string()))?;

        let row = row.ok_or_else(|| StewardError::Memory(format!("entry not found: {id}")))?;

        let provenance: String = row
            .try_get("provenance")
            .map_err(|e| StewardError::Database(e.to_string()))?;
        let current_trust: f64 = row
            .try_get("trust_score")
            .map_err(|e| StewardError::Database(e.to_string()))?;

        // Reject updates to immutable core memories
        if is_immutable_core_memory(&provenance, current_trust) {
            return Err(StewardError::Forbidden(
                "cannot modify immutable core memory \
                 (UserInstruction with trust_score=1.0)"
                    .to_string(),
            ));
        }

        sqlx::query("UPDATE memory_entries SET trust_score = $1, updated_at = NOW() WHERE id = $2")
            .bind(score)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| StewardError::Database(format!("update failed: {e}")))?;

        Ok(())
    }
}

// ============================================================
// Helpers
// ============================================================

/// Check if a memory entry is in the immutable core memory tier.
///
/// Entries with provenance `UserInstruction` and `trust_score == 1.0` are
/// considered immutable and cannot be modified except by explicit user commands.
fn is_immutable_core_memory(provenance: &str, trust_score: f64) -> bool {
    provenance == "UserInstruction" && (trust_score - 1.0).abs() < f64::EPSILON
}

/// Convert a [`MemoryProvenance`] enum to its database string representation.
fn provenance_to_str(p: MemoryProvenance) -> &'static str {
    match p {
        MemoryProvenance::UserInstruction => "UserInstruction",
        MemoryProvenance::AgentObservation => "AgentObservation",
        MemoryProvenance::ExternalContent => "ExternalContent",
        MemoryProvenance::ToolResult => "ToolResult",
    }
}

/// Parse a [`MemoryProvenance`] from its database string representation.
fn str_to_provenance(s: &str) -> Result<MemoryProvenance, StewardError> {
    match s {
        "UserInstruction" => Ok(MemoryProvenance::UserInstruction),
        "AgentObservation" => Ok(MemoryProvenance::AgentObservation),
        "ExternalContent" => Ok(MemoryProvenance::ExternalContent),
        "ToolResult" => Ok(MemoryProvenance::ToolResult),
        other => Err(StewardError::Memory(format!("unknown provenance: {other}"))),
    }
}

/// Convert a PostgreSQL row into a [`MemoryEntry`].
fn row_to_entry(row: PgRow) -> Result<MemoryEntry, StewardError> {
    let map_err = |e: sqlx::Error| StewardError::Database(e.to_string());

    Ok(MemoryEntry {
        id: Some(row.try_get("id").map_err(map_err)?),
        content: row.try_get("content").map_err(map_err)?,
        provenance: str_to_provenance(
            row.try_get::<String, _>("provenance")
                .map_err(map_err)?
                .as_str(),
        )?,
        trust_score: row.try_get("trust_score").map_err(map_err)?,
        created_at: row.try_get("created_at").map_err(map_err)?,
        embedding: row
            .try_get::<Option<Vector>, _>("embedding")
            .map_err(map_err)?
            .map(|v| v.to_vec()),
    })
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // ----------------------------------------------------------
    // Unit tests (no database required)
    // ----------------------------------------------------------

    #[test]
    fn test_provenance_roundtrip() {
        let variants = [
            MemoryProvenance::UserInstruction,
            MemoryProvenance::AgentObservation,
            MemoryProvenance::ExternalContent,
            MemoryProvenance::ToolResult,
        ];
        for v in variants {
            let s = provenance_to_str(v);
            let parsed = str_to_provenance(s).unwrap();
            assert_eq!(v, parsed);
        }
    }

    #[test]
    fn test_str_to_provenance_unknown() {
        let result = str_to_provenance("InvalidProvenance");
        assert!(result.is_err());
    }

    #[test]
    fn test_immutable_core_memory_check() {
        // UserInstruction at 1.0 is immutable
        assert!(is_immutable_core_memory("UserInstruction", 1.0));
        // UserInstruction at less than 1.0 is mutable
        assert!(!is_immutable_core_memory("UserInstruction", 0.8));
        // Other provenances at 1.0 are mutable
        assert!(!is_immutable_core_memory("AgentObservation", 1.0));
        assert!(!is_immutable_core_memory("ExternalContent", 1.0));
        assert!(!is_immutable_core_memory("ToolResult", 1.0));
    }

    #[test]
    fn test_provenance_to_str_values() {
        assert_eq!(
            provenance_to_str(MemoryProvenance::UserInstruction),
            "UserInstruction"
        );
        assert_eq!(
            provenance_to_str(MemoryProvenance::AgentObservation),
            "AgentObservation"
        );
        assert_eq!(
            provenance_to_str(MemoryProvenance::ExternalContent),
            "ExternalContent"
        );
        assert_eq!(
            provenance_to_str(MemoryProvenance::ToolResult),
            "ToolResult"
        );
    }

    // ----------------------------------------------------------
    // Integration tests (require DATABASE_URL env var)
    // ----------------------------------------------------------

    async fn create_store() -> PgMemoryStore {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        PgMemoryStore::new(&url)
            .await
            .expect("failed to create store")
    }

    fn make_entry(provenance: MemoryProvenance, trust: f64) -> MemoryEntry {
        MemoryEntry {
            id: None,
            content: format!("test-{}", Uuid::new_v4()),
            provenance,
            trust_score: trust,
            created_at: Utc::now(),
            embedding: None,
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_store_and_retrieve() {
        let store = create_store().await;
        let entry = make_entry(MemoryProvenance::AgentObservation, 0.7);
        let content = entry.content.clone();

        let id = store.store(entry).await.unwrap();
        let retrieved = store.get(&id).await.unwrap().expect("entry should exist");

        assert_eq!(retrieved.id, Some(id));
        assert_eq!(retrieved.content, content);
        assert_eq!(retrieved.provenance, MemoryProvenance::AgentObservation);
        assert!((retrieved.trust_score - 0.7).abs() < f64::EPSILON);
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_nonexistent() {
        let store = create_store().await;
        let result = store.get(&Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn test_store_with_explicit_id() {
        let store = create_store().await;
        let explicit_id = Uuid::new_v4();
        let mut entry = make_entry(MemoryProvenance::ToolResult, 0.5);
        entry.id = Some(explicit_id);

        let id = store.store(entry).await.unwrap();
        assert_eq!(id, explicit_id);

        let retrieved = store.get(&id).await.unwrap().expect("entry should exist");
        assert_eq!(retrieved.id, Some(explicit_id));
    }

    #[tokio::test]
    #[ignore]
    async fn test_provenance_filtering() {
        let store = create_store().await;

        // Use a unique marker so results are isolated from other test runs
        let marker = Uuid::new_v4().to_string();
        let mut user_entry = make_entry(MemoryProvenance::UserInstruction, 1.0);
        user_entry.content = format!("user-{marker}");
        let mut agent_entry = make_entry(MemoryProvenance::AgentObservation, 0.6);
        agent_entry.content = format!("agent-{marker}");
        let mut ext_entry = make_entry(MemoryProvenance::ExternalContent, 0.3);
        ext_entry.content = format!("external-{marker}");

        store.store(user_entry).await.unwrap();
        store.store(agent_entry).await.unwrap();
        store.store(ext_entry).await.unwrap();

        // Filter by UserInstruction
        let results = store
            .get_by_provenance(MemoryProvenance::UserInstruction, 100)
            .await
            .unwrap();
        assert!(results
            .iter()
            .all(|e| e.provenance == MemoryProvenance::UserInstruction));
        assert!(results
            .iter()
            .any(|e| e.content == format!("user-{marker}")));

        // Filter by AgentObservation
        let results = store
            .get_by_provenance(MemoryProvenance::AgentObservation, 100)
            .await
            .unwrap();
        assert!(results
            .iter()
            .all(|e| e.provenance == MemoryProvenance::AgentObservation));
        assert!(results
            .iter()
            .any(|e| e.content == format!("agent-{marker}")));
    }

    #[tokio::test]
    #[ignore]
    async fn test_trust_score_update() {
        let store = create_store().await;
        let entry = make_entry(MemoryProvenance::AgentObservation, 0.5);

        let id = store.store(entry).await.unwrap();
        store.update_trust(&id, 0.9).await.unwrap();

        let updated = store.get(&id).await.unwrap().expect("entry should exist");
        assert!((updated.trust_score - 0.9).abs() < f64::EPSILON);
    }

    #[tokio::test]
    #[ignore]
    async fn test_immutable_core_memory_protection() {
        let store = create_store().await;
        let entry = make_entry(MemoryProvenance::UserInstruction, 1.0);

        let id = store.store(entry).await.unwrap();

        // Attempting to update trust of immutable core memory should fail
        let result = store.update_trust(&id, 0.5).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            StewardError::Forbidden(msg) => {
                assert!(msg.contains("immutable core memory"));
            }
            other => panic!("expected Forbidden error, got: {other}"),
        }

        // Verify the trust score was not changed
        let entry = store.get(&id).await.unwrap().expect("entry should exist");
        assert!((entry.trust_score - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    #[ignore]
    async fn test_user_instruction_mutable_when_not_max_trust() {
        let store = create_store().await;
        let entry = make_entry(MemoryProvenance::UserInstruction, 0.8);

        let id = store.store(entry).await.unwrap();
        // Should succeed because trust_score != 1.0
        store.update_trust(&id, 0.9).await.unwrap();

        let updated = store.get(&id).await.unwrap().expect("entry should exist");
        assert!((updated.trust_score - 0.9).abs() < f64::EPSILON);
    }

    #[tokio::test]
    #[ignore]
    async fn test_update_trust_nonexistent() {
        let store = create_store().await;
        let result = store.update_trust(&Uuid::new_v4(), 0.5).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn test_vector_embedding_storage() {
        let store = create_store().await;
        let embedding = vec![0.1_f32; 1536];
        let mut entry = make_entry(MemoryProvenance::ToolResult, 0.6);
        entry.embedding = Some(embedding.clone());

        let id = store.store(entry).await.unwrap();
        let retrieved = store.get(&id).await.unwrap().expect("entry should exist");

        let stored = retrieved.embedding.expect("embedding should be stored");
        assert_eq!(stored.len(), 1536);
        // pgvector stores float4, check with reasonable tolerance
        assert!((stored[0] - 0.1).abs() < 1e-6);
        assert!((stored[1535] - 0.1).abs() < 1e-6);
    }

    #[tokio::test]
    #[ignore]
    async fn test_store_without_embedding() {
        let store = create_store().await;
        let entry = make_entry(MemoryProvenance::AgentObservation, 0.5);

        let id = store.store(entry).await.unwrap();
        let retrieved = store.get(&id).await.unwrap().expect("entry should exist");
        assert!(retrieved.embedding.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_by_provenance_respects_limit() {
        let store = create_store().await;
        let marker = Uuid::new_v4().to_string();

        // Store 5 entries with ToolResult provenance
        for i in 0..5 {
            let mut entry = make_entry(MemoryProvenance::ToolResult, 0.5);
            entry.content = format!("limit-test-{marker}-{i}");
            store.store(entry).await.unwrap();
        }

        // Request only 2
        let results = store
            .get_by_provenance(MemoryProvenance::ToolResult, 2)
            .await
            .unwrap();
        assert!(results.len() <= 2);
    }
}
