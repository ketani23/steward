# Memory System — Phase 1 Implementation Plan

> Prepared for handoff to an implementation session.
> Branch: `feat/memory-system`
> Source document: `MEMORY_REQUIREMENTS.md`

---

## 1. Current State Assessment

### What Exists

#### Two Separate Memory Tables (the core problem)

The codebase has diverged into two unrelated table implementations:

**`memory_entries`** — created by `PgMemoryStore` in `workspace.rs`:
```sql
memory_entries (
  id UUID PRIMARY KEY,
  content TEXT NOT NULL,
  provenance TEXT NOT NULL,         -- PascalCase: "UserInstruction", "AgentObservation"
  trust_score DOUBLE PRECISION DEFAULT 0.0,
  embedding vector(1536),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  metadata JSONB DEFAULT '{}'
)
```

**`memories`** — created by `HybridMemorySearch` in `search.rs`:
```sql
memories (
  id UUID PRIMARY KEY,
  content TEXT NOT NULL,
  provenance TEXT NOT NULL DEFAULT 'agent_observation',  -- snake_case
  trust_score DOUBLE PRECISION DEFAULT 0.5,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  embedding vector(1536)
)
```

These tables are COMPLETELY DISCONNECTED. They have incompatible provenance string conventions (PascalCase vs snake_case), different default trust scores, and different column sets.

#### What Is Wired Up Today

- **`HybridMemorySearch`** is created in `steward-server/src/main.rs` at section `// ── 7. Memory`
- Its `run_migrations()` is called → the `memories` table is created on startup ✓
- `HybridMemorySearch` is passed as `memory: Arc<dyn MemorySearch>` to `AgentDeps`
- The agent's `retrieve_context()` calls `self.memory.search(query, 5)` and injects results as `[Context N]` in the user prompt — **the read path is wired up**
- **`PgMemoryStore`** is NEVER instantiated in the server. It is dead code for production purposes
- `embedding_provider: None` → only FTS search works, no vector search

#### The Root Bug (the "memories table WARN")

The `memories` table is created, but **nothing writes to it**. Every call to `retrieve_context()` returns empty results because:
1. `PgMemoryStore` writes to `memory_entries` (wrong table, never called anyway)
2. `HybridMemorySearch` only reads from `memories` — no write path exists
3. Result: memory search always returns empty, pre-turn injection is a no-op

#### What Is Missing

| Requirement | Status |
|------------|--------|
| `scope` column in `memories` table | ✗ Missing |
| Write path to `memories` table | ✗ Missing |
| Embedding provider implementation | ✗ Missing (provider=None) |
| Extraction pipeline (post-turn LLM call) | ✗ Missing |
| Deduplication before store | ✗ Missing |
| `memory.search` tool (registered) | ✗ Missing |
| `memory.store` tool | ✗ Missing |
| `MemoryStore` in `AgentDeps` | ✗ Missing |
| Extraction trigger in agent loop | ✗ Missing |

#### What Works Correctly

- RRF fusion algorithm (`compute_rrf`) — well tested, correct
- FTS search query against `memories` table — correct SQL
- Vector search query against `memories` table — correct SQL
- Trust-score weighting in search results — correct
- Pre-turn injection format (`[Context N] {content}`) — correct
- `PgMemoryStore` trust immutability logic — correct (but uses wrong table)
- All unit tests pass — no DB required tests are green

---

## 2. Phase 1 Scope (Detailed)

Phase 1 is strictly: **make memory work end-to-end**. No personality scoping, no update semantics, no reflection jobs.

### 2.1 Fix the Table — Add Scope Column

Modify `MEMORIES_TABLE_MIGRATION` in `search.rs` to include Phase 1 columns. Add `ALTER TABLE IF NOT EXISTS` migration steps so existing tables are upgraded.

New `memories` schema after Phase 1:
```sql
memories (
  id UUID PRIMARY KEY,
  content TEXT NOT NULL,
  provenance TEXT NOT NULL DEFAULT 'agent_observation',  -- keep existing column
  scope TEXT NOT NULL DEFAULT 'shared',                   -- NEW Phase 1
  source_session TEXT,                                    -- NEW Phase 1 (session ID)
  source_channel TEXT,                                    -- NEW Phase 1 (telegram/api/etc)
  trust_score DOUBLE PRECISION NOT NULL DEFAULT 0.5,
  confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,       -- NEW Phase 1
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  embedding vector(1536)
)
```

**Why keep `provenance` not rename to `source_type`**: The existing `search.rs` already uses `provenance` in every SQL query. Renaming mid-migration creates a window where old code breaks. A future Phase 2 migration can rename once all read/write paths are updated. Document this as technical debt.

### 2.2 Implement MemoryStore on HybridMemorySearch

`HybridMemorySearch` already has the `PgPool` and `EmbeddingProvider`. Implement `MemoryStore` directly on it so it can both write and read from `memories`. This unifies storage and search in one struct.

The `store` method on `HybridMemorySearch`:
1. Accept `MemoryEntry`
2. If no embedding in entry, auto-generate via `self.embedding_provider`
3. INSERT into `memories` table (not `memory_entries`)
4. Return the UUID

`HybridMemorySearch` becomes the canonical memory backend for Phase 1.

### 2.3 Add scope to MemoryEntry

Add optional scope/session/channel fields to `MemoryEntry` in `steward-types/src/actions.rs`. All new fields are `Option<T>` to avoid breaking existing constructors that don't set them.

### 2.4 Implement EmbeddingProvider with OpenAI Backend

Create `crates/steward-memory/src/embedding.rs`:
- `OpenAiEmbeddingProvider` implementing the `EmbeddingProvider` trait from `search.rs`
- Calls `POST https://api.openai.com/v1/embeddings` with `text-embedding-3-small`
- Output: 1536-dimensional f32 vector
- Config: `api_key: String` (from `OPENAI_API_KEY` env var)
- Graceful fallback: if OpenAI key absent, server uses `None` embedding provider (FTS-only)

**Note on vector dimensions**: The requirements say `VECTOR(768)` but the existing code uses `vector(1536)` and `text-embedding-3-small` outputs 1536. **Use 1536** — the requirements document contains a mistake here.

### 2.5 Build the Extraction Pipeline

Create `crates/steward-memory/src/extraction.rs`:
- `FactExtractor` struct holds `Arc<dyn LlmProvider>`, `Arc<dyn MemoryStore>`, `Arc<dyn MemorySearch>`
- `extract_from_turn(user_msg, agent_response, session_id, channel) -> Result<usize, StewardError>`
  - Returns count of new facts stored (0 if no new facts)
- LLM call uses Haiku-class model with a structured extraction prompt
- Parses JSON array of facts: `[{content, scope_suggestion, confidence}]`
- Deduplicates: calls `search(content, 3)` → if top score > 0.9, skip
- Stores non-duplicate facts with `source_type=agent_observation`, trust=0.6

Wire into agent loop in `steward-core/src/agent.rs`:
- Add `extractor: Option<Arc<FactExtractor>>` to `AgentDeps` and `Agent`
- After `self.conversation_store.store_turn(...)`, fire off async extraction:
  ```rust
  if let Some(extractor) = self.extractor.clone() {
      let user_msg = sanitized.text.clone();
      let response = final_response.clone();
      tokio::spawn(async move {
          if let Err(e) = extractor.extract_from_turn(&user_msg, &response, &session_key, "").await {
              tracing::warn!(error = %e, "Fact extraction failed");
          }
      });
  }
  ```

### 2.6 Add memory.search Tool

Create `crates/steward-tools/src/built_in/memory_search.rs`:
- `MemorySearchTool` holds `Arc<dyn MemorySearch>`
- Tool name: `memory.search`
- Permission tier: `AutoExecute` (read-only, safe)
- Parameters: `query: String` (required), `limit: Option<usize>` (default 5, max 20), `scope: Option<String>` (default "shared")
- Returns JSON: `{results: [{content, score, provenance, created_at, scope}]}`

### 2.7 Add memory.store Tool

Create `crates/steward-tools/src/built_in/memory_store.rs`:
- `MemoryStoreTool` holds `Arc<dyn MemoryStore>`
- Tool name: `memory.store`
- Permission tier: `LogAndExecute`
- Parameters: `content: String` (required), `scope: Option<String>` (default "shared"), `tags: Option<Vec<String>>`
- Returns JSON: `{id: "<uuid>", stored: true}`

### 2.8 Update permissions.yaml

`memory.store` needs to be added to `log_and_execute`. `memory.search` is already in `auto_execute`.

### 2.9 Register Tools in Server

In `steward-server/src/main.rs`, after other tool registrations:
```rust
tools.register_built_in(
    MemorySearchTool::tool_definition(),
    Arc::new(MemorySearchTool::new(memory.clone())),
).await?;

tools.register_built_in(
    MemoryStoreTool::tool_definition(),
    Arc::new(MemoryStoreTool::new(memory_store.clone())),
).await?;
```

The `memory` variable is `Arc<HybridMemorySearch>` (not `Arc<dyn MemorySearch>`) at the point of construction, so it can be used for both roles. Store it as both `Arc<dyn MemorySearch>` and `Arc<dyn MemoryStore>` by cloning before casting.

### 2.10 Pre-turn Memory Injection (Already Partially Done)

The agent's `retrieve_context()` and `build_user_prompt()` already implement pre-turn injection correctly:
- Searches 5 memories on the user's message text
- Injects as `Relevant context:\n[Context 1] ...\n\nUser message:\n...`

**No changes needed to the injection logic** — it just starts working once data flows into the `memories` table.

**One small improvement**: Make the context injection reference the memory score so the agent can use it:
```
[Context 1 (score: 0.82)] {fact}
```
This is optional for Phase 1.

---

## 3. File-by-File Change Plan

### 3.1 `crates/steward-types/src/actions.rs`

**What changes**: Extend `MemoryEntry` with optional Phase 1 fields.

```rust
pub struct MemoryEntry {
    pub id: Option<MemoryId>,
    pub content: String,
    pub provenance: MemoryProvenance,
    pub trust_score: f64,
    pub created_at: DateTime<Utc>,
    pub embedding: Option<Vec<f32>>,
    // Phase 1 additions — all Option to preserve existing constructors
    pub scope: Option<String>,           // 'shared' or personality_id; None = 'shared'
    pub source_session: Option<String>,  // session key that produced this fact
    pub source_channel: Option<String>,  // "telegram", "api", "slack"
    pub confidence: Option<f64>,         // extraction confidence (1.0 if user-authored)
}
```

**Why here**: `MemoryEntry` is the shared type crossing the `MemoryStore`/`MemorySearch` boundary. The server, agent, and tool crates all use it. It belongs in `steward-types`.

**Impact on existing code**: Every `MemoryEntry { ... }` struct literal will fail to compile until new fields are added. Files affected:
- `steward-memory/src/workspace.rs` — `make_entry()` test helper
- `steward-memory/src/search.rs` — `candidate_to_entry()` function
- All integration tests that construct `MemoryEntry` directly

All of these get `scope: None, source_session: None, source_channel: None, confidence: None` added.

---

### 3.2 `crates/steward-memory/src/search.rs`

**What changes**:

1. **Update `MEMORIES_TABLE_MIGRATION`** — add Phase 1 columns:
```rust
const MEMORIES_TABLE_MIGRATION: &str = "\
CREATE TABLE IF NOT EXISTS memories (\
    id UUID PRIMARY KEY, \
    content TEXT NOT NULL, \
    provenance TEXT NOT NULL DEFAULT 'agent_observation', \
    scope TEXT NOT NULL DEFAULT 'shared', \
    source_session TEXT, \
    source_channel TEXT, \
    trust_score DOUBLE PRECISION NOT NULL DEFAULT 0.5, \
    confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0, \
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
    embedding vector(1536)\
)";
```

2. **Add ALTER TABLE migration steps** in `run_migrations()` for existing tables:
```rust
const SCOPE_MIGRATION: &str = "ALTER TABLE memories ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'shared'";
const SESSION_MIGRATION: &str = "ALTER TABLE memories ADD COLUMN IF NOT EXISTS source_session TEXT";
const CHANNEL_MIGRATION: &str = "ALTER TABLE memories ADD COLUMN IF NOT EXISTS source_channel TEXT";
const CONFIDENCE_MIGRATION: &str = "ALTER TABLE memories ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0";
```

Run these in `run_migrations()` after the table creation.

3. **Implement `MemoryStore` on `HybridMemorySearch`**:

```rust
#[async_trait]
impl MemoryStore for HybridMemorySearch {
    async fn store(&self, entry: MemoryEntry) -> Result<MemoryId, StewardError> {
        let id = entry.id.unwrap_or_else(Uuid::new_v4);
        let scope = entry.scope.as_deref().unwrap_or("shared");
        let provenance = provenance_to_str(entry.provenance);

        // Auto-generate embedding if provider is available and entry lacks one
        let embedding_str = if let Some(emb) = &entry.embedding {
            Some(vec_to_pgvector(emb))
        } else if let Some(provider) = &self.embedding_provider {
            match provider.embed(&entry.content).await {
                Ok(emb) => Some(vec_to_pgvector(&emb)),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to generate embedding for new memory");
                    None
                }
            }
        } else {
            None
        };

        sqlx::query(
            "INSERT INTO memories (id, content, provenance, scope, source_session, \
             source_channel, trust_score, confidence, created_at, embedding) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::vector)"
        )
        .bind(id)
        .bind(&entry.content)
        .bind(provenance)
        .bind(scope)
        .bind(entry.source_session.as_deref())
        .bind(entry.source_channel.as_deref())
        .bind(entry.trust_score)
        .bind(entry.confidence.unwrap_or(1.0))
        .bind(entry.created_at)
        .bind(embedding_str.as_deref())
        .execute(&self.pool)
        .await
        .map_err(|e| StewardError::Database(format!("memory store failed: {e}")))?;

        Ok(id)
    }

    async fn get(&self, id: &MemoryId) -> Result<Option<MemoryEntry>, StewardError> {
        // SELECT from memories table by id
    }

    async fn update_trust(&self, id: &MemoryId, score: f64) -> Result<(), StewardError> {
        // UPDATE memories SET trust_score = $1 WHERE id = $2
        // Note: no immutability check needed for Phase 1 (Phase 2 adds that)
    }
}
```

4. **Add `provenance_to_str` helper** (currently only `provenance_from_str` exists in search.rs — the PascalCase variant is in workspace.rs; add the snake_case version here):
```rust
fn provenance_to_str(p: MemoryProvenance) -> &'static str {
    match p {
        MemoryProvenance::UserInstruction => "user_instruction",
        MemoryProvenance::AgentObservation => "agent_observation",
        MemoryProvenance::ExternalContent => "external_content",
        MemoryProvenance::ToolResult => "tool_result",
    }
}
```

5. **Update `SearchCandidate` and `candidate_to_entry`** to include `scope` and `confidence` columns (they need to be read from FTS/vector result rows).

6. **Update FTS/vector SQL queries** to SELECT the new columns (`scope`, `source_session`, `source_channel`, `confidence`).

7. **Add scope-aware search** (new public method, used by `memory.search` tool):
```rust
pub async fn search_scoped(
    &self,
    query: &str,
    limit: usize,
    scope: &str,
) -> Result<Vec<MemorySearchResult>, StewardError>
```
SQL adds `WHERE scope IN ('shared', $scope_param)` to both FTS and vector queries. For Phase 1 with no personalities, the caller always passes `"shared"`, which returns only shared memories.

---

### 3.3 `crates/steward-memory/src/embedding.rs` — NEW FILE

```rust
//! OpenAI embedding provider for steward-memory.

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use steward_types::errors::StewardError;
use crate::search::EmbeddingProvider;

/// OpenAI text-embedding-3-small provider (1536 dimensions).
pub struct OpenAiEmbeddingProvider {
    client: Client,
    api_key: String,
    model: String,
}

#[derive(Serialize)]
struct EmbedRequest<'a> {
    model: &'a str,
    input: &'a str,
}

#[derive(Deserialize)]
struct EmbedResponse {
    data: Vec<EmbedData>,
}

#[derive(Deserialize)]
struct EmbedData {
    embedding: Vec<f32>,
}

impl OpenAiEmbeddingProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model: "text-embedding-3-small".to_string(),
        }
    }

    pub fn from_env() -> Option<Self> {
        std::env::var("OPENAI_API_KEY").ok().map(Self::new)
    }
}

#[async_trait]
impl EmbeddingProvider for OpenAiEmbeddingProvider {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, StewardError> {
        let resp = self.client
            .post("https://api.openai.com/v1/embeddings")
            .bearer_auth(&self.api_key)
            .json(&EmbedRequest { model: &self.model, input: text })
            .send()
            .await
            .map_err(|e| StewardError::LlmProvider(format!("embedding request failed: {e}")))?
            .error_for_status()
            .map_err(|e| StewardError::LlmProvider(format!("embedding API error: {e}")))?
            .json::<EmbedResponse>()
            .await
            .map_err(|e| StewardError::LlmProvider(format!("embedding response parse failed: {e}")))?;

        resp.data.into_iter().next()
            .map(|d| d.embedding)
            .ok_or_else(|| StewardError::LlmProvider("empty embedding response".to_string()))
    }
}
```

---

### 3.4 `crates/steward-memory/src/extraction.rs` — NEW FILE

```rust
//! Post-turn fact extraction pipeline.
//!
//! After each agent turn, calls a lightweight LLM to extract factual
//! claims from the conversation and stores them in memory with deduplication.

use std::sync::Arc;
use serde::Deserialize;
use steward_types::actions::{MemoryEntry, MemoryProvenance, CompletionRequest, ChatMessage, ChatRole};
use steward_types::errors::StewardError;
use steward_types::traits::{LlmProvider, MemoryStore, MemorySearch};

/// Configuration for the extraction pipeline.
pub struct ExtractionConfig {
    /// LLM model to use for extraction (should be a cheap/fast model).
    pub model: String,
    /// Similarity threshold above which a new fact is considered a duplicate.
    /// Default: 0.9
    pub dedup_threshold: f64,
    /// Maximum facts to extract per turn. Prevents unbounded extraction.
    pub max_facts_per_turn: usize,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            model: "claude-haiku-4-5-20251001".to_string(),
            dedup_threshold: 0.9,
            max_facts_per_turn: 10,
        }
    }
}

/// A fact extracted from a conversation turn.
#[derive(Debug, Deserialize)]
struct ExtractedFact {
    content: String,
    scope_suggestion: Option<String>,
    confidence: Option<f64>,
}

/// Post-turn extraction pipeline.
pub struct FactExtractor {
    llm: Arc<dyn LlmProvider>,
    store: Arc<dyn MemoryStore>,
    search: Arc<dyn MemorySearch>,
    config: ExtractionConfig,
}

impl FactExtractor {
    pub fn new(
        llm: Arc<dyn LlmProvider>,
        store: Arc<dyn MemoryStore>,
        search: Arc<dyn MemorySearch>,
        config: ExtractionConfig,
    ) -> Self {
        Self { llm, store, search, config }
    }

    /// Extract facts from a conversation turn and store non-duplicates.
    ///
    /// Returns the count of new facts stored. Returns 0 (not an error) if
    /// no new facts found or if the LLM returns empty array.
    pub async fn extract_from_turn(
        &self,
        user_message: &str,
        agent_response: &str,
        session_id: &str,
        channel: &str,
    ) -> Result<usize, StewardError> {
        let prompt = build_extraction_prompt(user_message, agent_response);

        let request = CompletionRequest {
            system: EXTRACTION_SYSTEM_PROMPT.to_string(),
            messages: vec![ChatMessage {
                role: ChatRole::User,
                content: prompt,
            }],
            model: self.config.model.clone(),
            max_tokens: 1024,
            temperature: Some(0.0),  // deterministic extraction
        };

        let response = self.llm.complete(request).await
            .map_err(|e| StewardError::Memory(format!("extraction LLM failed: {e}")))?;

        // Parse the JSON array
        let facts: Vec<ExtractedFact> = match parse_extraction_response(&response.content) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse extraction response, skipping");
                return Ok(0);
            }
        };

        let mut stored_count = 0;

        for fact in facts.into_iter().take(self.config.max_facts_per_turn) {
            if fact.content.trim().is_empty() {
                continue;
            }

            // Deduplication check
            if self.is_duplicate(&fact.content).await {
                tracing::debug!(content = %fact.content, "Skipping duplicate fact");
                continue;
            }

            let entry = MemoryEntry {
                id: None,
                content: fact.content,
                provenance: MemoryProvenance::AgentObservation,
                trust_score: 0.6,
                created_at: chrono::Utc::now(),
                embedding: None,
                scope: Some(fact.scope_suggestion.unwrap_or_else(|| "shared".to_string())),
                source_session: Some(session_id.to_string()),
                source_channel: Some(channel.to_string()),
                confidence: Some(fact.confidence.unwrap_or(0.8)),
            };

            match self.store.store(entry).await {
                Ok(_) => stored_count += 1,
                Err(e) => tracing::warn!(error = %e, "Failed to store extracted fact"),
            }
        }

        tracing::debug!(stored = stored_count, "Extraction complete");
        Ok(stored_count)
    }

    /// Check if a fact already exists (similarity > threshold).
    async fn is_duplicate(&self, content: &str) -> bool {
        match self.search.search(content, 3).await {
            Ok(results) => {
                results.first()
                    .map(|r| r.score > self.config.dedup_threshold)
                    .unwrap_or(false)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Dedup search failed, assuming not duplicate");
                false
            }
        }
    }
}

const EXTRACTION_SYSTEM_PROMPT: &str = "\
You extract factual claims from conversations that are worth remembering.
Return a JSON array of facts. Each fact must be a complete, self-contained sentence.
If no new facts are present, return an empty array [].
Do not extract opinions, questions, or transient information.
Only extract durable facts: user preferences, project decisions, technical facts, user identity.

Response format: [{\"content\": \"...\", \"scope_suggestion\": \"shared\", \"confidence\": 0.9}]";

fn build_extraction_prompt(user_message: &str, agent_response: &str) -> String {
    format!(
        "Conversation turn:\nUser: {user_message}\n\nAgent: {agent_response}\n\nExtract facts:",
    )
}

fn parse_extraction_response(content: &str) -> Result<Vec<ExtractedFact>, StewardError> {
    // Find JSON array in response (LLMs sometimes wrap in prose)
    let start = content.find('[').ok_or_else(|| StewardError::Memory("no JSON array in response".to_string()))?;
    let end = content.rfind(']').ok_or_else(|| StewardError::Memory("unclosed JSON array".to_string()))?;
    let json_str = &content[start..=end];

    serde_json::from_str(json_str)
        .map_err(|e| StewardError::Memory(format!("JSON parse failed: {e}")))
}
```

---

### 3.5 `crates/steward-memory/src/lib.rs`

Add new modules:
```rust
pub mod embedding;
pub mod extraction;
pub mod integrity;
pub mod provenance;
pub mod search;
pub mod workspace;
```

---

### 3.6 `crates/steward-memory/Cargo.toml`

Add `reqwest` for the OpenAI embedding HTTP call:
```toml
reqwest.workspace = true
```

---

### 3.7 `crates/steward-tools/src/built_in/memory_search.rs` — NEW FILE

```rust
use std::sync::Arc;
use async_trait::async_trait;
use serde::Deserialize;
use steward_types::actions::{PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;
use steward_types::traits::MemorySearch;
use crate::registry::BuiltInHandler;

pub struct MemorySearchTool {
    memory: Arc<dyn MemorySearch>,
}

impl MemorySearchTool {
    pub fn new(memory: Arc<dyn MemorySearch>) -> Self {
        Self { memory }
    }

    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: "memory.search".to_string(),
            description: "Search persistent memory for relevant facts. Returns facts ranked by relevance and trust.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search query"},
                    "limit": {"type": "integer", "description": "Max results (default 5, max 20)"},
                    "scope": {"type": "string", "description": "Memory scope to search (default 'shared')"}
                },
                "required": ["query"]
            }),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::AutoExecute,
        }
    }
}

#[derive(Deserialize)]
struct Params {
    query: String,
    limit: Option<usize>,
    scope: Option<String>,
}

#[async_trait]
impl BuiltInHandler for MemorySearchTool {
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        let params: Params = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid memory.search parameters: {e}")))?;

        let limit = params.limit.unwrap_or(5).min(20);
        let results = self.memory.search(&params.query, limit).await?;

        let formatted: Vec<serde_json::Value> = results.iter().map(|r| {
            serde_json::json!({
                "content": r.entry.content,
                "score": r.score,
                "provenance": format!("{:?}", r.entry.provenance),
                "created_at": r.entry.created_at.to_rfc3339(),
                "scope": r.entry.scope.as_deref().unwrap_or("shared"),
            })
        }).collect();

        Ok(ToolResult {
            success: true,
            output: serde_json::json!({"results": formatted, "count": formatted.len()}),
            error: None,
        })
    }
}
```

---

### 3.8 `crates/steward-tools/src/built_in/memory_store.rs` — NEW FILE

```rust
use std::sync::Arc;
use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use steward_types::actions::{MemoryEntry, MemoryProvenance, PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;
use steward_types::traits::MemoryStore;
use crate::registry::BuiltInHandler;

pub struct MemoryStoreTool {
    store: Arc<dyn MemoryStore>,
}

impl MemoryStoreTool {
    pub fn new(store: Arc<dyn MemoryStore>) -> Self {
        Self { store }
    }

    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: "memory.store".to_string(),
            description: "Explicitly store a fact in persistent memory. Use when you want to remember something specific that automatic extraction might miss.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "The fact to remember"},
                    "scope": {"type": "string", "description": "Memory scope (default 'shared')"},
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional tags for organization"
                    }
                },
                "required": ["content"]
            }),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::LogAndExecute,
        }
    }
}

#[derive(Deserialize)]
struct Params {
    content: String,
    scope: Option<String>,
    #[allow(dead_code)]
    tags: Option<Vec<String>>,  // stored in Phase 2
}

#[async_trait]
impl BuiltInHandler for MemoryStoreTool {
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        let params: Params = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid memory.store parameters: {e}")))?;

        if params.content.trim().is_empty() {
            return Err(StewardError::Tool("content cannot be empty".to_string()));
        }

        let entry = MemoryEntry {
            id: None,
            content: params.content,
            provenance: MemoryProvenance::AgentObservation,
            trust_score: 0.6,
            created_at: Utc::now(),
            embedding: None,
            scope: Some(params.scope.unwrap_or_else(|| "shared".to_string())),
            source_session: None,
            source_channel: None,
            confidence: Some(1.0),  // explicitly stored = high confidence
        };

        let id = self.store.store(entry).await?;

        Ok(ToolResult {
            success: true,
            output: serde_json::json!({"id": id.to_string(), "stored": true}),
            error: None,
        })
    }
}
```

---

### 3.9 `crates/steward-tools/src/built_in/mod.rs`

Add two new modules:
```rust
pub mod memory_search;
pub mod memory_store;
```

---

### 3.10 `crates/steward-core/src/agent.rs`

**Changes**:

1. Add `FactExtractor` import from `steward_memory::extraction`
   (requires adding `steward-memory` to `steward-core/Cargo.toml`)

2. Add to `AgentDeps`:
```rust
pub struct AgentDeps {
    // ... existing fields ...
    pub memory_store: Arc<dyn MemoryStore>,
    pub extractor: Option<Arc<steward_memory::extraction::FactExtractor>>,
}
```

3. Add to `Agent`:
```rust
pub struct Agent {
    // ... existing fields ...
    memory_store: Arc<dyn MemoryStore>,
    extractor: Option<Arc<steward_memory::extraction::FactExtractor>>,
}
```

4. Update `Agent::new()` to accept the new deps.

5. In `handle_message()`, after `self.conversation_store.store_turn(...)` (around line 339), add:
```rust
// Step 9: Post-turn fact extraction (async, non-blocking)
if let Some(extractor) = self.extractor.clone() {
    let user_msg = sanitized.text.clone();
    let agent_resp = final_response.clone();
    let sess = session_key.clone();
    let ch = format!("{:?}", message.channel);
    tokio::spawn(async move {
        if let Err(e) = extractor.extract_from_turn(&user_msg, &agent_resp, &sess, &ch).await {
            tracing::warn!(error = %e, "Post-turn fact extraction failed");
        }
    });
}
```

**Why `steward-core` depends on `steward-memory`**: The `FactExtractor` type is defined in `steward-memory`. The dependency direction is acceptable: `steward-core` is already the "orchestrator" crate that depends on security, tools, and now memory. Verify this doesn't create a circular dependency — `steward-memory` only depends on `steward-types`, so no cycle.

---

### 3.11 `crates/steward-core/Cargo.toml`

Add:
```toml
steward-memory.workspace = true
```

---

### 3.12 `crates/steward-server/src/main.rs`

**Section `// ── 7. Memory`** — replace current block with:

```rust
// ── 7. Memory (requires DB) ─────────────────────────────────
let (memory_arc, memory_store_arc, extractor) = if let Some(ref pool) = db_pool {
    // Build embedding provider if OPENAI_API_KEY is set
    let embedding_provider: Option<Arc<dyn EmbeddingProvider>> =
        OpenAiEmbeddingProvider::from_env().map(|p| Arc::new(p) as Arc<dyn EmbeddingProvider>);

    if embedding_provider.is_none() {
        warn!("OPENAI_API_KEY not set — vector search disabled, using FTS only");
    }

    let search = Arc::new(HybridMemorySearch::new(
        pool.clone(),
        SearchConfig::default(),
        embedding_provider,
    ));

    search.run_migrations().await
        .map_err(|e| format!("Memory migration failed: {e}"))?;
    info!("Memory table and indexes ready (with scope column)");

    // FactExtractor uses a Haiku-class LLM for cheap extraction
    let haiku_llm: Arc<dyn LlmProvider> = Arc::new(AnthropicProvider::new(
        config.anthropic_api_key.clone(),
        "claude-haiku-4-5-20251001".to_string(),
    ));
    let extractor = Arc::new(FactExtractor::new(
        haiku_llm,
        search.clone() as Arc<dyn MemoryStore>,
        search.clone() as Arc<dyn MemorySearch>,
        ExtractionConfig::default(),
    ));

    (
        search.clone() as Arc<dyn MemorySearch>,
        search.clone() as Arc<dyn MemoryStore>,
        Some(extractor),
    )
} else {
    warn!("No DATABASE_URL — memory disabled");
    (
        Arc::new(NullMemorySearch) as Arc<dyn MemorySearch>,
        Arc::new(NullMemoryStore) as Arc<dyn MemoryStore>,
        None,
    )
};
```

Add after tool registry setup:
```rust
// Memory tools
tools.register_built_in(
    MemorySearchTool::tool_definition(),
    Arc::new(MemorySearchTool::new(memory_arc.clone())),
).await?;
tools.register_built_in(
    MemoryStoreTool::tool_definition(),
    Arc::new(MemoryStoreTool::new(memory_store_arc.clone())),
).await?;
```

Update `AgentDeps` construction:
```rust
let agent_deps = AgentDeps {
    llm,
    guardian,
    permissions,
    tools,
    egress,
    ingress,
    audit: audit.clone(),
    memory: memory_arc,
    memory_store: memory_store_arc,
    channel: channel.clone(),
    conversation_store: Arc::new(ConversationStore::new()),
    extractor,
};
```

Add a `NullMemoryStore` fallback near `NullMemorySearch`:
```rust
struct NullMemoryStore;
#[async_trait]
impl MemoryStore for NullMemoryStore {
    async fn store(&self, entry: MemoryEntry) -> Result<MemoryId, StewardError> {
        Ok(entry.id.unwrap_or_else(Uuid::new_v4))
    }
    async fn get(&self, _id: &MemoryId) -> Result<Option<MemoryEntry>, StewardError> {
        Ok(None)
    }
    async fn update_trust(&self, _id: &MemoryId, _score: f64) -> Result<(), StewardError> {
        Ok(())
    }
}
```

**New imports needed**:
```rust
use steward_memory::embedding::OpenAiEmbeddingProvider;
use steward_memory::extraction::{ExtractionConfig, FactExtractor};
use steward_memory::search::{EmbeddingProvider, HybridMemorySearch, SearchConfig};
use steward_tools::built_in::memory_search::MemorySearchTool;
use steward_tools::built_in::memory_store::MemoryStoreTool;
use steward_types::traits::{MemoryStore};
```

---

### 3.13 `config/permissions.yaml`

Add `memory.store` to `log_and_execute`:
```yaml
log_and_execute:
  actions:
    - reminder.create
    - note.create
    - message.draft
    - file.read
    - file.list
    - web.search
    - web.fetch
    - memory.store      # NEW: explicit fact storage by agent (audited)
    - shell.exec.readonly
  constraints:
    rate_limit: 30/minute
```

(`memory.search` is already in `auto_execute` — no change needed there.)

---

## 4. Data Flow Diagrams

### 4.1 Extraction Flow (Post-Turn, Async)

```
InboundMessage arrives
    │
    ▼
Agent::handle_message()
    │
    ├── Step 1: ingress sanitize
    ├── Step 2: retrieve_context (memory search — returns results now that data exists)
    ├── Steps 3-7: LLM call, tool execution, response generation
    ├── Step 8: egress filter
    ├── Step 8b: conversation_store.store_turn()
    │
    └── Step 9: tokio::spawn(async {
              FactExtractor::extract_from_turn(
                  user_message, agent_response, session_key, channel
              )
                  │
                  ▼
              LLM call (claude-haiku) with extraction prompt
                  │
                  ▼
              Parse JSON: [{content, scope_suggestion, confidence}]
                  │
                  ▼
              For each fact:
                  ├── memory_search.search(fact.content, 3)
                  ├── if top_score > 0.9 → SKIP (duplicate)
                  └── else → memory_store.store(MemoryEntry{...})
                                  │
                                  ▼
                              INSERT INTO memories (id, content, provenance='agent_observation',
                                  scope='shared', source_session=..., trust_score=0.6,
                                  confidence=0.8, embedding=<from OpenAI>)
          })
    │
    ▼
Return final_response to user (extraction happens in background)
```

### 4.2 Recall Flow (Pre-Turn Injection)

```
InboundMessage("how do we deploy steward?")
    │
    ▼
Agent::handle_message()
    │
    ▼
Step 2: retrieve_context(sanitized.text)
    │
    ▼
HybridMemorySearch::search("how do we deploy steward?", 5)
    │
    ├── FTS: SELECT ... WHERE to_tsvector(@@ websearch_to_tsquery
    │         ORDER BY ts_rank DESC LIMIT 100
    │
    ├── Vector: SELECT ... ORDER BY embedding <=> $query_embedding LIMIT 100
    │           (requires OPENAI_API_KEY for embedding generation)
    │
    ├── RRF fusion: score = sum(weight / (60 + rank))
    │
    └── Trust weighting: final_score = rrf_score * trust_score
    │
    ▼
Vec<MemorySearchResult> — top 5 results
    │
    ▼
build_user_prompt():
    "Relevant context:
    [Context 1] Steward is deployed via Docker Compose on port 8080
    [Context 2] The DATABASE_URL is set in .env file
    ...

    User message:
    how do we deploy steward?"
    │
    ▼
LLM receives context-enriched prompt
```

### 4.3 Tool-Triggered Memory Flow

```
User: "Remember that we decided to use gRPC for the agent-to-agent protocol"
    │
    ▼
Agent decides to call memory.store({
    content: "Project decided to use gRPC for agent-to-agent protocol",
    scope: "shared"
})
    │
    ▼
Guardian review → Permission check (LogAndExecute) → Execute
    │
    ▼
MemoryStoreTool::execute()
    │
    ▼
HybridMemorySearch::store(MemoryEntry{
    content: "Project decided to use gRPC for agent-to-agent protocol",
    provenance: AgentObservation,
    trust_score: 0.6,
    scope: "shared",
    confidence: 1.0,
    embedding: <OpenAI generates this>,
    ...
})
    │
    ▼
INSERT INTO memories (...)
    │
    ▼
Future searches for "gRPC" or "agent protocol" will return this fact
```

---

## 5. Migration Plan

### SQL Migrations Run at Startup

All migrations are in `HybridMemorySearch::run_migrations()`. They are idempotent (`IF NOT EXISTS`).

**Migration 1** (existing): `CREATE EXTENSION IF NOT EXISTS vector`

**Migration 2** (existing, extended): `CREATE TABLE IF NOT EXISTS memories (...)` — now includes `scope`, `source_session`, `source_channel`, `confidence` columns in the CREATE statement for fresh installs.

**Migration 3** (new, for existing tables):
```sql
ALTER TABLE memories ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'shared';
ALTER TABLE memories ADD COLUMN IF NOT EXISTS source_session TEXT;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS source_channel TEXT;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0;
```

**Migration 4** (existing): `CREATE INDEX IF NOT EXISTS idx_memories_fts ...`

**Migration 5** (existing): `CREATE INDEX IF NOT EXISTS idx_memories_embedding_hnsw ...`

**Migration 6** (new): `CREATE INDEX IF NOT EXISTS idx_memories_scope ON memories (scope)` — for scope filtering performance.

### `memory_entries` Table

No migration is needed. `memory_entries` continues to exist but is not used by the server. Add a code comment in `workspace.rs` marking it as deprecated for Phase 1. A future Phase 2 PR can either:
- Drop `memory_entries` if no data migration is needed
- Migrate data to `memories` and drop

### Backward Compatibility

- All migrations use `IF NOT EXISTS` — safe to run multiple times
- New `MemoryEntry` fields are `Option<T>` — existing test code compiles with `..., scope: None, ...`
- `NullMemoryStore` and `NullMemorySearch` ensure the server runs without a DB
- FTS-only mode still works if `OPENAI_API_KEY` is absent

---

## 6. Testing Strategy

### 6.1 Unit Tests (No Database Required)

**In `search.rs`** (extend existing test module):
- `test_provenance_to_str_lowercase()` — verify new `provenance_to_str` returns snake_case
- `test_store_entry_roundtrip()` — mock pool (or use `#[ignore]` for integration)
- `test_dedup_threshold_logic()` — test dedup score comparison logic in isolation

**In `extraction.rs`** (new test module):
- `test_parse_extraction_response_valid()` — valid JSON array → `Vec<ExtractedFact>`
- `test_parse_extraction_response_empty()` — `"[]"` → empty vec
- `test_parse_extraction_response_embedded_json()` — JSON buried in prose
- `test_parse_extraction_response_invalid()` — malformed JSON → `Err`
- `test_build_extraction_prompt()` — prompt contains user/agent turn content

**In `memory_search.rs` tool** (new test module):
- `test_tool_definition_name_and_tier()` — name="memory.search", tier=AutoExecute
- `test_execute_formats_results()` — mock MemorySearch returning results, verify JSON shape
- `test_execute_limits_to_20()` — caller passes limit=100, capped at 20
- `test_execute_missing_query_param()` — returns error

**In `memory_store.rs` tool** (new test module):
- `test_tool_definition_name_and_tier()` — name="memory.store", tier=LogAndExecute
- `test_execute_stores_entry()` — mock MemoryStore, verify store was called
- `test_execute_empty_content_rejected()` — empty content returns error
- `test_execute_returns_uuid()` — verify JSON has `id` field

### 6.2 Integration Tests (Require `DATABASE_URL`)

All marked `#[ignore]`.

**In `search.rs`** (extend existing):
- `test_store_and_search_roundtrip()` — store a fact, search for it, verify found
- `test_scope_filtering()` — store with scope='dev', search returns nothing unless scope includes 'dev'
- `test_duplicate_detection()` — store fact, search for it (should have score near 1.0)

**In `extraction.rs`** (new integration tests):
- `test_extraction_stores_fact()` — mock LLM returning one fact, verify it appears in search
- `test_extraction_skips_duplicate()` — pre-store a fact, run extraction with same fact, verify count=0 stored
- `test_extraction_handles_empty_response()` — LLM returns `[]`, verify no error, count=0

**In `embedding.rs`** (gated on `OPENAI_API_KEY`):
- `test_embed_returns_1536_dims()` — real API call, verify vector length

### 6.3 Coverage Goals

Per CLAUDE.md: >80% on security-critical modules. Memory isn't security-critical in the same way, but:
- `extraction.rs`: aim for 100% of unit-testable logic (parse, dedup threshold, prompt building)
- `embedding.rs`: unit test mocked HTTP, integration test real API
- `search.rs`: existing tests cover RRF; new tests cover store path and scope filtering

---

## 7. PR Strategy

**Recommendation: Two PRs in sequence.**

### PR 1: "fix(memory): unify table schema, add write path, scope column"

**Scope**:
- Modify `steward-types/src/actions.rs` — extend `MemoryEntry`
- Modify `steward-memory/src/search.rs` — add scope migrations, add `MemoryStore` impl, add `provenance_to_str`
- Create `steward-memory/src/embedding.rs` — `OpenAiEmbeddingProvider`
- Modify `steward-memory/src/lib.rs` — add embedding module
- Modify `steward-memory/Cargo.toml` — add reqwest
- All unit + integration tests for the above

**Why this first**: This is the schema fix and the write path. Everything in PR 2 depends on being able to write to `memories`. This PR is independently reviewable: "the memory table now works correctly end-to-end for read and write."

**PR 1 acceptance criteria**:
- `HybridMemorySearch` implements both `MemoryStore` and `MemorySearch`
- `memories` table has `scope` column after `run_migrations()`
- `store()` + `search()` roundtrip test passes
- OpenAI provider works (with API key)

### PR 2: "feat(memory): extraction pipeline, tools, server wiring"

**Depends on**: PR 1 merged

**Scope**:
- Create `steward-memory/src/extraction.rs` — `FactExtractor`
- Create `steward-tools/src/built_in/memory_search.rs`
- Create `steward-tools/src/built_in/memory_store.rs`
- Modify `steward-tools/src/built_in/mod.rs`
- Modify `steward-core/src/agent.rs` — add extractor to AgentDeps, trigger post-turn
- Modify `steward-core/Cargo.toml` — add steward-memory dep
- Modify `steward-server/src/main.rs` — wire everything up
- Modify `config/permissions.yaml` — add memory.store
- All tests

**PR 2 acceptance criteria**:
- Agent turns trigger async extraction (verifiable via logs)
- `memory.search` tool registered and callable
- `memory.store` tool registered and callable
- End-to-end test: tell agent a fact, ask about it later, memory is injected

---

## 8. Risk Assessment

### High Risk

**R1: Circular dependency `steward-core` → `steward-memory`**
- `steward-core/Cargo.toml` currently does NOT depend on `steward-memory`
- Adding this dependency creates: `steward-server` → `steward-core` → `steward-memory` → `steward-types`
- This chain is fine. No cycle exists.
- **Mitigation**: Verify with `cargo build -p steward-core` after adding dep.

**R2: `MemoryEntry` struct literal breaks compile**
- Every place that constructs `MemoryEntry { ... }` with struct literal syntax will fail to compile after adding new fields (Rust requires all fields).
- Files affected: `workspace.rs` (tests), `search.rs` (candidate_to_entry), `main.rs` (MockMemory tests), potentially integration test crate.
- **Mitigation**: Search exhaustively with `grep -r "MemoryEntry {" --include="*.rs"` before committing PR 1. Update all occurrences.

### Medium Risk

**R3: Provenance case mismatch**
- `workspace.rs` uses PascalCase ("UserInstruction"), `search.rs` uses snake_case ("user_instruction")
- Any code that mixes both will silently write wrong values that fail to roundtrip.
- **Mitigation**: The `memories` table exclusively uses snake_case (from `search.rs`). `memory_entries` uses PascalCase (from `workspace.rs`). Since `memory_entries` is deprecated, no mixing occurs. Add a test explicitly verifying the `provenance_to_str` in search.rs returns snake_case.

**R4: Extraction fires on every turn, including tool results**
- The extraction is triggered after EVERY `handle_message()` call, including those where the agent is doing tool work and hasn't produced a meaningful human-facing response.
- Extracting from a tool-execution response like "I fetched the URL, here's the content..." could flood memory with noise.
- **Mitigation**: The extraction prompt instructs the LLM to return `[]` for non-fact content. The Haiku model reliably returns empty array for non-memorable turns. Add a length check: skip extraction if `agent_response.len() < 50` (trivially short responses).

**R5: Deduplication score threshold**
- The 0.9 similarity threshold for deduplication is a guess. With only FTS (no embeddings), RRF scores are much lower than 0.9 for any result, so deduplication will never trigger in FTS-only mode.
- **Mitigation**: The deduplication check compares `trust_weighted RRF score` (not raw similarity). At launch, with no OpenAI key, scores are very low, so dedup never fires — this means some duplicates will accumulate. This is acceptable for Phase 1. In Phase 2, when embeddings are available, raw cosine similarity should be used for dedup instead of the trust-weighted RRF score. Document this as a known limitation.

**R6: OpenAI API key required for vector search**
- Without `OPENAI_API_KEY`, the system falls back to FTS-only. This is documented and handled gracefully. But the CI/CD environment may not have the key.
- **Mitigation**: All integration tests that test vector search must be gated with `#[ignore]` AND an explicit env var check for `OPENAI_API_KEY`. Unit tests mock the provider.

### Low Risk

**R7: Async extraction task panics**
- `tokio::spawn` doesn't propagate panics to the main task. A panic in extraction would be silently lost.
- **Mitigation**: Ensure `extract_from_turn` never panics — use `?` throughout, not `unwrap`. The outer `if let Err(e) = ...` catches errors and logs them.

**R8: `ALTER TABLE ADD COLUMN IF NOT EXISTS` PostgreSQL version**
- `IF NOT EXISTS` for `ADD COLUMN` was added in PostgreSQL 9.6. The docker-compose uses `pgvector/pgvector:pg16`, so this is fine.

**R9: Large context windows from memory injection**
- If many high-scoring memories exist, 5 injected facts could add significant tokens.
- **Mitigation**: The limit is hardcoded to 5 in `retrieve_context()`. Each fact is bounded by extraction (no raw chunks, only processed facts). This is acceptable for Phase 1. Phase 2 can make it configurable.

---

## 9. Open Implementation Questions

These must be decided before coding begins. Recommendations are included.

### Q1: Which `MemoryStore` implementation wins?

Currently `PgMemoryStore` (workspace.rs, `memory_entries`) and the new Phase 1 `MemoryStore` impl on `HybridMemorySearch` (search.rs, `memories`) will coexist. The server should use ONLY `HybridMemorySearch` for Phase 1.

**Decision needed**: Should `workspace.rs` / `PgMemoryStore` be left as-is (unused, deprecated), or refactored to use `memories`?

**Recommendation**: Leave `workspace.rs` as-is for Phase 1 (don't break the existing tests). Add a `#[deprecated]` comment. Delete in Phase 2 once `memories` is proven.

### Q2: Where does `EmbeddingProvider` trait live?

Currently defined in `search.rs`. For the embedding implementation in `embedding.rs` to not import from `search.rs` (which feels awkward), it could move to:
- `steward-types/src/traits.rs` — but CLAUDE.md says don't modify this file
- A new `steward-types/src/embedding.rs` or `steward-memory/src/embedding.rs`
- Keep in `search.rs`, import from there

**Recommendation**: Keep in `search.rs` for Phase 1 (pub use re-exported from `lib.rs` if needed). Move to `steward-types` in Phase 2 when the interface is stable.

### Q3: Vector dimensions — 768 or 1536?

Requirements say 768, existing code uses 1536, `text-embedding-3-small` outputs 1536.

**Decision needed**: Use 1536 (consistent with existing code and chosen model)?

**Recommendation**: Yes, use 1536. The requirements doc has a typo or refers to a different model. Document in code comments.

### Q4: Extraction model string

Requirements say "Haiku-class". The current model strings in the codebase are like `claude-sonnet-4-5-20250929`.

**Decision needed**: What exact model string for extraction?

**Recommendation**: Use `claude-haiku-4-5-20251001` per the system instructions. Make it configurable via `ExtractionConfig.model` so it can be changed without code changes.

### Q5: Trust score for user-instruction stored memories

When the agent calls `memory.store` (which uses `MemoryProvenance::AgentObservation` and `trust_score=0.6`), this doesn't match what the requirements describe for explicitly user-authored facts (`trust_score=1.0`).

**Decision needed**: Should `memory.store` called by the agent have trust=0.6 (agent), or should it recognize when the user is the one directing the store and use trust=1.0?

**Recommendation for Phase 1**: Use trust=0.6 for all `memory.store` calls (conservative). The agent is always an intermediary. Phase 2's trust scoring can refine this.

### Q6: Scope for Phase 1 — what goes into search query?

With no personality system yet, all facts are stored with `scope='shared'`. The search query should filter `WHERE scope = 'shared'` (or equivalently no filter since everything is shared).

**Decision needed**: Should Phase 1 search pass a scope parameter or just return all memories?

**Recommendation**: Pass `scope='shared'` explicitly in the search query, even if that's currently all memories. This makes the scope filtering code exist and be tested before personalities are added in Phase 3.

### Q7: Dedup threshold with FTS-only mode

In FTS-only mode (no OpenAI key), the RRF scores max out around `1/61 ≈ 0.016` per rank, weighted by trust. Even a perfect duplicate would score at most `~0.016 * 1.0 = 0.016`, nowhere near 0.9.

**Decision needed**: Is deduplication silently no-op in FTS-only mode acceptable?

**Recommendation**: Yes, accept this for Phase 1. Document it. When embeddings are available, cosine similarity scores are 0.0-1.0 and the 0.9 threshold is meaningful. For Phase 1 without embeddings, duplicates will accumulate — this is a known, acceptable limitation.

### Q8: What happens if extraction fails to parse LLM JSON?

If the Haiku model returns malformed JSON, the extraction silently returns Ok(0). This means no facts are stored but no error is surfaced to the user. This is correct (extraction is best-effort), but how do we know if the prompt is systematically broken?

**Recommendation**: Add a warning log with the raw response content (truncated) when JSON parsing fails. This makes debugging easier without exposing potentially sensitive content in error messages. Add a metric/counter if observability tooling is added later.

### Q9: Extraction during tool-use turns

The agent's `handle_message()` has a tool loop. If the user message is "search the web for X and remember what you find", the `final_response` after tool execution may be "I found the following: [tool results]..." which could be worth extracting.

**Decision needed**: Extract from ALL turns, or only from turns with a substantive human-facing response?

**Recommendation**: Extract from all turns. The extraction prompt is designed to return `[]` for non-memorable content. The Haiku model is cheap enough that false-positive extraction calls are not a cost concern.

---

## Appendix: File Modification Summary

| File | Action | Why |
|------|--------|-----|
| `steward-types/src/actions.rs` | Modify | Add scope/session/channel/confidence to MemoryEntry |
| `steward-memory/src/search.rs` | Modify | Add scope column, MemoryStore impl, store() method, scope-filtered search |
| `steward-memory/src/embedding.rs` | **Create** | OpenAI embedding provider |
| `steward-memory/src/extraction.rs` | **Create** | Post-turn fact extraction pipeline |
| `steward-memory/src/lib.rs` | Modify | Export new modules |
| `steward-memory/Cargo.toml` | Modify | Add reqwest dependency |
| `steward-tools/src/built_in/memory_search.rs` | **Create** | memory.search tool |
| `steward-tools/src/built_in/memory_store.rs` | **Create** | memory.store tool |
| `steward-tools/src/built_in/mod.rs` | Modify | Expose new tool modules |
| `steward-core/src/agent.rs` | Modify | Add memory_store + extractor to AgentDeps, trigger extraction post-turn |
| `steward-core/Cargo.toml` | Modify | Add steward-memory dependency |
| `steward-server/src/main.rs` | Modify | Wire up embedding provider, FactExtractor, register tools |
| `config/permissions.yaml` | Modify | Add memory.store to log_and_execute |
| `steward-memory/src/workspace.rs` | Modify (minor) | Add deprecation comment, fix MemoryEntry struct literals |

**Not modified**:
- `steward-types/src/traits.rs` — per CLAUDE.md instructions
- `steward-memory/src/provenance.rs` — still a stub, Phase 2
- `steward-memory/src/integrity.rs` — still a stub, Phase 2
- `docs/architecture.md` — per CLAUDE.md instructions
- Any security subsystem files
