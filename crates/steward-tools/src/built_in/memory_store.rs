//! Built-in `memory.store` tool for explicitly storing facts in persistent memory.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;

use steward_types::actions::{
    MemoryEntry, MemoryProvenance, PermissionTier, ToolDefinition, ToolResult, ToolSource,
};
use steward_types::errors::StewardError;
use steward_types::traits::MemoryStore;

use crate::registry::BuiltInHandler;

/// Built-in tool that stores a fact in persistent memory.
pub struct MemoryStoreTool {
    store: Arc<dyn MemoryStore>,
}

impl MemoryStoreTool {
    /// Create a new memory store tool.
    pub fn new(store: Arc<dyn MemoryStore>) -> Self {
        Self { store }
    }

    /// Return the tool definition for registration.
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
    tags: Option<Vec<String>>, // stored in Phase 2
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
            provenance: MemoryProvenance::UserInstruction,
            trust_score: 0.6,
            created_at: chrono::Utc::now(),
            embedding: None,
            scope: Some(params.scope.unwrap_or_else(|| "shared".to_string())),
            source_session: None,
            source_channel: None,
            confidence: Some(1.0), // explicitly stored = high confidence
        };

        let id = self.store.store(entry).await?;

        Ok(ToolResult {
            success: true,
            output: serde_json::json!({"id": id.to_string(), "stored": true}),
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use steward_types::actions::MemoryId;
    use tokio::sync::Mutex;

    struct MockMemoryStore {
        stored: Mutex<Vec<MemoryEntry>>,
    }

    impl MockMemoryStore {
        fn new() -> Self {
            Self {
                stored: Mutex::new(vec![]),
            }
        }
    }

    #[async_trait]
    impl MemoryStore for MockMemoryStore {
        async fn store(&self, entry: MemoryEntry) -> Result<MemoryId, StewardError> {
            let id = entry.id.unwrap_or_else(uuid::Uuid::new_v4);
            self.stored.lock().await.push(entry);
            Ok(id)
        }

        async fn get(&self, _id: &MemoryId) -> Result<Option<MemoryEntry>, StewardError> {
            Ok(None)
        }

        async fn update_trust(&self, _id: &MemoryId, _score: f64) -> Result<(), StewardError> {
            Ok(())
        }
    }

    #[test]
    fn test_tool_definition_name_and_tier() {
        let def = MemoryStoreTool::tool_definition();
        assert_eq!(def.name, "memory.store");
        assert_eq!(def.permission_tier, PermissionTier::LogAndExecute);
    }

    #[tokio::test]
    async fn test_execute_stores_entry() {
        let mock = Arc::new(MockMemoryStore::new());
        let tool = MemoryStoreTool::new(mock.clone());
        let result = tool
            .execute(serde_json::json!({"content": "test fact"}))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(mock.stored.lock().await.len(), 1);
        assert_eq!(mock.stored.lock().await[0].content, "test fact");
    }

    #[tokio::test]
    async fn test_execute_empty_content_rejected() {
        let mock = Arc::new(MockMemoryStore::new());
        let tool = MemoryStoreTool::new(mock);
        let result = tool.execute(serde_json::json!({"content": "  "})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_returns_uuid() {
        let mock = Arc::new(MockMemoryStore::new());
        let tool = MemoryStoreTool::new(mock);
        let result = tool
            .execute(serde_json::json!({"content": "remember this"}))
            .await
            .unwrap();

        assert!(result.output["id"].is_string());
        assert_eq!(result.output["stored"], true);
    }
}
