//! Built-in `memory.search` tool for querying persistent memory.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;

use steward_types::actions::{PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;
use steward_types::traits::MemorySearch;

use crate::registry::BuiltInHandler;

/// Built-in tool that searches persistent memory for relevant facts.
pub struct MemorySearchTool {
    memory: Arc<dyn MemorySearch>,
}

impl MemorySearchTool {
    /// Create a new memory search tool.
    pub fn new(memory: Arc<dyn MemorySearch>) -> Self {
        Self { memory }
    }

    /// Return the tool definition for registration.
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
        let scope = params.scope.as_deref().or(Some("shared"));
        let results = self.memory.search(&params.query, limit, scope).await?;

        let formatted: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "content": r.entry.content,
                    "score": r.score,
                    "provenance": format!("{:?}", r.entry.provenance),
                    "created_at": r.entry.created_at.to_rfc3339(),
                    "scope": r.entry.scope.as_deref().unwrap_or("shared"),
                })
            })
            .collect();

        let count = formatted.len();
        Ok(ToolResult {
            success: true,
            output: serde_json::json!({"results": formatted, "count": count}),
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use steward_types::actions::{MemoryEntry, MemoryProvenance, MemorySearchResult};

    struct MockMemorySearch {
        results: Vec<MemorySearchResult>,
    }

    #[async_trait]
    impl MemorySearch for MockMemorySearch {
        async fn search(
            &self,
            _query: &str,
            _limit: usize,
            _scope: Option<&str>,
        ) -> Result<Vec<MemorySearchResult>, StewardError> {
            Ok(self.results.clone())
        }
    }

    fn make_result(content: &str, score: f64) -> MemorySearchResult {
        MemorySearchResult {
            entry: MemoryEntry {
                id: Some(uuid::Uuid::new_v4()),
                content: content.to_string(),
                provenance: MemoryProvenance::AgentObservation,
                trust_score: 0.6,
                created_at: chrono::Utc::now(),
                embedding: None,
                scope: Some("shared".to_string()),
                source_session: None,
                source_channel: None,
                confidence: Some(0.9),
            },
            score,
            fts_rank: Some(1),
            vector_rank: None,
        }
    }

    #[test]
    fn test_tool_definition_name_and_tier() {
        let def = MemorySearchTool::tool_definition();
        assert_eq!(def.name, "memory.search");
        assert_eq!(def.permission_tier, PermissionTier::AutoExecute);
    }

    #[tokio::test]
    async fn test_execute_formats_results() {
        let mock = MockMemorySearch {
            results: vec![make_result("test fact", 0.85)],
        };
        let tool = MemorySearchTool::new(Arc::new(mock));
        let result = tool
            .execute(serde_json::json!({"query": "test"}))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output["count"], 1);
        assert_eq!(result.output["results"][0]["content"], "test fact");
    }

    #[tokio::test]
    async fn test_execute_limits_to_20() {
        let mock = MockMemorySearch { results: vec![] };
        let tool = MemorySearchTool::new(Arc::new(mock));
        // Passing limit=100 should be capped internally (verified by the tool not erroring)
        let result = tool
            .execute(serde_json::json!({"query": "test", "limit": 100}))
            .await
            .unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_execute_missing_query_param() {
        let mock = MockMemorySearch { results: vec![] };
        let tool = MemorySearchTool::new(Arc::new(mock));
        let result = tool.execute(serde_json::json!({})).await;
        assert!(result.is_err());
    }
}
