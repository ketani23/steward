//! File read built-in tool.
//!
//! Reads text file contents from within the workspace, with optional
//! line-based offset and limit (default 200 lines).
//!
//! Security: paths are validated against the workspace root — directory
//! traversal and symlink escapes are rejected.
//!
//! Permission tier: `LogAndExecute` (reading is non-destructive).

use std::path::PathBuf;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use steward_types::actions::{PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;

use crate::built_in::workspace::{validate_path, workspace_root};
use crate::registry::BuiltInHandler;

/// Default maximum number of lines returned when no limit is specified.
const DEFAULT_LINE_LIMIT: usize = 200;

/// File read tool — reads text files within the workspace.
///
/// Implements [`BuiltInHandler`] to be registered with the tool registry.
pub struct FileReadTool {
    workspace: PathBuf,
}

impl FileReadTool {
    /// Create a new tool with an explicit workspace root.
    pub fn new(workspace: PathBuf) -> Self {
        Self { workspace }
    }

    /// Create a new tool reading the workspace from the environment.
    ///
    /// Uses `STEWARD_WORKSPACE` env var, falling back to the current directory.
    pub fn from_env() -> Self {
        Self::new(workspace_root())
    }

    /// Return the [`ToolDefinition`] for this tool.
    ///
    /// Name: `file.read`, source: `BuiltIn`, tier: `LogAndExecute`.
    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: "file.read".to_string(),
            description: "Read the contents of a file. Supports text files. \
                          Returns up to `limit` lines starting from `offset`."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file, relative to the workspace root."
                    },
                    "offset": {
                        "type": "number",
                        "description": "Line number (1-based) to start reading from. Defaults to 1."
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of lines to return. Defaults to 200."
                    }
                },
                "required": ["path"]
            }),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::LogAndExecute,
        }
    }
}

/// Parameters for the `file.read` tool call.
#[derive(Debug, Deserialize)]
struct FileReadParams {
    path: String,
    /// 1-based line offset (first line to include).
    offset: Option<usize>,
    /// Maximum number of lines to return.
    limit: Option<usize>,
}

#[async_trait]
impl BuiltInHandler for FileReadTool {
    /// Execute a file read request.
    ///
    /// Flow:
    /// 1. Parse `{"path": "...", "offset": N, "limit": M}` from JSON.
    /// 2. Validate path against workspace root.
    /// 3. Read file contents from disk.
    /// 4. Apply offset (skip lines) and limit (max lines).
    /// 5. Return content with metadata (line count, truncated flag).
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        // 1. Parse parameters.
        let params: FileReadParams = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid file.read parameters: {e}")))?;

        // 2. Validate path.
        let safe_path = validate_path(&params.path, &self.workspace)?;

        debug!(path = %safe_path.display(), "file.read executing");

        // 3. Read file contents.
        let raw = tokio::fs::read_to_string(&safe_path)
            .await
            .map_err(|e| StewardError::Tool(format!("cannot read {}: {e}", params.path)))?;

        // 4. Apply offset and limit.
        let all_lines: Vec<&str> = raw.lines().collect();
        let total_lines = all_lines.len();

        // offset is 1-based; convert to 0-based index.
        let skip = params.offset.unwrap_or(1).saturating_sub(1);
        let limit = params.limit.unwrap_or(DEFAULT_LINE_LIMIT);

        let sliced: Vec<&str> = all_lines.iter().skip(skip).take(limit).copied().collect();
        let truncated = (skip + sliced.len()) < total_lines;

        let content = sliced.join("\n");

        // 5. Return structured result.
        Ok(ToolResult {
            success: true,
            output: serde_json::json!({
                "content": content,
                "path": params.path,
                "total_lines": total_lines,
                "lines_returned": sliced.len(),
                "offset": skip + 1,
                "truncated": truncated,
            }),
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tool(ws: &std::path::Path) -> FileReadTool {
        FileReadTool::new(ws.to_path_buf())
    }

    // ── tool_definition ──────────────────────────────────────────────────

    #[test]
    fn test_tool_definition_name_source_tier() {
        let def = FileReadTool::tool_definition();
        assert_eq!(def.name, "file.read");
        assert!(matches!(def.source, ToolSource::BuiltIn));
        assert_eq!(def.permission_tier, PermissionTier::LogAndExecute);
    }

    #[test]
    fn test_tool_definition_schema_has_path() {
        let def = FileReadTool::tool_definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("path")));
    }

    // ── happy path ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_reads_file_content() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("hello.txt");
        fs::write(&file, "line1\nline2\nline3\n").unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({"path": "hello.txt"}))
            .await
            .unwrap();

        assert!(result.success);
        let content = result.output["content"].as_str().unwrap();
        assert!(content.contains("line1"));
        assert!(content.contains("line2"));
        assert!(content.contains("line3"));
    }

    #[tokio::test]
    async fn test_offset_skips_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("multi.txt");
        fs::write(&file, "a\nb\nc\nd\ne\n").unwrap();

        // offset=3 means start from line 3 (1-based)
        let result = tool(tmp.path())
            .execute(serde_json::json!({"path": "multi.txt", "offset": 3}))
            .await
            .unwrap();

        assert!(result.success);
        let content = result.output["content"].as_str().unwrap();
        assert!(!content.contains('a'));
        assert!(!content.contains('b'));
        assert!(content.contains('c'));
    }

    #[tokio::test]
    async fn test_limit_truncates_output() {
        let tmp = tempfile::tempdir().unwrap();
        let lines: String = (1..=10).map(|i| format!("line{i}\n")).collect();
        let file = tmp.path().join("many.txt");
        fs::write(&file, &lines).unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({"path": "many.txt", "limit": 3}))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output["lines_returned"], 3);
        assert_eq!(result.output["truncated"], true);
    }

    #[tokio::test]
    async fn test_full_file_not_truncated() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("small.txt");
        fs::write(&file, "one\ntwo\n").unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({"path": "small.txt"}))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output["truncated"], false);
        assert_eq!(result.output["total_lines"], 2);
    }

    // ── security ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_traversal_dotdot_rejected() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({"path": "../../etc/passwd"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    #[tokio::test]
    async fn test_absolute_outside_rejected() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({"path": "/etc/shadow"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    #[tokio::test]
    async fn test_nonexistent_file_returns_error() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({"path": "no_such_file.txt"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("does not exist") || err.to_string().contains("cannot read"),
            "unexpected error: {err}"
        );
    }

    // ── error handling ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_missing_path_parameter() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({"content": "oops"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid file.read"));
    }
}
