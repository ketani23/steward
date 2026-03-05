//! File edit built-in tool.
//!
//! Edits a file by replacing an exact text match.  The `old_text` must match
//! exactly once in the file — the tool returns an error if it matches zero or
//! more than once.
//!
//! Security: paths are validated against the workspace root — directory
//! traversal and symlink escapes are rejected.
//!
//! Permission tier: `HumanApproval` (modifying files is destructive).

use std::path::PathBuf;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use steward_types::actions::{PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;

use crate::built_in::workspace::{validate_path, workspace_root};
use crate::registry::BuiltInHandler;

/// File edit tool — performs an exact text replacement within a workspace file.
///
/// Implements [`BuiltInHandler`] to be registered with the tool registry.
pub struct FileEditTool {
    workspace: PathBuf,
}

impl FileEditTool {
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
    /// Name: `file.edit`, source: `BuiltIn`, tier: `HumanApproval`.
    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: "file.edit".to_string(),
            description: "Edit a file by replacing exact text. \
                          `old_text` must match exactly once in the file."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file, relative to the workspace root."
                    },
                    "old_text": {
                        "type": "string",
                        "description": "Exact text to find in the file. Must match exactly once."
                    },
                    "new_text": {
                        "type": "string",
                        "description": "Replacement text."
                    }
                },
                "required": ["path", "old_text", "new_text"]
            }),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::HumanApproval,
        }
    }
}

/// Parameters for the `file.edit` tool call.
#[derive(Debug, Deserialize)]
struct FileEditParams {
    path: String,
    old_text: String,
    new_text: String,
}

#[async_trait]
impl BuiltInHandler for FileEditTool {
    /// Execute a file edit request.
    ///
    /// Flow:
    /// 1. Parse `{"path": "...", "old_text": "...", "new_text": "..."}` from JSON.
    /// 2. Validate path against workspace root.
    /// 3. Read file contents.
    /// 4. Count occurrences of `old_text`.
    /// 5. Reject if zero (not found) or more than one (ambiguous).
    /// 6. Replace and write the modified file back.
    /// 7. Return confirmation.
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        // 1. Parse parameters.
        let params: FileEditParams = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid file.edit parameters: {e}")))?;

        // 2. Validate path (file must exist to edit it).
        let safe_path = validate_path(&params.path, &self.workspace)?;

        debug!(path = %safe_path.display(), "file.edit executing");

        // 3. Read file contents.
        let original = tokio::fs::read_to_string(&safe_path)
            .await
            .map_err(|e| StewardError::Tool(format!("cannot read {}: {e}", params.path)))?;

        // 4. Count occurrences.
        let count = original.matches(params.old_text.as_str()).count();

        // 5. Reject ambiguous or missing matches.
        if count == 0 {
            return Err(StewardError::Tool(format!(
                "old_text not found in {}: the text must match exactly",
                params.path
            )));
        }
        if count > 1 {
            return Err(StewardError::Tool(format!(
                "old_text matches {count} times in {} — must match exactly once to avoid ambiguity",
                params.path
            )));
        }

        // 6. Replace and write.
        let modified = original.replacen(params.old_text.as_str(), &params.new_text, 1);
        tokio::fs::write(&safe_path, &modified)
            .await
            .map_err(|e| StewardError::Tool(format!("cannot write {}: {e}", params.path)))?;

        // 7. Return confirmation.
        Ok(ToolResult {
            success: true,
            output: serde_json::json!({
                "path": params.path,
                "replaced": true,
            }),
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tool(ws: &std::path::Path) -> FileEditTool {
        FileEditTool::new(ws.to_path_buf())
    }

    // ── tool_definition ──────────────────────────────────────────────────

    #[test]
    fn test_tool_definition_name_source_tier() {
        let def = FileEditTool::tool_definition();
        assert_eq!(def.name, "file.edit");
        assert!(matches!(def.source, ToolSource::BuiltIn));
        assert_eq!(def.permission_tier, PermissionTier::HumanApproval);
    }

    #[test]
    fn test_tool_definition_schema_requires_all_fields() {
        let def = FileEditTool::tool_definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("path")));
        assert!(required.iter().any(|v| v.as_str() == Some("old_text")));
        assert!(required.iter().any(|v| v.as_str() == Some("new_text")));
    }

    // ── happy path ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_replaces_unique_match() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("code.txt");
        fs::write(&file, "Hello, World!\n").unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "code.txt",
                "old_text": "World",
                "new_text": "Steward"
            }))
            .await
            .unwrap();

        assert!(result.success);
        let content = fs::read_to_string(&file).unwrap();
        assert_eq!(content, "Hello, Steward!\n");
    }

    #[tokio::test]
    async fn test_replaces_multiline_match() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("block.txt");
        fs::write(&file, "fn old() {\n    todo!()\n}\n").unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "block.txt",
                "old_text": "fn old() {\n    todo!()\n}",
                "new_text": "fn new() {\n    42\n}"
            }))
            .await
            .unwrap();

        assert!(result.success);
        let content = fs::read_to_string(&file).unwrap();
        assert!(content.contains("fn new()"));
        assert!(!content.contains("fn old()"));
    }

    #[tokio::test]
    async fn test_replace_preserves_rest_of_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("data.txt");
        fs::write(&file, "line1\ntarget\nline3\n").unwrap();

        tool(tmp.path())
            .execute(serde_json::json!({
                "path": "data.txt",
                "old_text": "target",
                "new_text": "REPLACED"
            }))
            .await
            .unwrap();

        let content = fs::read_to_string(&file).unwrap();
        assert!(content.contains("line1"));
        assert!(content.contains("REPLACED"));
        assert!(content.contains("line3"));
        assert!(!content.contains("target"));
    }

    // ── error: not found ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_old_text_not_found_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("text.txt");
        fs::write(&file, "hello world").unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "text.txt",
                "old_text": "nonexistent string",
                "new_text": "replacement"
            }))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("not found"));
    }

    // ── error: multiple matches ───────────────────────────────────────────

    #[tokio::test]
    async fn test_multiple_matches_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("dup.txt");
        fs::write(&file, "foo\nfoo\n").unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "dup.txt",
                "old_text": "foo",
                "new_text": "bar"
            }))
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("2 times") || err.to_string().contains("ambiguity"),
            "unexpected error: {err}"
        );
    }

    // ── security ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_traversal_dotdot_rejected() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "../../etc/passwd",
                "old_text": "root",
                "new_text": "evil"
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    #[tokio::test]
    async fn test_absolute_outside_rejected() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "/etc/shadow",
                "old_text": "root",
                "new_text": "evil"
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    // ── error handling ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_nonexistent_file_returns_error() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "ghost.txt",
                "old_text": "x",
                "new_text": "y"
            }))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("does not exist") || err.to_string().contains("cannot read"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn test_missing_parameters() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({"path": "file.txt"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid file.edit"));
    }
}
