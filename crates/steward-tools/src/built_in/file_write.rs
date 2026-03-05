//! File write built-in tool.
//!
//! Writes text content to a file within the workspace.  Parent directories
//! are created automatically.  Existing files are overwritten.
//!
//! Security: paths are validated against the workspace root — directory
//! traversal and symlink escapes are rejected.
//!
//! Permission tier: `HumanApproval` (writing is destructive).

use std::path::PathBuf;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use steward_types::actions::{PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;

use crate::built_in::workspace::{validate_write_path, workspace_root, write_safely};
use crate::registry::BuiltInHandler;

/// File write tool — creates or overwrites files within the workspace.
///
/// Implements [`BuiltInHandler`] to be registered with the tool registry.
pub struct FileWriteTool {
    workspace: PathBuf,
}

impl FileWriteTool {
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
    /// Name: `file.write`, source: `BuiltIn`, tier: `HumanApproval`.
    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: "file.write".to_string(),
            description: "Write content to a file. Creates parent directories if needed. \
                          Overwrites existing files."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file, relative to the workspace root."
                    },
                    "content": {
                        "type": "string",
                        "description": "Text content to write to the file."
                    }
                },
                "required": ["path", "content"]
            }),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::HumanApproval,
        }
    }
}

/// Parameters for the `file.write` tool call.
#[derive(Debug, Deserialize)]
struct FileWriteParams {
    path: String,
    content: String,
}

#[async_trait]
impl BuiltInHandler for FileWriteTool {
    /// Execute a file write request.
    ///
    /// Flow:
    /// 1. Parse `{"path": "...", "content": "..."}` from JSON.
    /// 2. Validate path against workspace root.
    /// 3. Create parent directories as needed.
    /// 4. Write content to the file.
    /// 5. Return confirmation with bytes written.
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        // 1. Parse parameters.
        let params: FileWriteParams = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid file.write parameters: {e}")))?;

        // 2. Validate path.
        let safe_path = validate_write_path(&params.path, &self.workspace)?;

        debug!(path = %safe_path.display(), "file.write executing");

        // 3. Create parent directories, then re-canonicalize and re-verify
        //    the parent to guard against a symlink race between
        //    validate_write_path and create_dir_all.
        if let Some(parent) = safe_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                StewardError::Tool(format!(
                    "cannot create parent directories for {}: {e}",
                    params.path
                ))
            })?;

            let canonical_parent = tokio::fs::canonicalize(parent).await.map_err(|e| {
                StewardError::Tool(format!("cannot canonicalize parent directory: {e}"))
            })?;
            let canonical_ws = tokio::fs::canonicalize(&self.workspace)
                .await
                .map_err(|e| StewardError::Tool(format!("cannot canonicalize workspace: {e}")))?;
            if !canonical_parent.starts_with(&canonical_ws) {
                return Err(StewardError::Tool(format!(
                    "parent directory is outside workspace: {}",
                    params.path
                )));
            }
        }

        // 4. Write content with O_NOFOLLOW + post-open /proc/self/fd verification
        //    to eliminate both final-component and ancestor-directory TOCTOU races.
        let bytes = params.content.len();
        {
            let path = safe_path;
            let display = params.path.clone();
            let content = params.content.into_bytes();
            let workspace = self.workspace.clone();
            tokio::task::spawn_blocking(move || {
                write_safely(&path, &workspace, &content)
                    .map_err(|e| StewardError::Tool(format!("cannot write {display}: {e}")))
            })
            .await
            .map_err(|e| StewardError::Tool(format!("cannot write {}: {e}", params.path)))?
        }?;

        // 5. Return confirmation.
        Ok(ToolResult {
            success: true,
            output: serde_json::json!({
                "path": params.path,
                "bytes_written": bytes,
            }),
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tool(ws: &std::path::Path) -> FileWriteTool {
        FileWriteTool::new(ws.to_path_buf())
    }

    // ── tool_definition ──────────────────────────────────────────────────

    #[test]
    fn test_tool_definition_name_source_tier() {
        let def = FileWriteTool::tool_definition();
        assert_eq!(def.name, "file.write");
        assert!(matches!(def.source, ToolSource::BuiltIn));
        assert_eq!(def.permission_tier, PermissionTier::HumanApproval);
    }

    #[test]
    fn test_tool_definition_schema_requires_path_and_content() {
        let def = FileWriteTool::tool_definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("path")));
        assert!(required.iter().any(|v| v.as_str() == Some("content")));
    }

    // ── happy path ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_creates_new_file() {
        let tmp = tempfile::tempdir().unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "output.txt",
                "content": "hello world"
            }))
            .await
            .unwrap();

        assert!(result.success);
        let content = fs::read_to_string(tmp.path().join("output.txt")).unwrap();
        assert_eq!(content, "hello world");
    }

    #[tokio::test]
    async fn test_overwrites_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("existing.txt"), "old content").unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "existing.txt",
                "content": "new content"
            }))
            .await
            .unwrap();

        assert!(result.success);
        let content = fs::read_to_string(tmp.path().join("existing.txt")).unwrap();
        assert_eq!(content, "new content");
    }

    #[tokio::test]
    async fn test_creates_parent_directories() {
        let tmp = tempfile::tempdir().unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "deep/nested/dir/file.txt",
                "content": "nested content"
            }))
            .await
            .unwrap();

        assert!(result.success);
        let content = fs::read_to_string(tmp.path().join("deep/nested/dir/file.txt")).unwrap();
        assert_eq!(content, "nested content");
    }

    #[tokio::test]
    async fn test_bytes_written_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let content = "hello";

        let result = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "bytes.txt",
                "content": content
            }))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output["bytes_written"], content.len());
    }

    // ── security ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_traversal_dotdot_rejected() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({
                "path": "../../etc/evil.txt",
                "content": "evil"
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
                "path": "/tmp/evil.txt",
                "content": "evil"
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    // ── error handling ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_missing_path_parameter() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({"content": "oops"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid file.write"));
    }

    #[tokio::test]
    async fn test_missing_content_parameter() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({"path": "file.txt"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid file.write"));
    }
}
