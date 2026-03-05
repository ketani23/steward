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
use tokio::io::AsyncBufReadExt as _;
use tracing::debug;

use steward_types::actions::{PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;

use crate::built_in::workspace::{open_safely, validate_path, workspace_root};
use crate::registry::BuiltInHandler;

/// Default number of lines returned when the caller does not specify a limit.
const DEFAULT_LINE_LIMIT: usize = 1000;

/// Absolute maximum lines that can be returned in a single call.
///
/// Even if the caller passes `limit=9999999`, the response is capped here,
/// keeping peak memory bounded regardless of file size.
const MAX_LINE_LIMIT: usize = 50_000;

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
                        "type": "integer",
                        "description": "Line number (1-based) to start reading from. Defaults to 1."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of lines to return. Defaults to 1000."
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
    /// 3. Return empty immediately if `limit == 0`.
    /// 4. Open file via openat chain (no symlink at any step).
    /// 5. Apply offset (skip lines) and limit (max lines).
    /// 6. Return content with metadata (line count, truncated flag).
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        // 1. Parse parameters.
        let params: FileReadParams = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid file.read parameters: {e}")))?;

        // 2. Validate path.
        let safe_path = validate_path(&params.path, &self.workspace)?;

        debug!(path = %safe_path.display(), "file.read executing");

        // offset is 1-based; convert to 0-based skip count.
        let skip = params.offset.unwrap_or(1).saturating_sub(1);
        let limit = params
            .limit
            .unwrap_or(DEFAULT_LINE_LIMIT)
            .min(MAX_LINE_LIMIT);

        // limit=0 means the caller requested nothing.  validate_path already
        // confirmed the file exists; return empty content immediately.
        if limit == 0 {
            return Ok(ToolResult {
                success: true,
                output: serde_json::json!({
                    "content": "",
                    "path": params.path,
                    "lines_shown": skip,
                    "lines_returned": 0_usize,
                    "offset": skip + 1,
                    "truncated": true,
                }),
                error: None,
            });
        }

        // 3. Open via openat chain — no symlink at any path component is followed.
        let std_file = tokio::task::spawn_blocking({
            let path = safe_path;
            let workspace = self.workspace.clone();
            move || open_safely(&path, &workspace)
        })
        .await
        .map_err(|e| StewardError::Tool(format!("cannot read {}: {e}", params.path)))?
        .map_err(|e| StewardError::Tool(format!("cannot read {}: {e}", params.path)))?;
        let file = tokio::fs::File::from_std(std_file);
        let reader = tokio::io::BufReader::new(file);
        let mut lines_iter = reader.lines();

        // 4. Apply offset and limit during reading.
        let mut skipped: usize = 0;
        let mut collected: Vec<String> = Vec::new();

        loop {
            let line = lines_iter
                .next_line()
                .await
                .map_err(|e| StewardError::Tool(format!("cannot read {}: {e}", params.path)))?;

            let Some(line) = line else { break };

            if skipped < skip {
                skipped += 1;
                continue;
            }

            collected.push(line);

            if collected.len() >= limit {
                break; // Stop reading early — do not load the remainder into memory.
            }
        }

        let lines_returned = collected.len();
        // Peek one more line to distinguish "hit the limit with more content
        // remaining" from "file had exactly `limit` lines".  The previous
        // `lines_returned >= limit` check produced a false positive when the
        // file size was an exact multiple of the limit.
        let truncated = if lines_returned >= limit {
            lines_iter
                .next_line()
                .await
                .map(|opt| opt.is_some())
                .unwrap_or(false)
        } else {
            false
        };
        // lines_shown = lines processed up to the end of the returned window
        // (skipped lines + lines actually returned).  When the file is
        // truncated this is NOT the full file line count — callers should use
        // `truncated` to detect that more content exists.
        let lines_shown = skipped + lines_returned;
        let content = collected.join("\n");

        // 5. Return structured result.
        Ok(ToolResult {
            success: true,
            output: serde_json::json!({
                "content": content,
                "path": params.path,
                "lines_shown": lines_shown,
                "lines_returned": lines_returned,
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
    async fn test_limit_zero_returns_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("data.txt");
        fs::write(&file, "line1\nline2\nline3\n").unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({"path": "data.txt", "limit": 0}))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(
            result.output["lines_returned"], 0,
            "limit=0 must return 0 lines"
        );
        assert_eq!(
            result.output["content"], "",
            "limit=0 must return empty content"
        );
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
    async fn test_exact_limit_not_truncated() {
        let tmp = tempfile::tempdir().unwrap();
        // File has exactly 3 lines; reading with limit=3 must NOT report truncated.
        let lines: String = (1..=3).map(|i| format!("line{i}\n")).collect();
        fs::write(tmp.path().join("exact.txt"), &lines).unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({"path": "exact.txt", "limit": 3}))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output["lines_returned"], 3);
        assert_eq!(
            result.output["truncated"], false,
            "file with exactly limit lines must not be reported as truncated"
        );
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
        assert_eq!(result.output["lines_shown"], 2);
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

    #[cfg(unix)]
    #[tokio::test]
    async fn test_symlink_rejected_by_open_safely() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real.txt");
        fs::write(&real, "data").unwrap();

        // Symlink within workspace pointing to a real file within workspace.
        // O_NOFOLLOW in open_safely catches the final-component symlink swap.
        let link = tmp.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Opening the symlink directly must fail (O_NOFOLLOW returns ELOOP).
        let result = open_safely(&link, tmp.path());
        assert!(
            result.is_err(),
            "open_safely must reject a symlink final component"
        );
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
