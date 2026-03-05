//! File list built-in tool.
//!
//! Lists files and directories at a given path within the workspace.
//! Supports optional recursive traversal up to a configurable maximum depth.
//!
//! Security: paths are validated against the workspace root — directory
//! traversal and symlink escapes are rejected.
//!
//! Permission tier: `LogAndExecute` (listing is non-destructive).

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use steward_types::actions::{PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;

use crate::built_in::workspace::{validate_path, workspace_root};
use crate::registry::BuiltInHandler;

/// Default maximum directory depth for recursive listings.
const DEFAULT_MAX_DEPTH: usize = 3;

/// File list tool — enumerates files and directories within the workspace.
///
/// Implements [`BuiltInHandler`] to be registered with the tool registry.
pub struct FileListTool {
    workspace: PathBuf,
}

impl FileListTool {
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
    /// Name: `file.list`, source: `BuiltIn`, tier: `LogAndExecute`.
    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: "file.list".to_string(),
            description: "List files and directories at a path. \
                          Defaults to the workspace root. \
                          Set `recursive` to true for a depth-limited tree view."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path to list, relative to workspace root. \
                                        Defaults to the workspace root."
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Whether to recurse into sub-directories. Default: false."
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum recursion depth when recursive is true. Default: 3."
                    }
                },
                "required": []
            }),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::LogAndExecute,
        }
    }
}

/// Parameters for the `file.list` tool call.
#[derive(Debug, Deserialize)]
struct FileListParams {
    path: Option<String>,
    recursive: Option<bool>,
    max_depth: Option<usize>,
}

/// A single entry in the directory listing.
struct Entry {
    /// Relative display path (from the listed root).
    display: String,
    /// Entry type character: `d` for directory, `-` for file.
    kind: char,
    /// Size in bytes (0 for directories).
    size: u64,
}

#[async_trait]
impl BuiltInHandler for FileListTool {
    /// Execute a file list request.
    ///
    /// Flow:
    /// 1. Parse parameters; default path to workspace root.
    /// 2. Validate path against workspace root.
    /// 3. Collect directory entries (recursively if requested).
    /// 4. Format as a human-readable listing.
    /// 5. Return structured result.
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        // 1. Parse parameters.
        let params: FileListParams = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid file.list parameters: {e}")))?;

        // 2. Validate or default path.
        let canonical_workspace = std::fs::canonicalize(&self.workspace)
            .map_err(|e| StewardError::Tool(format!("cannot resolve workspace: {e}")))?;
        let target_dir = match &params.path {
            Some(p) if !p.is_empty() => validate_path(p, &self.workspace)?,
            _ => canonical_workspace.clone(),
        };

        if !target_dir.is_dir() {
            return Err(StewardError::Tool(format!(
                "not a directory: {}",
                params.path.as_deref().unwrap_or(".")
            )));
        }

        debug!(dir = %target_dir.display(), "file.list executing");

        let recursive = params.recursive.unwrap_or(false);
        let max_depth = params.max_depth.unwrap_or(DEFAULT_MAX_DEPTH);

        // 3. Collect entries.
        let mut entries: Vec<Entry> = Vec::new();
        collect_entries(
            &target_dir,
            &target_dir,
            &canonical_workspace,
            recursive,
            0,
            max_depth,
            &mut entries,
        )
        .map_err(|e| StewardError::Tool(format!("error listing directory: {e}")))?;

        // Sort: directories first, then by name.
        entries.sort_by(|a, b| {
            let dir_cmp = b.kind.cmp(&a.kind); // 'd' > '-', so dirs first
            dir_cmp.then(a.display.cmp(&b.display))
        });

        // 4. Format listing.
        let listing = format_listing(&entries);
        let entry_count = entries.len();

        // 5. Return structured result.
        Ok(ToolResult {
            success: true,
            output: serde_json::json!({
                "path": params.path.unwrap_or_else(|| ".".to_string()),
                "entry_count": entry_count,
                "recursive": recursive,
                "listing": listing,
            }),
            error: None,
        })
    }
}

/// Recursively collect directory entries into `out`.
///
/// `root` is the top-level directory being listed (for computing relative
/// display paths).  `current` is the directory being scanned at this call.
/// `workspace` is the canonicalized workspace root used for the symlink
/// boundary check — symlinks whose resolved targets fall outside it are
/// skipped and noted in the listing.
fn collect_entries(
    root: &Path,
    current: &Path,
    workspace: &Path,
    recursive: bool,
    depth: usize,
    max_depth: usize,
    out: &mut Vec<Entry>,
) -> std::io::Result<()> {
    let read_dir = fs::read_dir(current)?;

    for entry_result in read_dir {
        let entry = entry_result?;
        let entry_path = entry.path();

        // Use symlink_metadata (lstat) to inspect the entry WITHOUT following symlinks.
        let symlink_meta = fs::symlink_metadata(&entry_path)?;

        // Display path relative to root.  If strip_prefix fails (should not
        // happen since entry_path is always under root, but guard anyway) fall
        // back to just the filename to avoid leaking the absolute path.
        let rel = match entry_path.strip_prefix(root) {
            Ok(r) => r.to_string_lossy().into_owned(),
            Err(_) => entry_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        };

        if symlink_meta.file_type().is_symlink() {
            // Resolve the symlink target and verify it stays within the workspace.
            match fs::canonicalize(&entry_path) {
                Ok(resolved) if resolved.starts_with(workspace) => {
                    // Safe: symlink target is inside the workspace.
                    if resolved.is_dir() {
                        out.push(Entry {
                            display: format!("{rel}/"),
                            kind: 'd',
                            size: 0,
                        });
                        if recursive && depth < max_depth {
                            collect_entries(
                                root,
                                &resolved,
                                workspace,
                                recursive,
                                depth + 1,
                                max_depth,
                                out,
                            )?;
                        }
                    } else {
                        let size = fs::metadata(&entry_path).map(|m| m.len()).unwrap_or(0);
                        out.push(Entry {
                            display: rel,
                            kind: '-',
                            size,
                        });
                    }
                }
                _ => {
                    // Symlink escapes the workspace or cannot be resolved — skip it.
                    out.push(Entry {
                        display: format!("{rel} (symlink outside workspace, skipped)"),
                        kind: '-',
                        size: 0,
                    });
                }
            }
        } else if symlink_meta.is_dir() {
            out.push(Entry {
                display: format!("{rel}/"),
                kind: 'd',
                size: 0,
            });
            if recursive && depth < max_depth {
                // Canonicalize before recursing to guard against TOCTOU races.
                match fs::canonicalize(&entry_path) {
                    Ok(canonical) if canonical.starts_with(workspace) => {
                        collect_entries(
                            root,
                            &canonical,
                            workspace,
                            recursive,
                            depth + 1,
                            max_depth,
                            out,
                        )?;
                    }
                    _ => {} // Resolved outside workspace — skip.
                }
            }
        } else {
            out.push(Entry {
                display: rel,
                kind: '-',
                size: symlink_meta.len(),
            });
        }
    }
    Ok(())
}

/// Format collected entries into a human-readable string.
///
/// Format per line: `<kind><rw>  <size_padded>  <path>`
/// Example:
/// ```text
/// drw       0  docs/
/// -rw     128  src/main.rs
/// ```
fn format_listing(entries: &[Entry]) -> String {
    if entries.is_empty() {
        return "(empty)".to_string();
    }

    let max_size = entries.iter().map(|e| e.size).max().unwrap_or(0);
    // Width needed to display the largest size.
    let size_width = max_size.to_string().len().max(4);

    entries
        .iter()
        .map(|e| {
            let kind_str = if e.kind == 'd' { "drw" } else { "-rw" };
            format!(
                "{kind_str}  {:>width$}  {}",
                e.size,
                e.display,
                width = size_width
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tool(ws: &std::path::Path) -> FileListTool {
        FileListTool::new(ws.to_path_buf())
    }

    // ── tool_definition ──────────────────────────────────────────────────

    #[test]
    fn test_tool_definition_name_source_tier() {
        let def = FileListTool::tool_definition();
        assert_eq!(def.name, "file.list");
        assert!(matches!(def.source, ToolSource::BuiltIn));
        assert_eq!(def.permission_tier, PermissionTier::LogAndExecute);
    }

    // ── happy path ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_lists_workspace_root_by_default() {
        let tmp = tempfile::tempdir().unwrap();

        fs::write(tmp.path().join("readme.txt"), "hi").unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({}))
            .await
            .unwrap();

        assert!(result.success);
        let listing = result.output["listing"].as_str().unwrap();
        assert!(listing.contains("readme.txt"));
        assert!(listing.contains("src/"));
    }

    #[tokio::test]
    async fn test_lists_specific_subdir() {
        let tmp = tempfile::tempdir().unwrap();

        fs::create_dir(tmp.path().join("docs")).unwrap();
        fs::write(tmp.path().join("docs/guide.txt"), "guide").unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({"path": "docs"}))
            .await
            .unwrap();

        assert!(result.success);
        let listing = result.output["listing"].as_str().unwrap();
        assert!(listing.contains("guide.txt"));
    }

    #[tokio::test]
    async fn test_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("empty")).unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({"path": "empty"}))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output["entry_count"], 0);
        assert_eq!(result.output["listing"], "(empty)");
    }

    #[tokio::test]
    async fn test_recursive_listing() {
        let tmp = tempfile::tempdir().unwrap();

        fs::create_dir_all(tmp.path().join("a/b")).unwrap();
        fs::write(tmp.path().join("a/b/deep.txt"), "deep").unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({"recursive": true}))
            .await
            .unwrap();

        assert!(result.success);
        let listing = result.output["listing"].as_str().unwrap();
        assert!(listing.contains("deep.txt"), "listing: {listing}");
    }

    #[tokio::test]
    async fn test_max_depth_limits_recursion() {
        let tmp = tempfile::tempdir().unwrap();

        // Create a/b/c/d/deep.txt — 4 levels deep.
        fs::create_dir_all(tmp.path().join("a/b/c/d")).unwrap();
        fs::write(tmp.path().join("a/b/c/d/deep.txt"), "deep").unwrap();

        // With max_depth=2 the file at depth 4 should not appear.
        let result = tool(tmp.path())
            .execute(serde_json::json!({"recursive": true, "max_depth": 2}))
            .await
            .unwrap();

        assert!(result.success);
        let listing = result.output["listing"].as_str().unwrap();
        assert!(
            !listing.contains("deep.txt"),
            "should not see deep file: {listing}"
        );
    }

    #[tokio::test]
    async fn test_non_recursive_does_not_descend() {
        let tmp = tempfile::tempdir().unwrap();

        fs::create_dir(tmp.path().join("sub")).unwrap();
        fs::write(tmp.path().join("sub/hidden.txt"), "hidden").unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({"recursive": false}))
            .await
            .unwrap();

        assert!(result.success);
        let listing = result.output["listing"].as_str().unwrap();
        // The subdir appears but not its contents.
        assert!(listing.contains("sub/"));
        assert!(!listing.contains("hidden.txt"));
    }

    // ── security ─────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[tokio::test]
    async fn test_recursive_symlink_escape_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        // Create a file outside the workspace.
        fs::write(outside.path().join("secret.txt"), "secret content").unwrap();

        // Symlink inside workspace pointing to a directory outside workspace.
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("evil_link")).unwrap();

        let result = tool(tmp.path())
            .execute(serde_json::json!({"recursive": true}))
            .await
            .unwrap();

        assert!(result.success);
        let listing = result.output["listing"].as_str().unwrap();
        // Must not expose any file from outside the workspace.
        assert!(
            !listing.contains("secret.txt"),
            "symlink escape: secret.txt must not appear in listing: {listing}"
        );
        // The symlink itself should be noted as skipped.
        assert!(
            listing.contains("evil_link") && listing.contains("symlink outside workspace"),
            "expected symlink note in listing: {listing}"
        );
    }

    #[test]
    fn test_tool_definition_permission_tier_is_log_and_execute() {
        let def = FileListTool::tool_definition();
        assert_eq!(
            def.permission_tier,
            PermissionTier::LogAndExecute,
            "file.list must not require human approval"
        );
    }

    #[tokio::test]
    async fn test_traversal_dotdot_rejected() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({"path": "../../etc"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    #[tokio::test]
    async fn test_absolute_outside_rejected() {
        let tmp = tempfile::tempdir().unwrap();

        let err = tool(tmp.path())
            .execute(serde_json::json!({"path": "/etc"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    // ── format_listing ───────────────────────────────────────────────────

    #[test]
    fn test_format_listing_empty() {
        let result = format_listing(&[]);
        assert_eq!(result, "(empty)");
    }

    #[test]
    fn test_format_listing_has_file_entries() {
        let entries = vec![Entry {
            display: "notes.txt".to_string(),
            kind: '-',
            size: 1024,
        }];
        let result = format_listing(&entries);
        assert!(result.contains("-rw"));
        assert!(result.contains("1024"));
        assert!(result.contains("notes.txt"));
    }

    #[test]
    fn test_format_listing_dirs_prefix_d() {
        let entries = vec![Entry {
            display: "src/".to_string(),
            kind: 'd',
            size: 0,
        }];
        let result = format_listing(&entries);
        assert!(result.starts_with("drw"));
    }
}
