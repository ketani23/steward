//! Workspace path validation for file tools.
//!
//! Enforces that all file operations remain within the configured workspace
//! directory, preventing directory traversal and symlink escape attacks.
//!
//! The workspace root is configured via the `STEWARD_WORKSPACE` environment
//! variable; if unset it falls back to the process working directory.

use std::path::{Component, Path, PathBuf};

use steward_types::errors::StewardError;

/// Return the workspace root directory.
///
/// Priority: `STEWARD_WORKSPACE` env var → current working directory.
pub fn workspace_root() -> PathBuf {
    std::env::var("STEWARD_WORKSPACE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/home/steward"))
        })
}

/// Validate and resolve a path for a **read or list** operation.
///
/// - Rejects null bytes.
/// - Resolves `..` and `.` components lexically.
/// - Performs a full `canonicalize` (resolving symlinks) and verifies the
///   result is still within the workspace root.
///
/// Returns the canonicalized path on success, or [`StewardError::Tool`] on
/// any violation.
pub fn validate_path(requested: &str, workspace: &Path) -> Result<PathBuf, StewardError> {
    let canonical_workspace = canonicalize_workspace(workspace)?;
    let normalized = build_normalized(requested, &canonical_workspace)?;

    // Full canonicalization catches symlinks that point outside the workspace.
    let canonical = std::fs::canonicalize(&normalized)
        .map_err(|_| StewardError::Tool(format!("path does not exist: {requested}")))?;

    check_within_workspace(&canonical, &canonical_workspace, requested)?;
    Ok(canonical)
}

/// Validate and resolve a path for a **write** operation.
///
/// Like [`validate_path`] but the target file need not exist yet.
/// Canonicalizes the deepest existing ancestor directory to detect symlink
/// escapes through intermediate directories, then reattaches the
/// not-yet-created suffix.
///
/// Returns the resolved path on success.
pub fn validate_write_path(requested: &str, workspace: &Path) -> Result<PathBuf, StewardError> {
    let canonical_workspace = canonicalize_workspace(workspace)?;
    let normalized = build_normalized(requested, &canonical_workspace)?;

    // Canonicalize the deepest existing ancestor to catch symlinks in parent
    // directories (e.g. a symlinked subdir that points outside the workspace).
    let final_path = canonicalize_deepest_ancestor(&normalized)?;

    check_within_workspace(&final_path, &canonical_workspace, requested)?;
    Ok(final_path)
}

/// Open a file for reading with `O_NOFOLLOW` to prevent TOCTOU symlink attacks.
///
/// If a symlink is swapped in at `path` between the path-validation check and
/// the actual open call, `O_NOFOLLOW` causes the kernel to return `ELOOP`
/// immediately rather than following the link.
#[cfg(unix)]
pub fn open_file_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Fallback for non-Unix platforms where `O_NOFOLLOW` is unavailable.
#[cfg(not(unix))]
pub fn open_file_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Write `content` to `path` with `O_NOFOLLOW | O_CREAT | O_TRUNC` to prevent
/// TOCTOU symlink attacks.
///
/// Returns `ELOOP` if the final path component is a symbolic link.
#[cfg(unix)]
pub fn write_file_no_follow(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(content)
}

/// Fallback for non-Unix platforms.
#[cfg(not(unix))]
pub fn write_file_no_follow(path: &Path, content: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, content)
}

// ──────────────────────────── internal helpers ────────────────────────────

/// Canonicalize the workspace root.  If the workspace directory does not yet
/// exist (unusual but possible in tests), fall back to lexical normalization.
fn canonicalize_workspace(workspace: &Path) -> Result<PathBuf, StewardError> {
    if workspace.exists() {
        std::fs::canonicalize(workspace)
            .map_err(|e| StewardError::Tool(format!("cannot resolve workspace: {e}")))
    } else {
        Ok(normalize_lexical(workspace))
    }
}

/// Build a lexically normalized absolute path from `requested`, validating
/// that it lies within `canonical_workspace`.
fn build_normalized(requested: &str, canonical_workspace: &Path) -> Result<PathBuf, StewardError> {
    if requested.contains('\0') {
        return Err(StewardError::Tool("null byte in path".to_string()));
    }

    let req = Path::new(requested);
    let joined = if req.is_absolute() {
        req.to_path_buf()
    } else {
        canonical_workspace.join(req)
    };

    let normalized = normalize_lexical(&joined);

    // Lexical boundary check — catches `../` traversal before any I/O.
    if !normalized.starts_with(canonical_workspace) {
        return Err(StewardError::Tool(format!(
            "path is outside workspace boundary: {requested}"
        )));
    }

    Ok(normalized)
}

/// Assert that `path` starts with `workspace`, returning an error otherwise.
fn check_within_workspace(
    path: &Path,
    workspace: &Path,
    original: &str,
) -> Result<(), StewardError> {
    if !path.starts_with(workspace) {
        Err(StewardError::Tool(format!(
            "path is outside workspace boundary: {original}"
        )))
    } else {
        Ok(())
    }
}

/// Normalize a path purely lexically — no filesystem access.
///
/// Resolves `.` (current dir) and `..` (parent dir) components in sequence.
pub fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

/// Walk up the path until finding an existing directory, canonicalize it,
/// then reattach the non-existing filename suffix.
///
/// This is needed for write paths where the file (and possibly its parent
/// directories) do not yet exist.
fn canonicalize_deepest_ancestor(path: &Path) -> Result<PathBuf, StewardError> {
    if path.exists() {
        return std::fs::canonicalize(path)
            .map_err(|e| StewardError::Tool(format!("cannot canonicalize: {e}")));
    }

    let mut suffix_parts: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path.to_path_buf();

    loop {
        if cursor.exists() {
            let canonical = std::fs::canonicalize(&cursor)
                .map_err(|e| StewardError::Tool(format!("cannot canonicalize ancestor: {e}")))?;
            // Reconstruct: canonical_ancestor joined with suffix parts in order.
            let result = suffix_parts
                .iter()
                .rev()
                .fold(canonical, |acc, part| acc.join(part));
            return Ok(result);
        }

        match cursor.file_name().map(|n| n.to_os_string()) {
            Some(name) => {
                suffix_parts.push(name);
                cursor = match cursor.parent() {
                    Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                    _ => return Ok(path.to_path_buf()),
                };
            }
            None => return Ok(path.to_path_buf()),
        }
    }
}

// ──────────────────────────────── tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a temp directory that acts as the workspace root.
    fn make_workspace() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().canonicalize().unwrap();
        (tmp, ws)
    }

    // ── validate_path (read) ──────────────────────────────────────────────

    #[test]
    fn test_read_simple_file() {
        let (_tmp, ws) = make_workspace();
        let file = ws.join("hello.txt");
        fs::write(&file, "hello").unwrap();

        let result = validate_path("hello.txt", &ws).unwrap();
        assert_eq!(result, file);
    }

    #[test]
    fn test_read_subdir_file() {
        let (_tmp, ws) = make_workspace();
        fs::create_dir_all(ws.join("sub")).unwrap();
        let file = ws.join("sub/notes.txt");
        fs::write(&file, "notes").unwrap();

        let result = validate_path("sub/notes.txt", &ws).unwrap();
        assert_eq!(result, file);
    }

    #[test]
    fn test_read_nonexistent_returns_error() {
        let (_tmp, ws) = make_workspace();
        let err = validate_path("does_not_exist.txt", &ws).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn test_read_dotdot_traversal_rejected() {
        let (_tmp, ws) = make_workspace();
        let err = validate_path("../../etc/passwd", &ws).unwrap_err();
        assert!(
            err.to_string().contains("outside workspace"),
            "expected outside workspace, got: {err}"
        );
    }

    #[test]
    fn test_read_dotdot_in_middle_rejected() {
        let (_tmp, ws) = make_workspace();
        fs::create_dir_all(ws.join("sub")).unwrap();
        // sub/../../etc resolves to parent of workspace root
        let err = validate_path("sub/../../etc/passwd", &ws).unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    #[test]
    fn test_read_absolute_path_inside_workspace_allowed() {
        let (_tmp, ws) = make_workspace();
        let file = ws.join("abs.txt");
        fs::write(&file, "data").unwrap();

        let abs = file.to_str().unwrap();
        let result = validate_path(abs, &ws).unwrap();
        assert_eq!(result, file);
    }

    #[test]
    fn test_read_absolute_path_outside_workspace_rejected() {
        let (_tmp, ws) = make_workspace();
        let err = validate_path("/etc/passwd", &ws).unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    #[test]
    fn test_read_null_byte_rejected() {
        let (_tmp, ws) = make_workspace();
        let err = validate_path("file\0.txt", &ws).unwrap_err();
        assert!(err.to_string().contains("null byte"));
    }

    #[cfg(unix)]
    #[test]
    fn test_read_symlink_escape_rejected() {
        let (_tmp, ws) = make_workspace();
        // Create a symlink inside the workspace that points outside it.
        let link = ws.join("escape_link");
        std::os::unix::fs::symlink("/etc", &link).unwrap();

        let err = validate_path("escape_link/passwd", &ws).unwrap_err();
        assert!(
            err.to_string().contains("outside workspace"),
            "symlink escape should be rejected, got: {err}"
        );
    }

    // ── validate_write_path ───────────────────────────────────────────────

    #[test]
    fn test_write_new_file_allowed() {
        let (_tmp, ws) = make_workspace();
        let result = validate_write_path("newfile.txt", &ws).unwrap();
        assert_eq!(result, ws.join("newfile.txt"));
    }

    #[test]
    fn test_write_new_subdir_file_allowed() {
        let (_tmp, ws) = make_workspace();
        // Neither the subdir nor the file exists yet.
        let result = validate_write_path("newdir/file.txt", &ws).unwrap();
        assert_eq!(result, ws.join("newdir/file.txt"));
    }

    #[test]
    fn test_write_dotdot_traversal_rejected() {
        let (_tmp, ws) = make_workspace();
        let err = validate_write_path("../../etc/evil.txt", &ws).unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    #[test]
    fn test_write_absolute_outside_rejected() {
        let (_tmp, ws) = make_workspace();
        let err = validate_write_path("/etc/evil.txt", &ws).unwrap_err();
        assert!(err.to_string().contains("outside workspace"));
    }

    #[test]
    fn test_write_null_byte_rejected() {
        let (_tmp, ws) = make_workspace();
        let err = validate_write_path("file\0.txt", &ws).unwrap_err();
        assert!(err.to_string().contains("null byte"));
    }

    #[cfg(unix)]
    #[test]
    fn test_write_via_symlinked_parent_rejected() {
        let (_tmp, ws) = make_workspace();
        // symlink inside workspace → points to /tmp (outside workspace)
        let outside = tempfile::tempdir().unwrap();
        let link = ws.join("escape_dir");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();

        let err = validate_write_path("escape_dir/evil.txt", &ws).unwrap_err();
        assert!(
            err.to_string().contains("outside workspace"),
            "symlink parent escape should be rejected, got: {err}"
        );
    }

    // ── open_file_no_follow / write_file_no_follow ────────────────────────

    #[cfg(unix)]
    #[test]
    fn test_open_file_no_follow_accepts_regular_file() {
        let (_tmp, ws) = make_workspace();
        let file = ws.join("regular.txt");
        fs::write(&file, "data").unwrap();

        let result = open_file_no_follow(&file);
        assert!(
            result.is_ok(),
            "regular file must be openable: {:?}",
            result
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_open_file_no_follow_rejects_symlink() {
        let (_tmp, ws) = make_workspace();
        let target = ws.join("real.txt");
        fs::write(&target, "data").unwrap();

        let link = ws.join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // O_NOFOLLOW must refuse to open the symlink (final component is a symlink).
        let result = open_file_no_follow(&link);
        assert!(
            result.is_err(),
            "O_NOFOLLOW should reject opening a symlink directly"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_write_file_no_follow_accepts_regular_path() {
        let (_tmp, ws) = make_workspace();
        let file = ws.join("out.txt");

        let result = write_file_no_follow(&file, b"hello");
        assert!(
            result.is_ok(),
            "writing to a regular path must succeed: {:?}",
            result
        );
        assert_eq!(fs::read(&file).unwrap(), b"hello");
    }

    #[cfg(unix)]
    #[test]
    fn test_write_file_no_follow_rejects_symlink() {
        let (_tmp, ws) = make_workspace();
        let target = ws.join("real.txt");
        fs::write(&target, "original").unwrap();

        let link = ws.join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // O_NOFOLLOW must refuse to write through a symlink final component.
        let result = write_file_no_follow(&link, b"evil");
        assert!(
            result.is_err(),
            "O_NOFOLLOW should reject writing through a symlink"
        );
        // Verify the original file was not modified.
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
    }

    // ── normalize_lexical ─────────────────────────────────────────────────

    #[test]
    fn test_normalize_removes_cur_dir() {
        let p = Path::new("/a/./b/./c");
        assert_eq!(normalize_lexical(p), PathBuf::from("/a/b/c"));
    }

    #[test]
    fn test_normalize_resolves_parent() {
        let p = Path::new("/a/b/../c");
        assert_eq!(normalize_lexical(p), PathBuf::from("/a/c"));
    }

    #[test]
    fn test_normalize_multiple_parents() {
        let p = Path::new("/a/b/c/../../d");
        assert_eq!(normalize_lexical(p), PathBuf::from("/a/d"));
    }
}
