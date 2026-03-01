//! Shell execution built-in tool.
//!
//! Provides sandboxed command execution with:
//! - Command allowlisting and denylisting
//! - Shell metacharacter blocking (no pipes, redirects, subshells)
//! - Output size limits with truncation
//! - Execution timeout
//! - Working directory restrictions
//! - Environment variable filtering
//!
//! Permission tier: HumanApproval (always requires user confirmation).

use std::path::PathBuf;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, warn};

use steward_types::actions::{PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;

use crate::registry::BuiltInHandler;

/// Shell metacharacter patterns that are blocked to prevent injection.
///
/// Commands are executed directly via `tokio::process::Command` (not through
/// a shell), so these are an additional defense-in-depth layer.
const BLOCKED_METACHARACTERS: &[&str] = &["|", ">", "<", "`", "$(", ";", "&&", "||"];

/// Configuration for the shell execution tool.
#[derive(Debug, Clone, Deserialize)]
pub struct ShellConfig {
    /// Commands that are explicitly allowed. If non-empty, only these binaries
    /// may be executed (subject to the denylist override).
    /// An empty list means all commands are allowed (subject to the denylist).
    pub allowed_commands: Vec<String>,

    /// Commands that are always blocked, regardless of the allowlist.
    /// The denylist always wins over the allowlist.
    pub blocked_commands: Vec<String>,

    /// Maximum execution time in seconds before the command is killed.
    pub timeout_secs: u64,

    /// Maximum bytes of stdout or stderr before truncation.
    /// Each stream is truncated independently.
    pub max_output_bytes: usize,

    /// Working directory for command execution.
    /// If `None`, the process inherits the server's working directory.
    pub working_directory: Option<PathBuf>,

    /// Environment variables that are passed through to the child process.
    /// All other environment variables are cleared.
    pub environment_allowlist: Vec<String>,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            allowed_commands: Vec::new(),
            blocked_commands: Vec::new(),
            timeout_secs: 30,
            max_output_bytes: 65536,
            working_directory: None,
            environment_allowlist: vec![
                "PATH".to_string(),
                "HOME".to_string(),
                "USER".to_string(),
                "LANG".to_string(),
                "LC_ALL".to_string(),
            ],
        }
    }
}

/// Shell execution tool — runs commands directly (not via a shell).
///
/// Implements [`BuiltInHandler`] to be registered with the tool registry.
/// All commands require human approval before execution.
pub struct ShellTool {
    config: ShellConfig,
}

impl ShellTool {
    /// Create a new shell tool with the given configuration.
    pub fn new(config: ShellConfig) -> Self {
        Self { config }
    }

    /// Return the [`ToolDefinition`] for this tool.
    ///
    /// Name: `shell.exec`, source: `BuiltIn`, tier: `HumanApproval`.
    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: "shell.exec".to_string(),
            description: "Execute a shell command directly (no shell interpreter). \
                          Requires human approval before execution."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to execute (binary + arguments as a single string)"
                    }
                },
                "required": ["command"]
            }),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::HumanApproval,
        }
    }

    /// Check if a command string contains blocked shell metacharacters.
    fn contains_metacharacters(command: &str) -> Option<&'static str> {
        BLOCKED_METACHARACTERS
            .iter()
            .find(|&&meta| command.contains(meta))
            .copied()
    }

    /// Check if a binary name is allowed by the allowlist/denylist policy.
    fn is_binary_allowed(&self, binary: &str) -> Result<(), StewardError> {
        // Denylist always wins.
        if self.config.blocked_commands.contains(&binary.to_string()) {
            return Err(StewardError::Tool(format!(
                "command is blocked by denylist: {binary}"
            )));
        }

        // If allowlist is non-empty, the binary must be in it.
        if !self.config.allowed_commands.is_empty()
            && !self.config.allowed_commands.contains(&binary.to_string())
        {
            return Err(StewardError::Tool(format!(
                "command not in allowlist: {binary}"
            )));
        }

        Ok(())
    }

    /// Truncate a byte vector to `max_bytes`, returning a flag indicating truncation.
    fn truncate_output(output: Vec<u8>, max_bytes: usize) -> (String, bool) {
        if output.len() > max_bytes {
            let truncated = String::from_utf8_lossy(&output[..max_bytes]).to_string();
            (truncated, true)
        } else {
            (String::from_utf8_lossy(&output).to_string(), false)
        }
    }
}

/// Parameters for the shell.exec tool call.
#[derive(Debug, Deserialize)]
struct ShellParams {
    command: Option<String>,
}

#[async_trait]
impl BuiltInHandler for ShellTool {
    /// Execute a shell command.
    ///
    /// Flow:
    /// 1. Parse `{"command": "..."}` from JSON parameters
    /// 2. Reject empty command
    /// 3. Block shell metacharacters
    /// 4. Split on whitespace into binary + args
    /// 5. Validate binary against allow/deny lists
    /// 6. Build `tokio::process::Command` (direct execution, not via shell)
    /// 7. Clear env, set only allowed env vars
    /// 8. Set working directory if configured
    /// 9. Execute with timeout
    /// 10. Truncate stdout/stderr if over limit
    /// 11. Return structured result
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        // 1. Parse parameters.
        let params: ShellParams = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid shell.exec parameters: {e}")))?;

        let command = params.command.unwrap_or_default();

        // 2. Reject empty command.
        if command.trim().is_empty() {
            return Err(StewardError::Tool("empty command".to_string()));
        }

        // 3. Block shell metacharacters.
        if let Some(meta) = Self::contains_metacharacters(&command) {
            return Err(StewardError::Tool(format!(
                "shell metacharacter not allowed: {meta}"
            )));
        }

        // 4. Split on whitespace.
        let parts: Vec<&str> = command.split_whitespace().collect();
        let binary = parts[0];
        let args = &parts[1..];

        debug!(binary = %binary, args = ?args, "executing shell command");

        // 5. Validate binary against allowlist/denylist.
        self.is_binary_allowed(binary)?;

        // 6. Build Command — direct execution, NOT via shell.
        let mut cmd = tokio::process::Command::new(binary);
        cmd.args(args);

        // 7. Clear environment and set only allowed vars.
        cmd.env_clear();
        for var in &self.config.environment_allowlist {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }

        // 8. Set working directory if configured.
        if let Some(ref dir) = self.config.working_directory {
            cmd.current_dir(dir);
        }

        // Capture stdout and stderr.
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        // 9. Execute with timeout.
        let timeout_duration = std::time::Duration::from_secs(self.config.timeout_secs);

        let output = match tokio::time::timeout(timeout_duration, cmd.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                warn!(error = %e, binary = %binary, "command execution failed");
                return Ok(ToolResult {
                    success: false,
                    output: serde_json::json!({
                        "stdout": "",
                        "stderr": e.to_string(),
                        "exit_code": null,
                        "truncated": false,
                    }),
                    error: Some(format!("command execution failed: {e}")),
                });
            }
            Err(_) => {
                warn!(binary = %binary, timeout_secs = self.config.timeout_secs, "command timed out");
                return Ok(ToolResult {
                    success: false,
                    output: serde_json::json!({
                        "stdout": "",
                        "stderr": "",
                        "exit_code": null,
                        "truncated": false,
                        "timed_out": true,
                    }),
                    error: Some(format!(
                        "command timed out after {}s",
                        self.config.timeout_secs
                    )),
                });
            }
        };

        // 10. Truncate stdout/stderr independently.
        let (stdout, stdout_truncated) =
            Self::truncate_output(output.stdout, self.config.max_output_bytes);
        let (stderr, stderr_truncated) =
            Self::truncate_output(output.stderr, self.config.max_output_bytes);

        let exit_code = output.status.code();
        let success = exit_code == Some(0);
        let truncated = stdout_truncated || stderr_truncated;

        // 11. Return structured result.
        Ok(ToolResult {
            success,
            output: serde_json::json!({
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "truncated": truncated,
            }),
            error: if success {
                None
            } else {
                Some(format!(
                    "command exited with code {}",
                    exit_code.map_or("unknown".to_string(), |c| c.to_string())
                ))
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== tool_definition ==========

    #[test]
    fn test_tool_definition_name_source_tier() {
        let def = ShellTool::tool_definition();
        assert_eq!(def.name, "shell.exec");
        assert!(matches!(def.source, ToolSource::BuiltIn));
        assert_eq!(def.permission_tier, PermissionTier::HumanApproval);
    }

    #[test]
    fn test_tool_definition_has_command_in_schema() {
        let def = ShellTool::tool_definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("command")));
    }

    // ========== Default config ==========

    #[test]
    fn test_default_config() {
        let config = ShellConfig::default();
        assert!(config.allowed_commands.is_empty());
        assert!(config.blocked_commands.is_empty());
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_output_bytes, 65536);
        assert!(config.working_directory.is_none());
        assert!(config.environment_allowlist.contains(&"PATH".to_string()));
        assert!(config.environment_allowlist.contains(&"HOME".to_string()));
    }

    // ========== Allowlist tests ==========

    #[tokio::test]
    async fn test_allowlist_allows_listed_command() {
        let config = ShellConfig {
            allowed_commands: vec!["echo".to_string(), "ls".to_string()],
            ..ShellConfig::default()
        };
        let tool = ShellTool::new(config);

        let result = tool
            .execute(serde_json::json!({"command": "echo hello"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output["stdout"].as_str().unwrap().contains("hello"));
    }

    #[tokio::test]
    async fn test_allowlist_blocks_unlisted_command() {
        let config = ShellConfig {
            allowed_commands: vec!["echo".to_string()],
            ..ShellConfig::default()
        };
        let tool = ShellTool::new(config);

        let err = tool
            .execute(serde_json::json!({"command": "ls /tmp"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not in allowlist"));
    }

    // ========== Denylist tests ==========

    #[tokio::test]
    async fn test_denylist_blocks_listed_command() {
        let config = ShellConfig {
            blocked_commands: vec!["rm".to_string()],
            ..ShellConfig::default()
        };
        let tool = ShellTool::new(config);

        let err = tool
            .execute(serde_json::json!({"command": "rm -rf /"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("blocked by denylist"));
    }

    #[tokio::test]
    async fn test_denylist_overrides_allowlist() {
        let config = ShellConfig {
            allowed_commands: vec!["rm".to_string(), "echo".to_string()],
            blocked_commands: vec!["rm".to_string()],
            ..ShellConfig::default()
        };
        let tool = ShellTool::new(config);

        // rm is in both lists — denylist wins.
        let err = tool
            .execute(serde_json::json!({"command": "rm -rf /"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("blocked by denylist"));

        // echo is in allowlist and NOT in denylist — should work.
        let result = tool
            .execute(serde_json::json!({"command": "echo allowed"}))
            .await
            .unwrap();
        assert!(result.success);
    }

    // ========== Metacharacter tests ==========

    #[tokio::test]
    async fn test_metacharacter_pipe() {
        let tool = ShellTool::new(ShellConfig::default());
        let err = tool
            .execute(serde_json::json!({"command": "echo hello | cat"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("metacharacter"));
        assert!(err.to_string().contains("|"));
    }

    #[tokio::test]
    async fn test_metacharacter_redirect_out() {
        let tool = ShellTool::new(ShellConfig::default());
        let err = tool
            .execute(serde_json::json!({"command": "echo hello > /tmp/out"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("metacharacter"));
    }

    #[tokio::test]
    async fn test_metacharacter_redirect_in() {
        let tool = ShellTool::new(ShellConfig::default());
        let err = tool
            .execute(serde_json::json!({"command": "cat < /etc/passwd"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("metacharacter"));
    }

    #[tokio::test]
    async fn test_metacharacter_backtick() {
        let tool = ShellTool::new(ShellConfig::default());
        let err = tool
            .execute(serde_json::json!({"command": "echo `whoami`"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("metacharacter"));
    }

    #[tokio::test]
    async fn test_metacharacter_dollar_paren() {
        let tool = ShellTool::new(ShellConfig::default());
        let err = tool
            .execute(serde_json::json!({"command": "echo $(whoami)"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("metacharacter"));
    }

    #[tokio::test]
    async fn test_metacharacter_semicolon() {
        let tool = ShellTool::new(ShellConfig::default());
        let err = tool
            .execute(serde_json::json!({"command": "echo a; echo b"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("metacharacter"));
    }

    #[tokio::test]
    async fn test_metacharacter_and_and() {
        let tool = ShellTool::new(ShellConfig::default());
        let err = tool
            .execute(serde_json::json!({"command": "true && echo yes"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("metacharacter"));
    }

    #[tokio::test]
    async fn test_metacharacter_or_or() {
        let tool = ShellTool::new(ShellConfig::default());
        let err = tool
            .execute(serde_json::json!({"command": "false || echo fallback"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("metacharacter"));
    }

    // ========== Timeout test ==========

    #[tokio::test]
    async fn test_timeout() {
        let config = ShellConfig {
            timeout_secs: 1,
            ..ShellConfig::default()
        };
        let tool = ShellTool::new(config);

        let result = tool
            .execute(serde_json::json!({"command": "sleep 10"}))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("timed out"));
        assert_eq!(result.output["timed_out"], true);
    }

    // ========== Output truncation test ==========

    #[tokio::test]
    async fn test_output_truncation() {
        let config = ShellConfig {
            max_output_bytes: 16,
            ..ShellConfig::default()
        };
        let tool = ShellTool::new(config);

        // Generate output longer than 16 bytes.
        let result = tool
            .execute(serde_json::json!({"command": "echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}))
            .await
            .unwrap();

        assert_eq!(result.output["truncated"], true);
        let stdout = result.output["stdout"].as_str().unwrap();
        assert!(stdout.len() <= 16);
    }

    // ========== Working directory test ==========

    #[tokio::test]
    async fn test_working_directory() {
        let config = ShellConfig {
            working_directory: Some(PathBuf::from("/tmp")),
            ..ShellConfig::default()
        };
        let tool = ShellTool::new(config);

        let result = tool
            .execute(serde_json::json!({"command": "pwd"}))
            .await
            .unwrap();

        assert!(result.success);
        let stdout = result.output["stdout"].as_str().unwrap().trim();
        // /tmp may resolve to /private/tmp on macOS.
        assert!(
            stdout == "/tmp" || stdout == "/private/tmp",
            "unexpected pwd output: {stdout}"
        );
    }

    // ========== Environment filtering test ==========

    #[tokio::test]
    async fn test_environment_filtering() {
        let config = ShellConfig {
            environment_allowlist: vec!["PATH".to_string()],
            ..ShellConfig::default()
        };
        let tool = ShellTool::new(config);

        // HOME should NOT be set since it's not in our custom allowlist.
        let result = tool
            .execute(serde_json::json!({"command": "env"}))
            .await
            .unwrap();

        assert!(result.success);
        let stdout = result.output["stdout"].as_str().unwrap();
        // PATH should be present.
        assert!(stdout.contains("PATH="));
        // HOME should not be present (only PATH is in the allowlist).
        assert!(!stdout.contains("HOME="));
    }

    // ========== Exit code tests ==========

    #[tokio::test]
    async fn test_exit_code_zero_is_success() {
        let tool = ShellTool::new(ShellConfig::default());

        let result = tool
            .execute(serde_json::json!({"command": "true"}))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output["exit_code"], 0);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_exit_code_nonzero_is_failure() {
        let tool = ShellTool::new(ShellConfig::default());

        let result = tool
            .execute(serde_json::json!({"command": "false"}))
            .await
            .unwrap();

        assert!(!result.success);
        assert_eq!(result.output["exit_code"], 1);
        assert!(result.error.is_some());
    }

    // ========== Error handling tests ==========

    #[tokio::test]
    async fn test_empty_command() {
        let tool = ShellTool::new(ShellConfig::default());

        let err = tool
            .execute(serde_json::json!({"command": ""}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty command"));
    }

    #[tokio::test]
    async fn test_whitespace_only_command() {
        let tool = ShellTool::new(ShellConfig::default());

        let err = tool
            .execute(serde_json::json!({"command": "   "}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty command"));
    }

    #[tokio::test]
    async fn test_missing_command_parameter() {
        let tool = ShellTool::new(ShellConfig::default());

        let err = tool
            .execute(serde_json::json!({"not_command": "echo hi"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty command") || err.to_string().contains("invalid"));
    }

    #[tokio::test]
    async fn test_binary_not_found() {
        let tool = ShellTool::new(ShellConfig::default());

        let result = tool
            .execute(serde_json::json!({"command": "nonexistent_binary_xyz123"}))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap()
            .contains("execution failed"));
    }
}
