//! MCP capability manifest parser and enforcer.
//!
//! Parses per-server YAML manifests that declare:
//! - Which tools the agent can call
//! - Parameter restrictions and blocked patterns
//! - Rate limits per tool
//! - Permission tier overrides
//!
//! See `docs/architecture.md` section 8.3 for manifest format.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use serde::Deserialize;
use tracing::warn;

use steward_types::actions::{ManifestDecision, McpToolDef, PermissionTier};
use steward_types::errors::StewardError;
use steward_types::traits::McpManifest;

// ============================================================
// YAML-deserialized configuration types
// ============================================================

/// Top-level manifest YAML structure for a single MCP server.
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestConfig {
    /// MCP server name.
    pub server: String,
    /// Server URL (optional, for HTTP/SSE transports).
    pub url: Option<String>,
    /// Transport type: "stdio" or "sse".
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Server status (e.g., "active", "disabled").
    #[serde(default = "default_status")]
    pub status: String,
    /// List of tool capability declarations.
    #[serde(default)]
    pub allowed_tools: Vec<ToolConfig>,
    /// Explicitly blocked tools (tool calls to these are always denied).
    #[serde(default)]
    pub blocked_tools: Vec<String>,
    /// Glob patterns for blocked parameters (e.g., "*.bcc").
    #[serde(default)]
    pub blocked_params: Vec<String>,
    /// Per-tool schema rewrite rules.
    #[serde(default)]
    pub schema_rewrites: HashMap<String, SchemaRewriteConfig>,
    /// Egress filter configuration for this server.
    #[serde(default)]
    pub egress_filter: Option<EgressFilterConfig>,
    /// Audit configuration for this server.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
    /// Circuit breaker configuration for this server.
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

/// Configuration for a single tool's capabilities.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolConfig {
    /// Tool name (e.g., "gmail.send").
    pub name: String,
    /// Whether this tool is allowed.
    #[serde(default = "default_true")]
    pub allowed: bool,
    /// Rate limit string (e.g., "30/minute", "5/hour").
    pub rate_limit: Option<String>,
    /// Whether this tool requires human approval.
    #[serde(default)]
    pub requires_approval: bool,
    /// Permission tier override for this tool.
    pub permission_tier: Option<String>,
}

/// Schema rewrite rules for a specific tool.
#[derive(Debug, Clone, Deserialize)]
pub struct SchemaRewriteConfig {
    /// Parameters to strip from the tool's input schema.
    #[serde(default)]
    pub strip_params: Vec<String>,
    /// Parameter constraints to enforce.
    #[serde(default)]
    pub constrain_params: HashMap<String, ParamConstraint>,
}

/// Constraints on a single parameter.
#[derive(Debug, Clone, Deserialize)]
pub struct ParamConstraint {
    /// Maximum number of items (for arrays like recipients).
    pub max_recipients: Option<u64>,
    /// Maximum size in bytes (for attachments, etc.).
    pub max_size_bytes: Option<u64>,
    /// Maximum numeric value.
    pub maximum: Option<u64>,
}

/// Egress filter configuration for an MCP server.
#[derive(Debug, Clone, Deserialize)]
pub struct EgressFilterConfig {
    /// Whether egress filtering is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether to scan for PII.
    #[serde(default = "default_true")]
    pub scan_pii: bool,
    /// Whether to scan for secrets.
    #[serde(default = "default_true")]
    pub scan_secrets: bool,
}

/// Audit configuration for an MCP server.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    /// Whether audit logging is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether to log full parameters (vs. summary only).
    #[serde(default)]
    pub log_full_params: bool,
}

/// Circuit breaker configuration for an MCP server.
#[derive(Debug, Clone, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Consecutive errors before tripping.
    #[serde(default = "default_error_threshold")]
    pub error_threshold: u32,
    /// Time window for error counting (e.g., "60s").
    #[serde(default = "default_error_window")]
    pub error_window: String,
    /// Max response time before counting as error (e.g., "30s").
    #[serde(default = "default_latency_threshold")]
    pub latency_threshold: String,
    /// How long to wait before retry (e.g., "120s").
    #[serde(default = "default_recovery_timeout")]
    pub recovery_timeout: String,
    /// Successful probes needed to close circuit.
    #[serde(default = "default_recovery_probes")]
    pub recovery_probes: u32,
    /// Maximum backoff between retry attempts (e.g., "15m").
    #[serde(default = "default_max_recovery_backoff")]
    pub max_recovery_backoff: String,
}

fn default_transport() -> String {
    "stdio".to_string()
}
fn default_status() -> String {
    "active".to_string()
}
fn default_true() -> bool {
    true
}
fn default_error_threshold() -> u32 {
    5
}
fn default_error_window() -> String {
    "60s".to_string()
}
fn default_latency_threshold() -> String {
    "30s".to_string()
}
fn default_recovery_timeout() -> String {
    "120s".to_string()
}
fn default_recovery_probes() -> u32 {
    3
}
fn default_max_recovery_backoff() -> String {
    "15m".to_string()
}

// ============================================================
// Parsed rate limit
// ============================================================

/// A parsed rate limit: count per window.
#[derive(Debug, Clone)]
struct RateLimit {
    /// Maximum calls allowed in the window.
    max_calls: u64,
    /// Window duration in seconds.
    window_secs: u64,
}

impl RateLimit {
    /// Parse a rate limit string like "30/minute" or "5/hour".
    fn parse(s: &str) -> Result<Self, StewardError> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(StewardError::Config(format!(
                "invalid rate limit format: '{s}' (expected 'N/unit')"
            )));
        }
        let max_calls: u64 = parts[0].trim().parse().map_err(|_| {
            StewardError::Config(format!("invalid rate limit count: '{}'", parts[0]))
        })?;
        let window_secs = match parts[1].trim() {
            "second" | "sec" | "s" => 1,
            "minute" | "min" | "m" => 60,
            "hour" | "hr" | "h" => 3600,
            "day" | "d" => 86400,
            other => {
                return Err(StewardError::Config(format!(
                    "unknown rate limit unit: '{other}'"
                )))
            }
        };
        Ok(Self {
            max_calls,
            window_secs,
        })
    }
}

// ============================================================
// Rate limiter (sliding-window per tool)
// ============================================================

/// Sliding-window rate limiter state for a single tool.
#[derive(Debug)]
struct RateLimiterState {
    /// Timestamps of recent calls within the window.
    calls: Vec<Instant>,
    /// The rate limit configuration.
    limit: RateLimit,
}

impl RateLimiterState {
    fn new(limit: RateLimit) -> Self {
        Self {
            calls: Vec::new(),
            limit,
        }
    }

    /// Check if a new call is allowed. If allowed, records the call and returns Ok.
    /// If rate-limited, returns the number of seconds to wait.
    fn check_and_record(&mut self) -> Result<(), u64> {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.limit.window_secs);

        // Remove expired entries.
        self.calls.retain(|t| now.duration_since(*t) < window);

        if self.calls.len() as u64 >= self.limit.max_calls {
            // Calculate retry-after from the oldest entry in the window.
            let oldest = self.calls[0];
            let elapsed = now.duration_since(oldest);
            let retry_after = window.saturating_sub(elapsed).as_secs() + 1;
            Err(retry_after)
        } else {
            self.calls.push(now);
            Ok(())
        }
    }
}

// ============================================================
// The manifest implementation
// ============================================================

/// MCP capability manifest — parsed from YAML, enforces tool-level policy.
pub struct McpManifestImpl {
    /// The parsed configuration.
    config: ManifestConfig,
    /// Parsed rate limits per tool name.
    rate_limits: HashMap<String, RateLimit>,
    /// Runtime rate limiter state (mutable, behind Mutex for Send+Sync).
    rate_state: Mutex<HashMap<String, RateLimiterState>>,
}

impl std::fmt::Debug for McpManifestImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpManifestImpl")
            .field("server", &self.config.server)
            .field("transport", &self.config.transport)
            .finish()
    }
}

impl McpManifestImpl {
    /// Create from an already-parsed config (useful for tests).
    pub fn from_config(config: ManifestConfig) -> Result<Self, StewardError> {
        let mut rate_limits = HashMap::new();
        for tool in &config.allowed_tools {
            if let Some(rl_str) = &tool.rate_limit {
                let rl = RateLimit::parse(rl_str)?;
                rate_limits.insert(tool.name.clone(), rl);
            }
        }
        Ok(Self {
            config,
            rate_limits,
            rate_state: Mutex::new(HashMap::new()),
        })
    }

    /// Get the server name.
    pub fn server_name(&self) -> &str {
        &self.config.server
    }

    /// Get the underlying config reference.
    pub fn config(&self) -> &ManifestConfig {
        &self.config
    }

    /// Resolve the permission tier override for a tool, if any.
    pub fn permission_tier_for(&self, tool_name: &str) -> Option<PermissionTier> {
        self.config
            .allowed_tools
            .iter()
            .find(|t| t.name == tool_name)
            .and_then(|t| {
                // Check requires_approval first (shorthand).
                if t.requires_approval {
                    return Some(PermissionTier::HumanApproval);
                }
                // Then check explicit permission_tier field.
                t.permission_tier.as_deref().and_then(parse_permission_tier)
            })
    }

    /// Check if a parameter path matches any of the blocked_params glob patterns.
    fn is_param_blocked(&self, param_path: &str) -> bool {
        self.config
            .blocked_params
            .iter()
            .any(|pattern| glob_match::glob_match(pattern, param_path))
    }

    /// Recursively check all parameter keys against blocked patterns.
    ///
    /// `prefix` is the dotted path prefix. Top-level calls use "arguments" so that
    /// a param key "bcc" becomes "arguments.bcc", matching glob patterns like "*.bcc".
    fn check_params_recursive(&self, value: &serde_json::Value, prefix: &str) -> Option<String> {
        match value {
            serde_json::Value::Object(map) => {
                for key in map.keys() {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    if self.is_param_blocked(&path) {
                        return Some(path);
                    }
                    // Recurse into nested objects.
                    if let Some(blocked) = self.check_params_recursive(&map[key], &path) {
                        return Some(blocked);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Check parameter constraints for a tool call.
    fn check_constraints(&self, tool_name: &str, params: &serde_json::Value) -> Option<String> {
        let rewrites = self.config.schema_rewrites.get(tool_name)?;
        let obj = params.as_object()?;

        for (param_name, constraint) in &rewrites.constrain_params {
            if let Some(value) = obj.get(param_name) {
                if let Some(max_recipients) = constraint.max_recipients {
                    if let Some(arr) = value.as_array() {
                        if arr.len() as u64 > max_recipients {
                            return Some(format!(
                                "parameter '{param_name}' has {} items, max is {max_recipients}",
                                arr.len()
                            ));
                        }
                    }
                }
                if let Some(max_size) = constraint.max_size_bytes {
                    // Check if value has a "size" field or is a string whose length exceeds limit.
                    if let Some(s) = value.as_str() {
                        if s.len() as u64 > max_size {
                            return Some(format!(
                                "parameter '{param_name}' size {} exceeds max {max_size}",
                                s.len()
                            ));
                        }
                    }
                    // For objects that represent files, check a nested size field.
                    if let Some(size_val) = value.get("size").and_then(|v| v.as_u64()) {
                        if size_val > max_size {
                            return Some(format!(
                                "parameter '{param_name}' size {size_val} exceeds max {max_size}"
                            ));
                        }
                    }
                }
                if let Some(maximum) = constraint.maximum {
                    if let Some(n) = value.as_u64() {
                        if n > maximum {
                            return Some(format!(
                                "parameter '{param_name}' value {n} exceeds maximum {maximum}"
                            ));
                        }
                    }
                }
            }
        }
        None
    }

    /// Apply schema rewrites to a tool's input schema JSON.
    fn rewrite_schema(&self, tool_name: &str, mut schema: serde_json::Value) -> serde_json::Value {
        // First, strip any parameters matching blocked_params globs.
        self.strip_blocked_from_schema(&mut schema);

        // Then, apply per-tool schema rewrites.
        if let Some(rewrite) = self.config.schema_rewrites.get(tool_name) {
            // Strip explicitly named params.
            if let Some(props) = schema.get_mut("properties").and_then(|p| p.as_object_mut()) {
                for param in &rewrite.strip_params {
                    props.remove(param);
                }
            }
            // Remove stripped params from "required" array.
            if let Some(required) = schema.get_mut("required").and_then(|r| r.as_array_mut()) {
                required.retain(|v| {
                    v.as_str()
                        .is_none_or(|s| !rewrite.strip_params.contains(&s.to_string()))
                });
            }

            // Apply constraints to schema.
            if let Some(props) = schema.get_mut("properties").and_then(|p| p.as_object_mut()) {
                for (param_name, constraint) in &rewrite.constrain_params {
                    if let Some(prop_schema) = props.get_mut(param_name) {
                        if let Some(max_recipients) = constraint.max_recipients {
                            prop_schema["maxItems"] =
                                serde_json::Value::Number(max_recipients.into());
                        }
                        if let Some(max_size) = constraint.max_size_bytes {
                            prop_schema["maxSizeBytes"] =
                                serde_json::Value::Number(max_size.into());
                        }
                        if let Some(maximum) = constraint.maximum {
                            prop_schema["maximum"] = serde_json::Value::Number(maximum.into());
                        }
                    }
                }
            }
        }

        schema
    }

    /// Strip parameters from a JSON Schema that match blocked_params globs.
    ///
    /// Schema property keys are bare names (e.g., "bcc"). To match glob patterns
    /// like "*.bcc", we check against a synthetic "arguments.{key}" path.
    fn strip_blocked_from_schema(&self, schema: &mut serde_json::Value) {
        if self.config.blocked_params.is_empty() {
            return;
        }
        let to_remove: Vec<String> =
            if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
                props
                    .keys()
                    .filter(|key| {
                        let synthetic_path = format!("arguments.{key}");
                        self.is_param_blocked(&synthetic_path)
                    })
                    .cloned()
                    .collect()
            } else {
                return;
            };

        if to_remove.is_empty() {
            return;
        }

        if let Some(props) = schema.get_mut("properties").and_then(|p| p.as_object_mut()) {
            for key in &to_remove {
                props.remove(key);
            }
        }
        if let Some(required) = schema.get_mut("required").and_then(|r| r.as_array_mut()) {
            required.retain(|v| {
                v.as_str()
                    .is_none_or(|s| !to_remove.contains(&s.to_string()))
            });
        }
    }
}

/// Parse a permission tier string from YAML.
fn parse_permission_tier(s: &str) -> Option<PermissionTier> {
    match s {
        "auto_execute" | "AutoExecute" => Some(PermissionTier::AutoExecute),
        "log_and_execute" | "LogAndExecute" => Some(PermissionTier::LogAndExecute),
        "human_approval" | "HumanApproval" => Some(PermissionTier::HumanApproval),
        "forbidden" | "Forbidden" => Some(PermissionTier::Forbidden),
        _ => None,
    }
}

impl McpManifest for McpManifestImpl {
    fn load(path: &std::path::Path) -> Result<Self, StewardError>
    where
        Self: Sized,
    {
        let content = std::fs::read_to_string(path).map_err(|e| {
            StewardError::Config(format!(
                "failed to read manifest at {}: {e}",
                path.display()
            ))
        })?;
        let config: ManifestConfig = serde_yaml::from_str(&content)?;
        Self::from_config(config)
    }

    fn check_tool_call(&self, tool_name: &str, params: &serde_json::Value) -> ManifestDecision {
        // 1. Check if the tool is explicitly blocked.
        if self.config.blocked_tools.contains(&tool_name.to_string()) {
            return ManifestDecision::Block {
                reason: format!("tool '{tool_name}' is blocked by manifest"),
            };
        }

        // 2. Check if the tool is in the allowed list. If allowed_tools is non-empty,
        //    only tools listed there (with allowed=true) are permitted.
        if !self.config.allowed_tools.is_empty() {
            match self
                .config
                .allowed_tools
                .iter()
                .find(|t| t.name == tool_name)
            {
                Some(tool_cfg) => {
                    if !tool_cfg.allowed {
                        return ManifestDecision::Block {
                            reason: format!("tool '{tool_name}' is not allowed in manifest"),
                        };
                    }
                }
                None => {
                    return ManifestDecision::Block {
                        reason: format!(
                            "tool '{tool_name}' is not listed in manifest for server '{}'",
                            self.config.server
                        ),
                    };
                }
            }
        }

        // 3. Check blocked parameters (glob pattern matching).
        // Use "arguments" as root prefix so top-level keys become "arguments.bcc",
        // matching glob patterns like "*.bcc" (see architecture doc section 8.3).
        if let Some(blocked_param) = self.check_params_recursive(params, "arguments") {
            return ManifestDecision::Block {
                reason: format!("parameter '{blocked_param}' is blocked by manifest pattern"),
            };
        }

        // 4. Check parameter constraints.
        if let Some(violation) = self.check_constraints(tool_name, params) {
            return ManifestDecision::Block {
                reason: format!("constraint violation: {violation}"),
            };
        }

        // 5. Check rate limit.
        if let Some(limit) = self.rate_limits.get(tool_name) {
            let mut state = self.rate_state.lock().unwrap_or_else(|e| {
                warn!("rate limiter mutex poisoned, recovering: {e}");
                e.into_inner()
            });
            let limiter = state
                .entry(tool_name.to_string())
                .or_insert_with(|| RateLimiterState::new(limit.clone()));
            if let Err(retry_after) = limiter.check_and_record() {
                return ManifestDecision::RateLimit {
                    retry_after_secs: retry_after,
                };
            }
        }

        ManifestDecision::Allow
    }

    fn filter_tool_list(&self, tools: Vec<McpToolDef>) -> Vec<McpToolDef> {
        tools
            .into_iter()
            .filter(|tool| {
                // Remove explicitly blocked tools.
                if self.config.blocked_tools.contains(&tool.name) {
                    return false;
                }
                // If allowed_tools is specified, only keep tools that are listed and allowed.
                if !self.config.allowed_tools.is_empty() {
                    return self
                        .config
                        .allowed_tools
                        .iter()
                        .any(|t| t.name == tool.name && t.allowed);
                }
                true
            })
            .map(|mut tool| {
                // Rewrite schemas for allowed tools.
                tool.input_schema = self.rewrite_schema(&tool.name, tool.input_schema);
                tool
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Helper: build a Gmail-like manifest config for testing.
    fn gmail_manifest_yaml() -> &'static str {
        r#"
server: gmail-mcp
url: null
transport: stdio
status: active
allowed_tools:
  - name: gmail.search
    allowed: true
    rate_limit: "30/minute"
  - name: gmail.read
    allowed: true
    rate_limit: "60/minute"
  - name: gmail.send
    allowed: true
    requires_approval: true
    rate_limit: "5/minute"
  - name: gmail.delete
    allowed: false
  - name: gmail.modify_labels
    allowed: true
    rate_limit: "10/minute"
blocked_tools:
  - gmail.create_filter
blocked_params:
  - "*.bcc"
  - "*.forward_to"
schema_rewrites:
  gmail.send:
    strip_params:
      - bcc
      - forward_to
    constrain_params:
      to:
        max_recipients: 5
      attachments:
        max_size_bytes: 10485760
  gmail.search:
    constrain_params:
      max_results:
        maximum: 50
egress_filter:
  enabled: true
  scan_pii: true
  scan_secrets: true
audit:
  enabled: true
  log_full_params: false
circuit_breaker:
  error_threshold: 5
  error_window: "60s"
  latency_threshold: "30s"
  recovery_timeout: "120s"
  recovery_probes: 3
  max_recovery_backoff: "15m"
"#
    }

    fn make_manifest() -> McpManifestImpl {
        let config: ManifestConfig =
            serde_yaml::from_str(gmail_manifest_yaml()).expect("failed to parse test manifest");
        McpManifestImpl::from_config(config).expect("failed to create manifest")
    }

    // ---------------------------------------------------------
    // Test: Parse a complete Gmail manifest
    // ---------------------------------------------------------

    #[test]
    fn test_parse_complete_gmail_manifest() {
        let manifest = make_manifest();
        assert_eq!(manifest.server_name(), "gmail-mcp");
        assert_eq!(manifest.config().transport, "stdio");
        assert_eq!(manifest.config().status, "active");
        assert_eq!(manifest.config().allowed_tools.len(), 5);
        assert_eq!(manifest.config().blocked_tools, vec!["gmail.create_filter"]);
        assert_eq!(
            manifest.config().blocked_params,
            vec!["*.bcc", "*.forward_to"]
        );
        assert!(manifest.config().schema_rewrites.contains_key("gmail.send"));
        assert!(manifest.config().egress_filter.as_ref().unwrap().enabled);
        assert!(manifest.config().audit.as_ref().unwrap().enabled);
        assert_eq!(
            manifest
                .config()
                .circuit_breaker
                .as_ref()
                .unwrap()
                .error_threshold,
            5
        );
    }

    // ---------------------------------------------------------
    // Test: Load manifest from YAML file
    // ---------------------------------------------------------

    #[test]
    fn test_load_from_file() {
        let dir = std::env::temp_dir().join("steward_test_manifest");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_gmail.yaml");
        let yaml = r#"
server: gmail-mcp
transport: stdio
allowed_tools:
  - name: gmail.read
    allowed: true
blocked_tools: []
blocked_params: []
"#;
        std::fs::write(&path, yaml).unwrap();
        let manifest = McpManifestImpl::load(&path).expect("failed to load manifest from file");
        assert_eq!(manifest.server_name(), "gmail-mcp");
        std::fs::remove_file(&path).ok();
    }

    // ---------------------------------------------------------
    // Test: Tool filtering removes blocked tools
    // ---------------------------------------------------------

    #[test]
    fn test_filter_tool_list_removes_blocked_tools() {
        let manifest = make_manifest();
        let tools = vec![
            McpToolDef {
                name: "gmail.search".to_string(),
                description: Some("Search emails".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {"query": {"type": "string"}}
                }),
            },
            McpToolDef {
                name: "gmail.read".to_string(),
                description: Some("Read email".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {"id": {"type": "string"}}
                }),
            },
            McpToolDef {
                name: "gmail.send".to_string(),
                description: Some("Send email".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "to": {"type": "array", "items": {"type": "string"}},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                        "bcc": {"type": "array", "items": {"type": "string"}},
                        "forward_to": {"type": "string"}
                    },
                    "required": ["to", "subject", "body", "bcc"]
                }),
            },
            McpToolDef {
                name: "gmail.delete".to_string(),
                description: Some("Delete email".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {"id": {"type": "string"}}
                }),
            },
            McpToolDef {
                name: "gmail.create_filter".to_string(),
                description: Some("Create filter".to_string()),
                input_schema: json!({"type": "object", "properties": {}}),
            },
        ];

        let filtered = manifest.filter_tool_list(tools);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();

        // gmail.delete has allowed=false, gmail.create_filter is in blocked_tools.
        assert!(names.contains(&"gmail.search"));
        assert!(names.contains(&"gmail.read"));
        assert!(names.contains(&"gmail.send"));
        assert!(
            !names.contains(&"gmail.delete"),
            "delete should be filtered (allowed=false)"
        );
        assert!(
            !names.contains(&"gmail.create_filter"),
            "create_filter should be filtered (blocked)"
        );
    }

    // ---------------------------------------------------------
    // Test: Schema rewriting strips blocked parameters
    // ---------------------------------------------------------

    #[test]
    fn test_schema_rewriting_strips_blocked_params() {
        let manifest = make_manifest();
        let tools = vec![McpToolDef {
            name: "gmail.send".to_string(),
            description: Some("Send email".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "to": {"type": "array", "items": {"type": "string"}},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                    "bcc": {"type": "array", "items": {"type": "string"}},
                    "forward_to": {"type": "string"}
                },
                "required": ["to", "subject", "body", "bcc"]
            }),
        }];

        let filtered = manifest.filter_tool_list(tools);
        assert_eq!(filtered.len(), 1);

        let send_tool = &filtered[0];
        let props = send_tool.input_schema["properties"].as_object().unwrap();

        // bcc and forward_to should be stripped.
        assert!(
            !props.contains_key("bcc"),
            "bcc should be stripped from schema"
        );
        assert!(
            !props.contains_key("forward_to"),
            "forward_to should be stripped from schema"
        );

        // Other params should remain.
        assert!(props.contains_key("to"));
        assert!(props.contains_key("subject"));
        assert!(props.contains_key("body"));

        // "bcc" should be removed from required array.
        let required = send_tool.input_schema["required"].as_array().unwrap();
        let req_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(!req_names.contains(&"bcc"));
        assert!(req_names.contains(&"to"));
        assert!(req_names.contains(&"subject"));
        assert!(req_names.contains(&"body"));
    }

    // ---------------------------------------------------------
    // Test: Parameter constraint enforcement
    // ---------------------------------------------------------

    #[test]
    fn test_constraint_enforcement_max_recipients() {
        let manifest = make_manifest();

        // 5 recipients = allowed.
        let params_ok = json!({
            "to": ["a@b.com", "c@d.com", "e@f.com", "g@h.com", "i@j.com"],
            "subject": "Hello",
            "body": "Test"
        });
        let decision = manifest.check_tool_call("gmail.send", &params_ok);
        assert!(matches!(decision, ManifestDecision::Allow));

        // 6 recipients = blocked.
        let params_bad = json!({
            "to": ["a@b.com", "c@d.com", "e@f.com", "g@h.com", "i@j.com", "k@l.com"],
            "subject": "Mass mail",
            "body": "Spam"
        });
        let decision = manifest.check_tool_call("gmail.send", &params_bad);
        assert!(
            matches!(decision, ManifestDecision::Block { .. }),
            "should block when exceeding max_recipients"
        );
    }

    #[test]
    fn test_constraint_enforcement_max_size_bytes() {
        let manifest = make_manifest();

        // Attachment with size exceeding limit.
        let params = json!({
            "to": ["a@b.com"],
            "subject": "Big file",
            "body": "See attached",
            "attachments": {"size": 20_000_000_u64}
        });
        let decision = manifest.check_tool_call("gmail.send", &params);
        assert!(
            matches!(decision, ManifestDecision::Block { .. }),
            "should block oversized attachments"
        );
    }

    #[test]
    fn test_constraint_enforcement_maximum() {
        let manifest = make_manifest();

        // max_results = 100 exceeds maximum of 50.
        let params = json!({"query": "from:boss", "max_results": 100});
        let decision = manifest.check_tool_call("gmail.search", &params);
        assert!(
            matches!(decision, ManifestDecision::Block { .. }),
            "should block when exceeding maximum"
        );

        // max_results = 25 is fine.
        let params_ok = json!({"query": "from:boss", "max_results": 25});
        let decision = manifest.check_tool_call("gmail.search", &params_ok);
        assert!(matches!(decision, ManifestDecision::Allow));
    }

    // ---------------------------------------------------------
    // Test: Glob pattern matching for blocked_params
    // ---------------------------------------------------------

    #[test]
    fn test_glob_pattern_matching_blocked_params() {
        let manifest = make_manifest();

        // "*.bcc" should match "bcc" at top level.
        let params = json!({"to": ["a@b.com"], "bcc": ["hidden@example.com"]});
        let decision = manifest.check_tool_call("gmail.send", &params);
        assert!(
            matches!(decision, ManifestDecision::Block { .. }),
            "*.bcc should match 'bcc' param"
        );

        // "*.forward_to" should match "forward_to".
        let params = json!({"to": ["a@b.com"], "forward_to": "evil@example.com"});
        let decision = manifest.check_tool_call("gmail.send", &params);
        assert!(
            matches!(decision, ManifestDecision::Block { .. }),
            "*.forward_to should match 'forward_to'"
        );

        // Nested bcc should match via key-level glob check.
        let params = json!({"to": ["a@b.com"], "nested": {"bcc": ["hidden@example.com"]}});
        let decision = manifest.check_tool_call("gmail.send", &params);
        assert!(
            matches!(decision, ManifestDecision::Block { .. }),
            "*.bcc should match nested 'bcc' param"
        );
    }

    #[test]
    fn test_glob_pattern_no_false_positives() {
        let manifest = make_manifest();

        // Normal params without blocked fields should be fine.
        let params = json!({"to": ["a@b.com"], "subject": "Hi", "body": "Hello"});
        let decision = manifest.check_tool_call("gmail.send", &params);
        assert!(matches!(decision, ManifestDecision::Allow));
    }

    // ---------------------------------------------------------
    // Test: Rate limit checking
    // ---------------------------------------------------------

    #[test]
    fn test_rate_limit_checking() {
        let yaml = r#"
server: test-server
allowed_tools:
  - name: test.tool
    allowed: true
    rate_limit: "3/minute"
blocked_tools: []
blocked_params: []
"#;
        let config: ManifestConfig = serde_yaml::from_str(yaml).unwrap();
        let manifest = McpManifestImpl::from_config(config).unwrap();
        let params = json!({});

        // First 3 calls should succeed.
        for i in 0..3 {
            let decision = manifest.check_tool_call("test.tool", &params);
            assert!(
                matches!(decision, ManifestDecision::Allow),
                "call {i} should be allowed"
            );
        }

        // 4th call should be rate-limited.
        let decision = manifest.check_tool_call("test.tool", &params);
        assert!(
            matches!(decision, ManifestDecision::RateLimit { .. }),
            "call 4 should be rate limited"
        );
    }

    // ---------------------------------------------------------
    // Test: Permission tier overrides per tool
    // ---------------------------------------------------------

    #[test]
    fn test_permission_tier_overrides() {
        let manifest = make_manifest();

        // gmail.send has requires_approval=true → HumanApproval.
        assert_eq!(
            manifest.permission_tier_for("gmail.send"),
            Some(PermissionTier::HumanApproval)
        );

        // gmail.search has no override.
        assert_eq!(manifest.permission_tier_for("gmail.search"), None);

        // Unknown tool has no override.
        assert_eq!(manifest.permission_tier_for("unknown.tool"), None);
    }

    #[test]
    fn test_permission_tier_explicit_string() {
        let yaml = r#"
server: test-server
allowed_tools:
  - name: test.readonly
    allowed: true
    permission_tier: auto_execute
  - name: test.write
    allowed: true
    permission_tier: log_and_execute
  - name: test.dangerous
    allowed: true
    permission_tier: forbidden
blocked_tools: []
blocked_params: []
"#;
        let config: ManifestConfig = serde_yaml::from_str(yaml).unwrap();
        let manifest = McpManifestImpl::from_config(config).unwrap();

        assert_eq!(
            manifest.permission_tier_for("test.readonly"),
            Some(PermissionTier::AutoExecute)
        );
        assert_eq!(
            manifest.permission_tier_for("test.write"),
            Some(PermissionTier::LogAndExecute)
        );
        assert_eq!(
            manifest.permission_tier_for("test.dangerous"),
            Some(PermissionTier::Forbidden)
        );
    }

    // ---------------------------------------------------------
    // Test: Blocked tool call is rejected
    // ---------------------------------------------------------

    #[test]
    fn test_blocked_tool_call_rejected() {
        let manifest = make_manifest();

        // gmail.create_filter is in blocked_tools.
        let decision = manifest.check_tool_call("gmail.create_filter", &json!({}));
        assert!(matches!(decision, ManifestDecision::Block { .. }));

        // gmail.delete has allowed: false.
        let decision = manifest.check_tool_call("gmail.delete", &json!({}));
        assert!(matches!(decision, ManifestDecision::Block { .. }));
    }

    // ---------------------------------------------------------
    // Test: Unlisted tool call is rejected
    // ---------------------------------------------------------

    #[test]
    fn test_unlisted_tool_rejected() {
        let manifest = make_manifest();

        // A tool that doesn't appear anywhere in the manifest.
        let decision = manifest.check_tool_call("gmail.unknown", &json!({}));
        assert!(matches!(decision, ManifestDecision::Block { .. }));
    }

    // ---------------------------------------------------------
    // Test: Schema rewriting applies constraints
    // ---------------------------------------------------------

    #[test]
    fn test_schema_rewriting_applies_constraints() {
        let manifest = make_manifest();
        let tools = vec![
            McpToolDef {
                name: "gmail.send".to_string(),
                description: Some("Send email".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "to": {"type": "array", "items": {"type": "string"}},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                        "attachments": {"type": "object"}
                    }
                }),
            },
            McpToolDef {
                name: "gmail.search".to_string(),
                description: Some("Search emails".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "max_results": {"type": "integer"}
                    }
                }),
            },
        ];

        let filtered = manifest.filter_tool_list(tools);

        // gmail.send: "to" should have maxItems=5, "attachments" maxSizeBytes.
        let send = filtered.iter().find(|t| t.name == "gmail.send").unwrap();
        let to_schema = &send.input_schema["properties"]["to"];
        assert_eq!(to_schema["maxItems"], json!(5));

        let attachments_schema = &send.input_schema["properties"]["attachments"];
        assert_eq!(attachments_schema["maxSizeBytes"], json!(10_485_760));

        // gmail.search: "max_results" should have maximum=50.
        let search = filtered.iter().find(|t| t.name == "gmail.search").unwrap();
        let max_results_schema = &search.input_schema["properties"]["max_results"];
        assert_eq!(max_results_schema["maximum"], json!(50));
    }

    // ---------------------------------------------------------
    // Test: Allowed tool call succeeds
    // ---------------------------------------------------------

    #[test]
    fn test_allowed_tool_call_succeeds() {
        let manifest = make_manifest();
        let params = json!({"query": "from:alice", "max_results": 10});
        let decision = manifest.check_tool_call("gmail.search", &params);
        assert!(matches!(decision, ManifestDecision::Allow));
    }

    // ---------------------------------------------------------
    // Test: Rate limit parsing edge cases
    // ---------------------------------------------------------

    #[test]
    fn test_rate_limit_parsing() {
        assert!(RateLimit::parse("30/minute").is_ok());
        assert!(RateLimit::parse("5/hour").is_ok());
        assert!(RateLimit::parse("100/second").is_ok());
        assert!(RateLimit::parse("10/day").is_ok());
        assert!(RateLimit::parse("invalid").is_err());
        assert!(RateLimit::parse("30/lightyear").is_err());
        assert!(RateLimit::parse("abc/minute").is_err());
    }

    // ---------------------------------------------------------
    // Test: Empty manifest allows all tools
    // ---------------------------------------------------------

    #[test]
    fn test_empty_allowed_tools_allows_all() {
        let yaml = r#"
server: permissive-server
allowed_tools: []
blocked_tools: []
blocked_params: []
"#;
        let config: ManifestConfig = serde_yaml::from_str(yaml).unwrap();
        let manifest = McpManifestImpl::from_config(config).unwrap();

        let decision = manifest.check_tool_call("any.tool", &json!({}));
        assert!(matches!(decision, ManifestDecision::Allow));
    }

    // ---------------------------------------------------------
    // Test: Default config values
    // ---------------------------------------------------------

    #[test]
    fn test_minimal_manifest_defaults() {
        let yaml = r#"
server: minimal-server
allowed_tools:
  - name: test.tool
"#;
        let config: ManifestConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.transport, "stdio");
        assert_eq!(config.status, "active");
        assert!(config.blocked_tools.is_empty());
        assert!(config.blocked_params.is_empty());
        assert!(config.allowed_tools[0].allowed); // default true
    }
}
