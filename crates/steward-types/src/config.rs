/// Configuration types for the Steward agent framework.
///
/// These are stub types that will be expanded as config management is implemented.
/// Each parallel worker can add fields as needed.
use serde::{Deserialize, Serialize};

/// Top-level permissions configuration, parsed from `config/permissions.yaml`.
///
/// Defines the four permission tiers and their action mappings.
// TODO: Expand with full tier definitions, rate limit configs, time-of-day restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsConfig {
    /// Permission tier definitions.
    pub tiers: PermissionTiers,
}

/// The four permission tiers and their action lists.
// TODO: Add constraints (rate_limit, time_of_day), confirmation config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionTiers {
    /// Safe read-only operations — execute immediately.
    pub auto_execute: TierConfig,
    /// Low-risk writes — execute but log for audit.
    pub log_and_execute: TierConfig,
    /// High-risk actions — require explicit human approval.
    pub human_approval: TierConfig,
    /// Hard-blocked regardless of LLM output.
    pub forbidden: TierConfig,
}

/// Configuration for a single permission tier.
// TODO: Add constraints, confirmation, schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierConfig {
    /// Human-readable description of this tier.
    pub description: String,
    /// List of action patterns (supports wildcards like "email.*").
    pub actions: Vec<String>,
}

/// Guardrails configuration, parsed from `config/guardrails.yaml`.
// TODO: Expand with forbidden patterns, rate limits, circuit breaker defaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailsConfig {
    /// Maximum actions per minute across all tiers.
    pub global_rate_limit: Option<u32>,
    /// Forbidden content patterns (regex).
    pub forbidden_patterns: Vec<String>,
}

/// MCP server manifest configuration, parsed from `config/mcp-manifests/*.yaml`.
// TODO: Expand with full manifest schema from architecture doc section 8.3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpManifestConfig {
    /// MCP server name.
    pub server: String,
    /// Transport type ("stdio" or "http").
    pub transport: String,
    /// List of allowed tools with their configurations.
    pub allowed_tools: Vec<McpToolConfig>,
    /// Blocked parameter patterns (glob patterns like "*.bcc").
    pub blocked_params: Vec<String>,
}

/// Configuration for a single MCP tool in a manifest.
// TODO: Add schema_rewrites, rate_limit, permission_tier override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolConfig {
    /// Tool name.
    pub name: String,
    /// Whether this tool is allowed.
    pub allowed: bool,
    /// Rate limit (e.g., "30/minute").
    pub rate_limit: Option<String>,
    /// Whether this tool requires human approval regardless of tier.
    pub requires_approval: Option<bool>,
}

/// Per-server circuit breaker configuration, embedded in MCP manifest YAML.
///
/// Controls the state machine transitions: Closed → Open → HalfOpen.
/// See `docs/architecture.md` section 8.11 for specification.
///
/// ```yaml
/// circuit_breaker:
///   error_threshold: 5
///   error_window: 60s
///   latency_threshold: 30s
///   recovery_timeout: 120s
///   recovery_probes: 3
///   max_recovery_backoff: 15m
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Consecutive errors within `error_window` before the circuit trips open.
    pub error_threshold: u32,
    /// Duration window for counting consecutive errors (in seconds).
    pub error_window_secs: u64,
    /// Maximum response time before a call counts as an error (in seconds).
    pub latency_threshold_secs: u64,
    /// Base duration to wait before attempting recovery probes (in seconds).
    pub recovery_timeout_secs: u64,
    /// Number of consecutive successful probes needed to close the circuit.
    pub recovery_probes: u32,
    /// Maximum backoff between retry attempts (in seconds).
    pub max_recovery_backoff_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            error_threshold: 5,
            error_window_secs: 60,
            latency_threshold_secs: 30,
            recovery_timeout_secs: 120,
            recovery_probes: 3,
            max_recovery_backoff_secs: 900, // 15 minutes
        }
    }
}

/// Agent identity configuration, parsed from `config/identity.md`.
// TODO: Parse from markdown with YAML frontmatter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Agent name.
    pub name: String,
    /// Agent personality description.
    pub personality: String,
    /// Behavioral boundaries.
    pub boundaries: Vec<String>,
}
