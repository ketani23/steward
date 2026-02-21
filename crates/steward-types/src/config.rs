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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierConfig {
    /// Human-readable description of this tier.
    pub description: String,
    /// List of action patterns (supports wildcards like "email.*").
    pub actions: Vec<String>,
    /// Optional constraints (rate limits, etc.).
    #[serde(default)]
    pub constraints: Option<TierConstraints>,
    /// Optional confirmation config (for human_approval tier).
    #[serde(default)]
    pub confirmation: Option<ConfirmationConfig>,
}

/// Constraints that can be applied to a permission tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierConstraints {
    /// Rate limit in the format "N/period" (e.g., "60/minute", "10/second").
    pub rate_limit: Option<String>,
}

/// Configuration for the human approval confirmation flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationConfig {
    /// Which channel to request confirmation through.
    pub channel: Option<String>,
    /// What information to show in the confirmation request.
    pub show: Option<Vec<String>>,
    /// Timeout for the confirmation request (e.g., "5m").
    pub timeout: Option<String>,
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
