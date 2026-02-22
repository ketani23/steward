/// Configuration types for the Steward agent framework.
///
/// Full serde types for parsing permissions, guardrails, MCP manifests, and identity
/// config from YAML/Markdown files. Used by the `ConfigLoader` for directory-based loading,
/// validation, and hot-reload.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================
// Permissions Configuration (permissions.yaml)
// ============================================================

/// Top-level permissions configuration, parsed from `config/permissions.yaml`.
///
/// Defines the four permission tiers and their action mappings, rate limits,
/// time-of-day restrictions, and confirmation flow settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsConfig {
    /// Permission tier definitions.
    pub tiers: PermissionTiers,
}

/// The four permission tiers and their action lists.
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
    /// Optional constraints (rate limits, time-of-day, etc.).
    #[serde(default)]
    pub constraints: Option<TierConstraints>,
    /// Optional confirmation config (for human_approval tier).
    #[serde(default)]
    pub confirmation: Option<ConfirmationConfig>,
}

/// Constraints that can be applied to a permission tier.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TierConstraints {
    /// Rate limit in the format "N/period" (e.g., "60/minute", "10/second").
    pub rate_limit: Option<String>,
    /// Time-of-day restrictions — actions only allowed during these windows.
    #[serde(default)]
    pub time_of_day: Option<Vec<TimeOfDayWindow>>,
}

/// A time-of-day window during which actions are allowed.
///
/// Uses 24-hour format. If `start` > `end`, the window wraps past midnight
/// (e.g., start: "22:00", end: "06:00" means 10PM to 6AM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeOfDayWindow {
    /// Start time in HH:MM format (24-hour).
    pub start: String,
    /// End time in HH:MM format (24-hour).
    pub end: String,
    /// Optional timezone (e.g., "America/New_York"). Defaults to UTC.
    #[serde(default)]
    pub timezone: Option<String>,
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

// ============================================================
// Guardrails Configuration (guardrails.yaml)
// ============================================================

/// Guardrails configuration, parsed from `config/guardrails.yaml`.
///
/// Global safety constraints that apply across all permission tiers, including
/// forbidden patterns, circuit breaker defaults, and egress/ingress settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailsConfig {
    /// Maximum actions per minute across all tiers.
    pub global_rate_limit: Option<u32>,
    /// Forbidden content patterns (regex strings).
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
    /// Default circuit breaker configuration for MCP servers.
    #[serde(default)]
    pub circuit_breaker_defaults: Option<CircuitBreakerConfig>,
    /// Egress filter configuration.
    #[serde(default)]
    pub egress: Option<EgressConfig>,
    /// Ingress sanitizer configuration.
    #[serde(default)]
    pub ingress: Option<IngressConfig>,
}

/// Egress filter configuration from guardrails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressConfig {
    /// Maximum outbound messages per minute.
    pub max_outbound_per_minute: Option<u32>,
    /// Maximum recipients per message.
    pub max_recipients_per_message: Option<u32>,
    /// Whether PII scanning is enabled.
    #[serde(default = "default_true")]
    pub pii_scan_enabled: bool,
    /// Whether secret scanning is enabled.
    #[serde(default = "default_true")]
    pub secret_scan_enabled: bool,
}

/// Ingress sanitizer configuration from guardrails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressConfig {
    /// Maximum content size in characters (context budget).
    pub max_content_chars: Option<u64>,
    /// Whether injection detection is enabled.
    #[serde(default = "default_true")]
    pub injection_detection_enabled: bool,
}

fn default_true() -> bool {
    true
}

// ============================================================
// MCP Manifest Configuration (mcp-manifests/*.yaml)
// ============================================================

/// MCP server manifest configuration, parsed from `config/mcp-manifests/*.yaml`.
///
/// Full manifest schema from architecture doc section 8.3, including tool-level
/// allow/block, rate limiting, schema rewrites, and circuit breaker config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpManifestConfig {
    /// MCP server name.
    pub server: String,
    /// Transport type ("stdio" or "http").
    pub transport: String,
    /// List of allowed tools with their configurations.
    #[serde(default)]
    pub allowed_tools: Vec<McpToolConfig>,
    /// Blocked parameter patterns (glob patterns like "*.bcc").
    #[serde(default)]
    pub blocked_params: Vec<String>,
    /// Per-tool schema rewrite rules (architecture section 8.9).
    #[serde(default)]
    pub schema_rewrites: HashMap<String, SchemaRewriteConfig>,
    /// Circuit breaker configuration for this server.
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

/// Configuration for a single MCP tool in a manifest.
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
    /// Permission tier override for this tool.
    pub permission_tier: Option<String>,
    /// Schema rewrite rules for this tool's input schema.
    pub schema_rewrites: Option<SchemaRewriteConfig>,
}

/// Schema rewrite configuration for an MCP tool.
///
/// Used by the schema rewriter (architecture section 8.9) to strip blocked
/// parameters and apply constraints to tool input schemas before the agent
/// sees them. This is proactive defense — the agent cannot construct calls
/// with blocked parameters because they are absent from the schema.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SchemaRewriteConfig {
    /// Property names to remove from the schema's `properties` object.
    /// Also removed from `required` if present.
    #[serde(default)]
    pub strip_params: Vec<String>,
    /// Constraints to add or modify on existing properties.
    /// Keys are property names, values describe the constraints.
    #[serde(default)]
    pub constrain_params: HashMap<String, ParamConstraint>,
}

/// Constraints to apply to a JSON Schema property.
///
/// Each field maps to a JSON Schema keyword. Only non-None fields are
/// applied to the property's schema object.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParamConstraint {
    /// Maximum numeric value (JSON Schema `maximum`).
    pub maximum: Option<f64>,
    /// Minimum numeric value (JSON Schema `minimum`).
    pub minimum: Option<f64>,
    /// Maximum string length (JSON Schema `maxLength`).
    #[serde(rename = "maxLength")]
    pub max_length: Option<u64>,
    /// Minimum string length (JSON Schema `minLength`).
    #[serde(rename = "minLength")]
    pub min_length: Option<u64>,
    /// Maximum array items (JSON Schema `maxItems`).
    #[serde(rename = "maxItems")]
    pub max_items: Option<u64>,
    /// Minimum array items (JSON Schema `minItems`).
    #[serde(rename = "minItems")]
    pub min_items: Option<u64>,
    /// Regex pattern for string validation (JSON Schema `pattern`).
    pub pattern: Option<String>,
    /// Maximum number of recipients (custom constraint for communication tools).
    pub max_recipients: Option<u32>,
    /// Maximum size in bytes (custom constraint for file/attachment limits).
    pub max_size_bytes: Option<u64>,
}

// ============================================================
// Circuit Breaker Configuration
// ============================================================

/// Per-server circuit breaker configuration, embedded in MCP manifest YAML.
///
/// Controls the state machine transitions: Closed → Open → HalfOpen.
/// See `docs/architecture.md` section 8.11 for specification.
///
/// ```yaml
/// circuit_breaker:
///   error_threshold: 5
///   error_window_secs: 60
///   latency_threshold_secs: 30
///   recovery_timeout_secs: 120
///   recovery_probes: 3
///   max_recovery_backoff_secs: 900
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

// ============================================================
// Identity Configuration (identity.md)
// ============================================================

/// Agent identity configuration, parsed from `config/identity.md`.
///
/// Supports markdown files with a title, personality section, and
/// behavioral boundaries section. The raw markdown is also preserved
/// for injection into the system prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Agent name (parsed from the markdown title).
    pub name: String,
    /// Agent personality description (bullet points from the Personality section).
    pub personality: String,
    /// Behavioral boundaries (bullet points from the Behavioral Boundaries section).
    pub boundaries: Vec<String>,
    /// The raw markdown content for direct system prompt injection.
    #[serde(default)]
    pub raw_markdown: String,
}

impl IdentityConfig {
    /// Parse identity config from a markdown string.
    ///
    /// Expected format:
    /// ```markdown
    /// # Agent Name
    ///
    /// Description text.
    ///
    /// ## Personality
    ///
    /// - Trait 1
    /// - Trait 2
    ///
    /// ## Behavioral Boundaries
    ///
    /// - Boundary 1
    /// - Boundary 2
    /// ```
    pub fn from_markdown(content: &str) -> Result<Self, crate::errors::StewardError> {
        let raw_markdown = content.to_string();

        // Parse the title (first # heading)
        let name = content
            .lines()
            .find(|line| line.starts_with("# ") && !line.starts_with("## "))
            .map(|line| line.trim_start_matches("# ").trim().to_string())
            .unwrap_or_default();

        // Split into sections by ## headings
        let sections = parse_markdown_sections(content);

        // Extract personality section
        let personality = sections.get("personality").cloned().unwrap_or_default();

        // Extract behavioral boundaries as bullet points
        let boundaries = sections
            .get("behavioral boundaries")
            .map(|s| {
                s.lines()
                    .filter(|line| line.starts_with("- "))
                    .map(|line| line.trim_start_matches("- ").trim().to_string())
                    .collect()
            })
            .unwrap_or_default();

        if name.is_empty() {
            return Err(crate::errors::StewardError::Config(
                "identity.md must have a title (# heading)".to_string(),
            ));
        }

        Ok(Self {
            name,
            personality,
            boundaries,
            raw_markdown,
        })
    }
}

/// Parse markdown into sections keyed by lowercase heading text.
fn parse_markdown_sections(content: &str) -> HashMap<String, String> {
    let mut sections: HashMap<String, String> = HashMap::new();
    let mut current_heading: Option<String> = None;
    let mut current_content = String::new();

    for line in content.lines() {
        if line.starts_with("## ") {
            // Save previous section
            if let Some(heading) = current_heading.take() {
                sections.insert(heading, current_content.trim().to_string());
            }
            current_heading = Some(line.trim_start_matches("## ").trim().to_lowercase());
            current_content = String::new();
        } else if current_heading.is_some() {
            current_content.push_str(line);
            current_content.push('\n');
        }
    }

    // Save last section
    if let Some(heading) = current_heading {
        sections.insert(heading, current_content.trim().to_string());
    }

    sections
}

// ============================================================
// Aggregate Config
// ============================================================

/// All configuration loaded from a config directory.
///
/// This is the aggregate returned by `ConfigLoader` and distributed
/// via `tokio::sync::watch` on hot-reload.
#[derive(Debug, Clone)]
pub struct StewardConfig {
    /// Permissions configuration.
    pub permissions: PermissionsConfig,
    /// Guardrails configuration.
    pub guardrails: GuardrailsConfig,
    /// MCP manifests, keyed by server name.
    pub mcp_manifests: HashMap<String, McpManifestConfig>,
    /// Agent identity.
    pub identity: IdentityConfig,
}

/// Event emitted when configuration changes are detected.
#[derive(Debug, Clone)]
pub enum ConfigChangeEvent {
    /// Permissions config was reloaded.
    PermissionsReloaded,
    /// Guardrails config was reloaded.
    GuardrailsReloaded,
    /// An MCP manifest was reloaded or added.
    McpManifestReloaded {
        /// Server name of the changed manifest.
        server: String,
    },
    /// Identity config was reloaded.
    IdentityReloaded,
    /// Full config reload (e.g., on initial load).
    FullReload,
}
