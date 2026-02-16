/// Unified error type for the Steward agent framework.
///
/// All modules use this error type for propagation across crate boundaries.
/// Internal module errors should be converted into the appropriate variant.
#[derive(Debug, thiserror::Error)]
pub enum StewardError {
    /// Error from the ingress sanitizer (content tagging, injection detection).
    #[error("ingress error: {0}")]
    Ingress(String),

    /// Error from the egress filter (PII detection, secret scanning, policy violation).
    #[error("egress error: {0}")]
    Egress(String),

    /// Error from the secret broker (encryption, decryption, token provisioning).
    #[error("secret broker error: {0}")]
    SecretBroker(String),

    /// Error from the leak detector (pattern scanning failures).
    #[error("leak detector error: {0}")]
    LeakDetector(String),

    /// Error from the audit logger (logging or query failures).
    #[error("audit error: {0}")]
    Audit(String),

    /// Error from the permission engine (manifest parsing, rate limiting).
    #[error("permission error: {0}")]
    Permission(String),

    /// Error from the guardian LLM (review failures, malformed verdicts).
    #[error("guardian error: {0}")]
    Guardian(String),

    /// Error from the memory subsystem (storage, search, provenance).
    #[error("memory error: {0}")]
    Memory(String),

    /// Error from the tool registry or tool execution.
    #[error("tool error: {0}")]
    Tool(String),

    /// Error from an MCP server or the MCP proxy.
    #[error("MCP error: {0}")]
    Mcp(String),

    /// Error from a channel adapter (WhatsApp, Telegram, etc.).
    #[error("channel error: {0}")]
    Channel(String),

    /// Error from an LLM provider (API call failures, deserialization).
    #[error("LLM provider error: {0}")]
    LlmProvider(String),

    /// Error from configuration loading or validation.
    #[error("config error: {0}")]
    Config(String),

    /// Database error (connection, query, migration).
    #[error("database error: {0}")]
    Database(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// Action was forbidden by policy.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Timeout waiting for a response (human approval, tool call, etc.).
    #[error("timeout: {0}")]
    Timeout(String),

    /// Serialization or deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Generic internal error for unexpected conditions.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Rate limit exceeded information, returned by the permission engine.
#[derive(Debug, Clone)]
pub struct RateLimitExceeded {
    /// The action that exceeded the limit.
    pub action: String,
    /// Seconds until the rate limit resets.
    pub retry_after_secs: u64,
    /// The configured limit that was exceeded.
    pub limit: String,
}

impl std::fmt::Display for RateLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rate limit exceeded for '{}': {} (retry after {}s)",
            self.action, self.limit, self.retry_after_secs
        )
    }
}

impl std::error::Error for RateLimitExceeded {}

impl From<serde_json::Error> for StewardError {
    fn from(err: serde_json::Error) -> Self {
        StewardError::Serialization(err.to_string())
    }
}

impl From<serde_yaml::Error> for StewardError {
    fn from(err: serde_yaml::Error) -> Self {
        StewardError::Serialization(err.to_string())
    }
}
