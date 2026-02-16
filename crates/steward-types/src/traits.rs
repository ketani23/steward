/// Trait contracts for all Steward subsystems.
///
/// Every module in the Steward framework implements one or more traits from this file.
/// This enables parallel development: modules code against these interfaces, not against
/// each other's concrete types. All traits are defined here in `steward-types` so that
/// every crate can depend on them without circular dependencies.
use async_trait::async_trait;

use crate::actions::*;
use crate::errors::{RateLimitExceeded, StewardError};

// ============================================================
// Security Subsystem Traits
// ============================================================

/// Preprocesses external content before it reaches the LLM.
///
/// Wraps content in source tags, detects injection patterns, escapes special characters,
/// and enforces context budget limits. This is the first line of defense against
/// prompt injection attacks.
#[async_trait]
pub trait IngressSanitizer: Send + Sync {
    /// Sanitize raw external content.
    ///
    /// Returns tagged, escaped content with detection metadata. Does NOT strip
    /// detected injections — flags them so the agent knows content was suspicious.
    async fn sanitize(&self, input: RawContent) -> Result<SanitizedContent, StewardError>;

    /// Check if content contains known injection patterns.
    ///
    /// Non-destructive scan that returns all detected patterns with confidence scores.
    async fn detect_injection(&self, input: &str) -> Result<Vec<InjectionDetection>, StewardError>;
}

/// Scans all outbound content for PII, secrets, and policy violations.
///
/// This is the last line of defense before content leaves the system. Every outbound
/// message, API call, and file write passes through this filter.
#[async_trait]
pub trait EgressFilter: Send + Sync {
    /// Scan outbound content.
    ///
    /// Returns a decision: Pass (clean), Block (contains sensitive data), or
    /// Warn (suspicious but allowed, flagged in audit log).
    async fn filter(&self, content: &OutboundContent) -> Result<EgressDecision, StewardError>;

    /// Register additional patterns to scan for (e.g., user-specific PII).
    fn register_pattern(&mut self, pattern: SensitivePattern);
}

/// Manages encrypted credential storage and scoped token provisioning.
///
/// The agent never sees raw credentials. The broker stores them encrypted and
/// injects them at call boundaries just before the outbound request is sent.
#[async_trait]
pub trait SecretBroker: Send + Sync {
    /// Store a credential in the encrypted vault.
    async fn store(&self, key: &str, credential: &EncryptedCredential) -> Result<(), StewardError>;

    /// Provision a scoped, time-limited token for a specific tool call.
    async fn provision_token(
        &self,
        key: &str,
        scope: &TokenScope,
    ) -> Result<ScopedToken, StewardError>;

    /// Inject credentials into an outbound request at the transport boundary.
    ///
    /// The credential is decrypted only at this point and exists in memory briefly.
    async fn inject_credentials(
        &self,
        request: &mut ToolRequest,
        key: &str,
    ) -> Result<(), StewardError>;
}

/// Scans I/O for credential patterns in both directions.
///
/// This runs on every I/O crossing a security boundary. It must be fast —
/// no async, no allocations on the hot path where possible.
pub trait LeakDetector: Send + Sync {
    /// Scan a string for credential patterns (API keys, tokens, passwords, private keys).
    ///
    /// Returns all detected leaks with pattern name, offset, length, and confidence.
    fn scan(&self, content: &str) -> Vec<LeakDetection>;

    /// Scan and redact — returns content with secrets replaced by `[REDACTED:{pattern_name}]`.
    fn redact(&self, content: &str) -> String;
}

/// Append-only audit logging for all system events.
///
/// Every action, decision, and blocked attempt is logged. The audit trail is
/// append-only — no updates or deletes are permitted.
#[async_trait]
pub trait AuditLogger: Send + Sync {
    /// Log an audit event. Must be append-only — no updates or deletes.
    async fn log(&self, event: AuditEvent) -> Result<(), StewardError>;

    /// Query audit events with filters. Read-only.
    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>, StewardError>;
}

// ============================================================
// Permission Subsystem Traits
// ============================================================

/// Evaluates proposed actions against the declarative permission manifest.
///
/// Actions are classified into permission tiers (AutoExecute, LogAndExecute,
/// HumanApproval, Forbidden) based on YAML configuration. Unknown actions
/// default to HumanApproval (fail-closed).
#[async_trait]
pub trait PermissionEngine: Send + Sync {
    /// Classify an action into a permission tier based on the manifest.
    fn classify(&self, action: &ActionProposal) -> PermissionTier;

    /// Check rate limits for an action.
    ///
    /// Returns Ok if within limits, Err with retry information if exceeded.
    async fn check_rate_limit(&self, action: &ActionProposal) -> Result<(), RateLimitExceeded>;

    /// Reload permission manifest from disk (hot-reload support).
    async fn reload_manifest(&mut self) -> Result<(), StewardError>;
}

// ============================================================
// Guardian Trait
// ============================================================

/// Secondary LLM that reviews every proposed action before execution.
///
/// The guardian operates on a clean, distilled summary of the action — it never
/// sees the raw external content that the primary agent processed. This architectural
/// separation is key to its injection resistance.
#[async_trait]
pub trait Guardian: Send + Sync {
    /// Review a proposed action.
    ///
    /// Returns ALLOW, BLOCK, or ESCALATE_TO_HUMAN with reasoning. If the guardian's
    /// output is malformed, implementations should default to EscalateToHuman (fail safe).
    async fn review(
        &self,
        proposal: &GuardianReviewRequest,
    ) -> Result<GuardianVerdict, StewardError>;
}

// ============================================================
// Memory Subsystem Traits
// ============================================================

/// Persistent memory storage with provenance tracking.
///
/// Every memory entry is tagged with its origin (UserInstruction, AgentObservation,
/// ExternalContent, ToolResult) and has a trust score that influences search ranking.
#[async_trait]
pub trait MemoryStore: Send + Sync {
    /// Store a memory entry with provenance metadata.
    ///
    /// Generates a UUID if the entry's id is None.
    async fn store(&self, entry: MemoryEntry) -> Result<MemoryId, StewardError>;

    /// Retrieve a memory entry by ID.
    async fn get(&self, id: &MemoryId) -> Result<Option<MemoryEntry>, StewardError>;

    /// Update trust score for a memory entry.
    ///
    /// Will reject updates to immutable core memories (UserInstruction with trust_score=1.0).
    async fn update_trust(&self, id: &MemoryId, score: f64) -> Result<(), StewardError>;
}

/// Hybrid full-text + vector search over memory.
///
/// Combines PostgreSQL full-text search with pgvector similarity search,
/// fused using Reciprocal Rank Fusion (RRF).
#[async_trait]
pub trait MemorySearch: Send + Sync {
    /// Search memory using hybrid FTS + vector search with RRF scoring.
    ///
    /// Results are ranked by combined score, weighted by trust score.
    async fn search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MemorySearchResult>, StewardError>;
}

// ============================================================
// Tool Subsystem Traits
// ============================================================

/// Central registry for all tools (built-in, WASM, MCP).
///
/// Provides a unified interface for tool discovery and execution, routing calls
/// to the correct backend (direct call, WASM sandbox, or MCP proxy).
#[async_trait]
pub trait ToolRegistry: Send + Sync {
    /// List all available tools (filtered by permissions).
    async fn list_tools(&self) -> Result<Vec<ToolDefinition>, StewardError>;

    /// Execute a tool call, routing to the correct backend.
    async fn execute(&self, call: ToolCall) -> Result<ToolResult, StewardError>;

    /// Register a new tool (from MCP discovery, WASM deployment, etc.).
    async fn register(&mut self, tool: ToolDefinition) -> Result<(), StewardError>;
}

/// MCP capability manifest parser and enforcer.
///
/// Each MCP server has a YAML manifest that declares which tools the agent
/// can call, with what parameters, at what rate.
pub trait McpManifest: Send + Sync {
    /// Load manifest from YAML file.
    fn load(path: &std::path::Path) -> Result<Self, StewardError>
    where
        Self: Sized;

    /// Check if a tool call is allowed by this manifest.
    fn check_tool_call(&self, tool_name: &str, params: &serde_json::Value) -> ManifestDecision;

    /// Filter a tools/list response, removing blocked tools and rewriting schemas.
    fn filter_tool_list(&self, tools: Vec<McpToolDef>) -> Vec<McpToolDef>;
}

/// MCP transport abstraction — unifies stdio and HTTP/SSE transports.
///
/// The proxy uses this trait to communicate with MCP servers regardless of
/// their transport mechanism.
#[async_trait]
pub trait McpTransport: Send + Sync {
    /// Send a JSON-RPC message to the MCP server.
    async fn send(&mut self, message: JsonRpcMessage) -> Result<(), StewardError>;

    /// Receive the next JSON-RPC message from the MCP server.
    async fn recv(&mut self) -> Result<JsonRpcMessage, StewardError>;

    /// Close the transport connection.
    async fn close(&mut self) -> Result<(), StewardError>;

    /// Check if the transport is still connected.
    fn is_connected(&self) -> bool;
}

/// Circuit breaker for MCP server connections.
///
/// Implements the Closed → Open → HalfOpen state machine with configurable
/// thresholds, timeouts, and exponential backoff.
pub trait CircuitBreaker: Send + Sync {
    /// Record a successful call.
    fn record_success(&mut self);

    /// Record a failed call.
    fn record_failure(&mut self);

    /// Check if the circuit is open (broken), half-open, or closed (healthy).
    fn state(&self) -> CircuitState;

    /// Attempt a probe call (when half-open). Returns true if probe is allowed.
    fn attempt_probe(&mut self) -> bool;
}

// ============================================================
// Channel Traits
// ============================================================

/// Adapter for a communication channel (WhatsApp, Telegram, Slack, etc.).
///
/// Each channel implementation handles the platform-specific protocol for
/// sending/receiving messages and requesting human approval.
#[async_trait]
pub trait ChannelAdapter: Send + Sync {
    /// Send a message through this channel.
    async fn send_message(&self, message: OutboundMessage) -> Result<(), StewardError>;

    /// Start listening for inbound messages. Returns a receiver stream.
    async fn start_listening(
        &mut self,
    ) -> Result<tokio::sync::mpsc::Receiver<InboundMessage>, StewardError>;

    /// Request human approval for an action. Returns the user's decision.
    async fn request_approval(
        &self,
        request: ApprovalRequest,
    ) -> Result<ApprovalResponse, StewardError>;
}

// ============================================================
// LLM Provider Trait
// ============================================================

/// Provider-agnostic LLM interface.
///
/// Supports multiple LLM providers (Anthropic, OpenAI, Ollama, etc.) with a
/// unified interface for completions and tool-use.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Send a completion request. Returns the model's response.
    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, StewardError>;

    /// Send a completion request with tool definitions.
    ///
    /// Returns response with potential tool calls.
    async fn complete_with_tools(
        &self,
        request: CompletionRequest,
        tools: &[ToolDefinition],
    ) -> Result<CompletionResponse, StewardError>;
}
