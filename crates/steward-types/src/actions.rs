/// Shared data types used across all Steward subsystems.
///
/// These types are the lingua franca of the system — every module imports from here.
/// Parallel development is possible because all modules agree on these structures.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================
// Core Action Types
// ============================================================

/// A proposed action from the primary agent, awaiting guardian review and permission check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionProposal {
    /// Unique identifier for this proposal.
    pub id: Uuid,
    /// Name of the tool to invoke (e.g., "gmail.send", "shell.exec").
    pub tool_name: String,
    /// Parameters for the tool call as a JSON value.
    pub parameters: serde_json::Value,
    /// The agent's reasoning for proposing this action.
    pub reasoning: String,
    /// ID of the user message that triggered this action.
    pub user_message_id: Uuid,
    /// When this proposal was created.
    pub timestamp: DateTime<Utc>,
}

/// Permission tier for an action, determining the approval workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionTier {
    /// Safe read-only operations — execute immediately.
    AutoExecute,
    /// Low-risk writes — execute but log for audit.
    LogAndExecute,
    /// High-risk actions — require explicit human approval before execution.
    HumanApproval,
    /// Hard-blocked regardless of LLM output — never permitted.
    Forbidden,
}

// ============================================================
// Guardian Types
// ============================================================

/// Request sent to the guardian LLM for action review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianReviewRequest {
    /// The user's original message (text only, no raw external content).
    pub user_message: String,
    /// The proposed action to review.
    pub proposal: ActionProposal,
    /// Summary of the current permission policy.
    pub permission_context: String,
}

/// Guardian's verdict on a proposed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianVerdict {
    /// The guardian's decision.
    pub decision: GuardianDecision,
    /// Reasoning behind the decision.
    pub reasoning: String,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Specific injection indicators detected, if any.
    pub injection_indicators: Vec<String>,
    /// When this verdict was issued.
    pub timestamp: DateTime<Utc>,
}

/// Guardian decision outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardianDecision {
    /// Action appears safe and matches user intent.
    Allow,
    /// Action appears suspicious or dangerous — do not execute.
    Block,
    /// Uncertain — escalate to human for decision.
    EscalateToHuman,
}

// ============================================================
// Audit Types
// ============================================================

/// An event logged to the append-only audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub id: Uuid,
    /// When this event occurred.
    pub timestamp: DateTime<Utc>,
    /// Category of the event.
    pub event_type: AuditEventType,
    /// The action proposal, if this event is action-related.
    pub action: Option<ActionProposal>,
    /// Guardian verdict, if the guardian reviewed this action.
    pub guardian_verdict: Option<GuardianVerdict>,
    /// Permission tier assigned to the action.
    pub permission_tier: Option<PermissionTier>,
    /// Outcome of the action.
    pub outcome: ActionOutcome,
    /// Additional metadata as a JSON value.
    pub metadata: serde_json::Value,
}

/// Categories of audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// A tool was called.
    ToolCall,
    /// The guardian reviewed an action.
    GuardianReview,
    /// A permission check was performed.
    PermissionCheck,
    /// The egress filter blocked outbound content.
    EgressBlock,
    /// The ingress sanitizer detected a potential injection.
    IngressDetection,
    /// A rate limit was hit.
    RateLimitHit,
    /// A circuit breaker tripped.
    CircuitBreakerTrip,
    /// An MCP server event (connect, disconnect, error).
    McpServerEvent,
    /// A user approved or rejected an action.
    UserApproval,
}

/// Outcome of an action after passing through the security pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionOutcome {
    /// Action was executed successfully.
    Executed,
    /// Action was blocked (by guardian, permissions, or egress filter).
    Blocked {
        /// Why the action was blocked.
        reason: String,
    },
    /// Action is pending human approval.
    Pending,
    /// Action execution failed.
    Failed {
        /// Error description.
        error: String,
    },
    /// Action timed out waiting for approval or execution.
    TimedOut,
}

/// Filter criteria for querying audit events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter by time range start (inclusive).
    pub from: Option<DateTime<Utc>>,
    /// Filter by time range end (exclusive).
    pub to: Option<DateTime<Utc>>,
    /// Filter by event type.
    pub event_type: Option<AuditEventType>,
    /// Filter by action outcome.
    pub outcome: Option<String>,
    /// Filter by tool name.
    pub tool_name: Option<String>,
    /// Maximum number of results.
    pub limit: Option<usize>,
}

// ============================================================
// Ingress / Egress Types
// ============================================================

/// Raw content from an external source, before sanitization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawContent {
    /// The raw content text.
    pub text: String,
    /// Source of the content (e.g., "email", "whatsapp", "web").
    pub source: String,
    /// Sender identifier, if applicable.
    pub sender: Option<String>,
    /// Additional metadata about the content.
    pub metadata: serde_json::Value,
}

/// Content that has been sanitized by the ingress sanitizer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizedContent {
    /// The sanitized text with source tags and escaped content.
    pub text: String,
    /// Injection detections found during sanitization.
    pub detections: Vec<InjectionDetection>,
    /// Whether the content was truncated due to context budget.
    pub truncated: bool,
    /// Original source metadata.
    pub source: String,
}

/// A detected injection pattern in incoming content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionDetection {
    /// Name of the detected pattern (e.g., "ignore_instructions", "role_play_attack").
    pub pattern_name: String,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// The matched text snippet.
    pub matched_text: String,
    /// Byte offset in the original content.
    pub offset: usize,
}

/// Content about to leave the system (message, API call, file write).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundContent {
    /// The content to be sent.
    pub text: String,
    /// Type of outbound action (e.g., "email.send", "message.send", "file.write").
    pub action_type: String,
    /// Intended recipient, if applicable.
    pub recipient: Option<String>,
    /// Additional metadata.
    pub metadata: serde_json::Value,
}

/// Decision from the egress filter about outbound content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EgressDecision {
    /// Content is clean — allow it through.
    Pass,
    /// Content contains sensitive data — block it.
    Block {
        /// Reason for blocking.
        reason: String,
        /// Patterns that triggered the block.
        patterns_found: Vec<String>,
    },
    /// Content is suspicious but allowed — flag in audit log.
    Warn {
        /// Reason for the warning.
        reason: String,
    },
}

/// A pattern to scan for in outbound content (registered at runtime).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitivePattern {
    /// Human-readable name for this pattern.
    pub name: String,
    /// Regex pattern to match.
    pub pattern: String,
    /// Severity level.
    pub severity: PatternSeverity,
}

/// Severity of a detected sensitive pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternSeverity {
    /// Low severity — log and warn.
    Low,
    /// Medium severity — warn and may block depending on policy.
    Medium,
    /// High severity — always block.
    High,
    /// Critical severity — block and alert.
    Critical,
}

// ============================================================
// Leak Detection Types
// ============================================================

/// A detected credential or secret leak.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakDetection {
    /// Name of the pattern that matched (e.g., "aws_access_key", "github_token").
    pub pattern_name: String,
    /// Byte offset in the scanned content.
    pub offset: usize,
    /// Length of the matched content in bytes.
    pub length: usize,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
}

// ============================================================
// Secret Broker Types
// ============================================================

/// An encrypted credential stored in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedCredential {
    /// The encrypted credential data.
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption.
    pub nonce: Vec<u8>,
    /// Identifier for the encryption key used.
    pub key_id: String,
    /// When this credential was stored.
    pub created_at: DateTime<Utc>,
    /// When this credential expires, if applicable.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Scope for a provisioned token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenScope {
    /// Which tool this token is valid for.
    pub tool_name: String,
    /// Which endpoint or operation, if applicable.
    pub endpoint: Option<String>,
    /// How long the token is valid (in seconds).
    pub ttl_secs: u64,
    /// Whether the token can only be used once.
    pub single_use: bool,
}

/// A scoped, time-limited token provisioned by the secret broker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedToken {
    /// Unique token identifier.
    pub token_id: Uuid,
    /// Reference to the underlying credential (not the raw value).
    pub credential_key: String,
    /// Scope constraints.
    pub scope: TokenScope,
    /// When this token expires.
    pub expires_at: DateTime<Utc>,
    /// Whether this token has been used (for single-use tokens).
    pub used: bool,
}

/// A request to a tool, which may need credential injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRequest {
    /// Name of the tool being called.
    pub tool_name: String,
    /// Parameters for the tool call.
    pub parameters: serde_json::Value,
    /// Headers to include in the request (for HTTP-based tools).
    pub headers: std::collections::HashMap<String, String>,
}

// ============================================================
// Memory Types
// ============================================================

/// A memory entry with provenance tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    /// Unique identifier (None for new entries, assigned on store).
    pub id: Option<MemoryId>,
    /// The memory content text.
    pub content: String,
    /// How this memory was created.
    pub provenance: MemoryProvenance,
    /// Trust score (0.0 to 1.0). Higher = more trusted.
    pub trust_score: f64,
    /// When this memory was created.
    pub created_at: DateTime<Utc>,
    /// Vector embedding for similarity search (None if not yet computed).
    pub embedding: Option<Vec<f32>>,
}

/// How a memory entry was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryProvenance {
    /// Directly from a user instruction or statement.
    UserInstruction,
    /// Inferred or observed by the agent.
    AgentObservation,
    /// Derived from external content (email, web page, etc.).
    ExternalContent,
    /// Result of a tool execution.
    ToolResult,
}

/// Type alias for memory entry IDs.
pub type MemoryId = Uuid;

/// A memory search result with scoring information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySearchResult {
    /// The matching memory entry.
    pub entry: MemoryEntry,
    /// Combined RRF score.
    pub score: f64,
    /// Rank from full-text search (None if not found via FTS).
    pub fts_rank: Option<usize>,
    /// Rank from vector search (None if not found via vector search).
    pub vector_rank: Option<usize>,
}

// ============================================================
// Tool Types
// ============================================================

/// Definition of a tool available in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Unique name of the tool (e.g., "gmail.send", "shell.exec").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema describing the tool's input parameters.
    pub input_schema: serde_json::Value,
    /// Where this tool comes from.
    pub source: ToolSource,
    /// Default permission tier for this tool.
    pub permission_tier: PermissionTier,
}

/// Source/backend of a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolSource {
    /// A built-in, trusted tool running in-process.
    BuiltIn,
    /// A WASM-sandboxed tool with capability manifest.
    Wasm {
        /// Path to the WASM module.
        module_path: String,
    },
    /// A tool provided by an MCP server through the proxy.
    Mcp {
        /// Name of the MCP server providing this tool.
        server_name: String,
    },
}

/// A request to call a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Name of the tool to call.
    pub tool_name: String,
    /// Parameters for the call.
    pub parameters: serde_json::Value,
    /// ID of the action proposal that triggered this call.
    pub proposal_id: Uuid,
}

/// Result of a tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Whether the call succeeded.
    pub success: bool,
    /// The output content from the tool.
    pub output: serde_json::Value,
    /// Error message if the call failed.
    pub error: Option<String>,
}

// ============================================================
// MCP Types
// ============================================================

/// A JSON-RPC 2.0 message for MCP communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcMessage {
    /// JSON-RPC version (always "2.0").
    pub jsonrpc: String,
    /// Request ID (None for notifications).
    pub id: Option<serde_json::Value>,
    /// Method name (for requests/notifications).
    pub method: Option<String>,
    /// Parameters (for requests/notifications).
    pub params: Option<serde_json::Value>,
    /// Result (for responses).
    pub result: Option<serde_json::Value>,
    /// Error (for error responses).
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code.
    pub code: i64,
    /// Error message.
    pub message: String,
    /// Additional error data.
    pub data: Option<serde_json::Value>,
}

/// An MCP tool definition as returned by `tools/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDef {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: Option<String>,
    /// JSON Schema for the tool's input.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Decision from the MCP manifest about a tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ManifestDecision {
    /// Tool call is allowed.
    Allow,
    /// Tool call is blocked.
    Block {
        /// Reason for blocking.
        reason: String,
    },
    /// Rate limit exceeded for this tool.
    RateLimit {
        /// Seconds until the rate limit resets.
        retry_after_secs: u64,
    },
}

/// Circuit breaker states for MCP server connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Healthy — calls flowing normally.
    Closed,
    /// Broken — calls rejected, waiting for recovery timeout.
    Open,
    /// Testing — limited probe calls allowed to check recovery.
    HalfOpen,
}

/// Metrics snapshot from a circuit breaker instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerMetrics {
    /// Total number of recorded successes.
    pub total_successes: u64,
    /// Total number of recorded failures.
    pub total_failures: u64,
    /// Milliseconds spent in the current state.
    pub time_in_current_state_ms: u64,
    /// Number of times the circuit has tripped from Closed to Open.
    pub trips_count: u64,
    /// Current circuit state.
    pub current_state: CircuitState,
}

// ============================================================
// Channel Types
// ============================================================

/// A message received from a communication channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundMessage {
    /// Unique message identifier.
    pub id: Uuid,
    /// The message text content.
    pub text: String,
    /// Which channel this came from.
    pub channel: ChannelType,
    /// Sender identifier.
    pub sender: String,
    /// When the message was received.
    pub timestamp: DateTime<Utc>,
    /// Additional channel-specific metadata.
    pub metadata: serde_json::Value,
}

/// A message to send through a communication channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundMessage {
    /// Recipient identifier.
    pub recipient: String,
    /// The message text content.
    pub text: String,
    /// Which channel to send through.
    pub channel: ChannelType,
    /// Additional channel-specific metadata.
    pub metadata: serde_json::Value,
}

/// Supported communication channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    /// WhatsApp Business API.
    WhatsApp,
    /// Telegram Bot API.
    Telegram,
    /// Slack.
    Slack,
    /// Web chat interface.
    WebChat,
}

/// A request for human approval of an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// The action proposal requiring approval.
    pub proposal: ActionProposal,
    /// Guardian's verdict on this action.
    pub guardian_verdict: GuardianVerdict,
    /// The permission tier that triggered approval.
    pub permission_tier: PermissionTier,
    /// Which channel to request approval through.
    pub channel: ChannelType,
    /// Timeout in seconds before the approval expires.
    pub timeout_secs: u64,
}

/// User's response to an approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    /// Whether the user approved the action.
    pub approved: bool,
    /// Optional message from the user (e.g., modifications).
    pub message: Option<String>,
    /// When the response was received.
    pub timestamp: DateTime<Utc>,
}

// ============================================================
// LLM Types
// ============================================================

/// A request to an LLM for completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    /// System prompt.
    pub system: String,
    /// Conversation messages.
    pub messages: Vec<ChatMessage>,
    /// Model identifier (e.g., "claude-sonnet-4-5-20250929", "llama3").
    pub model: String,
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// Temperature for sampling.
    pub temperature: Option<f64>,
}

/// A message in a chat conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Role of the message author.
    pub role: ChatRole,
    /// Content of the message.
    pub content: String,
}

/// Roles in a chat conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatRole {
    /// The user sending the message.
    User,
    /// The AI assistant.
    Assistant,
}

/// Response from an LLM completion request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    /// The generated text content.
    pub content: String,
    /// Tool use blocks, if the model wants to call tools.
    pub tool_calls: Vec<ToolCallRequest>,
    /// Model identifier that generated this response.
    pub model: String,
    /// Token usage statistics.
    pub usage: TokenUsage,
}

/// A tool call requested by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRequest {
    /// Tool call ID (for matching with results).
    pub id: String,
    /// Name of the tool to call.
    pub tool_name: String,
    /// Arguments for the tool call.
    pub arguments: serde_json::Value,
}

/// Token usage statistics from an LLM call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Tokens in the input prompt.
    pub input_tokens: u32,
    /// Tokens in the generated output.
    pub output_tokens: u32,
}
