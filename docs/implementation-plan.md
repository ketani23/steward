# Project Steward: Implementation Plan

> **Purpose:** Executable task breakdown for building Steward using parallel Claude Code instances with git worktrees.
> **Companion doc:** `docs/architecture.md` (full design rationale)
> **Workflow:** Parallel worktree branches → overnight Claude Code runs → PR review in the morning

---

## How This Plan Works

Each **batch** contains tasks that can run in parallel across separate git worktrees. Within a batch, tasks have no compile-time dependencies on each other — they code against shared trait contracts defined in Phase 0.

**Task card format:**

```
TASK-{batch}.{number}: {Name}
Branch:      feat/{branch-name}
Files:       {files to create/modify}
Depends on:  {prior tasks that must be merged first}
Tests:       {what the test suite should cover}
Prompt:      {what to tell Claude Code}
```

---

## Phase 0: Project Skeleton (Single Claude Code Session — You + Claude Code Together)

**Goal:** Create the Cargo workspace, all module stubs, trait contracts, CI pipeline, and configuration scaffolding. This is the foundation that enables all parallel work. Do this in a single session on `main`.

### 0.1 Cargo Workspace Structure

```
steward/
├── Cargo.toml                  # Workspace root
├── CLAUDE.md                   # Claude Code project instructions
├── .github/
│   └── workflows/
│       └── ci.yml              # CI on push + PR
│
├── crates/
│   ├── steward-core/          # Agent loop, guardian, permissions, router
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── agent.rs
│   │       ├── guardian.rs
│   │       ├── permissions.rs
│   │       ├── router.rs
│   │       ├── scheduler.rs
│   │       └── worker.rs
│   │
│   ├── steward-security/      # Ingress, egress, secrets, leak detection, audit
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── ingress.rs
│   │       ├── egress.rs
│   │       ├── secret_broker.rs
│   │       ├── leak_detector.rs
│   │       └── audit.rs
│   │
│   ├── steward-memory/        # PostgreSQL workspace, search, provenance
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── workspace.rs
│   │       ├── search.rs
│   │       ├── provenance.rs
│   │       └── integrity.rs
│   │
│   ├── steward-tools/         # Tool registry, MCP proxy, WASM sandbox, staging
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── registry.rs
│   │       ├── mcp/
│   │       │   ├── mod.rs
│   │       │   ├── proxy.rs
│   │       │   ├── manifest.rs
│   │       │   ├── schema_rewrite.rs
│   │       │   ├── circuit_breaker.rs
│   │       │   ├── introspect.rs
│   │       │   ├── transport_stdio.rs
│   │       │   └── transport_http.rs
│   │       ├── wasm_sandbox.rs
│   │       ├── staging.rs
│   │       ├── subagent.rs
│   │       └── built_in/
│   │           ├── mod.rs
│   │           └── shell.rs
│   │
│   ├── steward-channels/      # Channel adapters (WhatsApp, Telegram, etc.)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── manager.rs
│   │       ├── whatsapp.rs
│   │       ├── telegram.rs
│   │       └── confirmation.rs
│   │
│   └── steward-types/         # Shared types, traits, error types
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── traits.rs       # ★ ALL TRAIT CONTRACTS LIVE HERE ★
│           ├── actions.rs      # ActionProposal, ActionResult, PermissionTier
│           ├── config.rs       # Config types (permissions, manifests, etc.)
│           └── errors.rs       # Shared error types
│
├── config/                     # Default configuration files
│   ├── permissions.yaml
│   ├── guardrails.yaml
│   └── identity.md
│
├── docs/
│   ├── architecture.md         # Full architecture document
│   └── implementation-plan.md  # This file
│
├── deploy/
│   ├── Dockerfile
│   └── docker-compose.yml
│
└── tests/
    ├── integration/
    └── injection_suite/
```

### 0.2 Why a `steward-types` Crate?

This is the keystone for parallel development. Every module depends on `steward-types` but not on each other. The types crate contains:

- **Trait definitions** that modules implement
- **Shared data structures** (ActionProposal, GuardianVerdict, AuditEvent, etc.)
- **Error types** with `thiserror`

When Claude Code works on `steward-security/egress.rs`, it implements the `EgressFilter` trait from `steward-types`. When another instance works on `steward-tools/mcp/proxy.rs`, it also imports from `steward-types`. Neither needs the other's code to compile.

### 0.3 Trait Contracts (steward-types/src/traits.rs)

These are the interfaces that every module codes against. Define them all in Phase 0 before any parallel work begins.

```rust
// ============================================================
// steward-types/src/traits.rs
//
// Trait contracts for all Steward subsystems.
// Parallel implementations code against these interfaces.
// ============================================================

use async_trait::async_trait;
use crate::actions::*;
use crate::errors::StewardError;

// ---- Security Subsystem Traits ----

/// Preprocesses external content before it reaches the LLM.
/// Wraps content in source tags, detects injection patterns, escapes special chars.
#[async_trait]
pub trait IngressSanitizer: Send + Sync {
    /// Sanitize raw external content. Returns tagged, escaped content with detection metadata.
    async fn sanitize(&self, input: RawContent) -> Result<SanitizedContent, StewardError>;

    /// Check if content contains known injection patterns. Non-destructive scan.
    async fn detect_injection(&self, input: &str) -> Result<Vec<InjectionDetection>, StewardError>;
}

/// Scans all outbound content for PII, secrets, and policy violations.
/// Last line of defense before content leaves the system.
#[async_trait]
pub trait EgressFilter: Send + Sync {
    /// Scan outbound content. Returns filtered content or a block decision with reason.
    async fn filter(&self, content: &OutboundContent) -> Result<EgressDecision, StewardError>;

    /// Register additional patterns to scan for (e.g., user-specific PII).
    fn register_pattern(&mut self, pattern: SensitivePattern);
}

/// Manages encrypted credential storage and scoped token provisioning.
/// The agent never sees raw credentials — the broker injects them at call boundaries.
#[async_trait]
pub trait SecretBroker: Send + Sync {
    /// Store a credential in the encrypted vault.
    async fn store(&self, key: &str, credential: &EncryptedCredential) -> Result<(), StewardError>;

    /// Provision a scoped, time-limited token for a specific tool call.
    async fn provision_token(&self, key: &str, scope: &TokenScope) -> Result<ScopedToken, StewardError>;

    /// Inject credentials into an outbound request at the transport boundary.
    async fn inject_credentials(&self, request: &mut ToolRequest, key: &str) -> Result<(), StewardError>;
}

/// Scans I/O for credential patterns in both directions.
#[async_trait]
pub trait LeakDetector: Send + Sync {
    /// Scan a string for credential patterns (API keys, tokens, passwords, private keys).
    fn scan(&self, content: &str) -> Vec<LeakDetection>;

    /// Scan and redact — returns content with secrets replaced by [REDACTED].
    fn redact(&self, content: &str) -> String;
}

/// Append-only audit logging for all system events.
#[async_trait]
pub trait AuditLogger: Send + Sync {
    /// Log an audit event. Must be append-only — no updates or deletes.
    async fn log(&self, event: AuditEvent) -> Result<(), StewardError>;

    /// Query audit events with filters. Read-only.
    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>, StewardError>;
}

// ---- Permission Subsystem Traits ----

/// Evaluates proposed actions against the declarative permission manifest.
#[async_trait]
pub trait PermissionEngine: Send + Sync {
    /// Classify an action into a permission tier.
    fn classify(&self, action: &ActionProposal) -> PermissionTier;

    /// Check rate limits for an action. Returns Ok if within limits, Err if exceeded.
    async fn check_rate_limit(&self, action: &ActionProposal) -> Result<(), RateLimitExceeded>;

    /// Reload permission manifest from disk (hot-reload support).
    async fn reload_manifest(&mut self) -> Result<(), StewardError>;
}

// ---- Guardian Trait ----

/// Secondary LLM that reviews every proposed action before execution.
/// Operates on a clean, distilled summary — never sees raw external content.
#[async_trait]
pub trait Guardian: Send + Sync {
    /// Review a proposed action. Returns ALLOW, BLOCK, or ESCALATE_TO_HUMAN with reasoning.
    async fn review(&self, proposal: &GuardianReviewRequest) -> Result<GuardianVerdict, StewardError>;
}

// ---- Memory Subsystem Traits ----

/// Persistent memory storage with provenance tracking.
#[async_trait]
pub trait MemoryStore: Send + Sync {
    /// Store a memory entry with provenance metadata.
    async fn store(&self, entry: MemoryEntry) -> Result<MemoryId, StewardError>;

    /// Retrieve a memory entry by ID.
    async fn get(&self, id: &MemoryId) -> Result<Option<MemoryEntry>, StewardError>;

    /// Update trust score for a memory entry.
    async fn update_trust(&self, id: &MemoryId, score: f64) -> Result<(), StewardError>;
}

/// Hybrid full-text + vector search over memory.
#[async_trait]
pub trait MemorySearch: Send + Sync {
    /// Search memory using hybrid FTS + vector search with RRF scoring.
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<MemorySearchResult>, StewardError>;
}

// ---- Tool Subsystem Traits ----

/// Central registry for all tools (built-in, WASM, MCP).
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
pub trait McpManifest: Send + Sync {
    /// Load manifest from YAML file.
    fn load(path: &std::path::Path) -> Result<Self, StewardError> where Self: Sized;

    /// Check if a tool call is allowed by this manifest.
    fn check_tool_call(&self, tool_name: &str, params: &serde_json::Value) -> ManifestDecision;

    /// Filter a tools/list response, removing blocked tools and rewriting schemas.
    fn filter_tool_list(&self, tools: Vec<McpToolDef>) -> Vec<McpToolDef>;
}

/// MCP transport abstraction — unifies stdio and HTTP/SSE transports.
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
pub trait CircuitBreaker: Send + Sync {
    /// Record a successful call.
    fn record_success(&mut self);

    /// Record a failed call.
    fn record_failure(&mut self);

    /// Check if the circuit is open (broken), half-open, or closed (healthy).
    fn state(&self) -> CircuitState;

    /// Attempt a probe call (when half-open).
    fn attempt_probe(&mut self) -> bool;
}

// ---- Channel Traits ----

/// Adapter for a communication channel (WhatsApp, Telegram, etc.).
#[async_trait]
pub trait ChannelAdapter: Send + Sync {
    /// Send a message through this channel.
    async fn send_message(&self, message: OutboundMessage) -> Result<(), StewardError>;

    /// Start listening for inbound messages. Returns a receiver stream.
    async fn start_listening(&mut self) -> Result<tokio::sync::mpsc::Receiver<InboundMessage>, StewardError>;

    /// Request human approval for an action. Returns the user's decision.
    async fn request_approval(&self, request: ApprovalRequest) -> Result<ApprovalResponse, StewardError>;
}

// ---- LLM Provider Trait ----

/// Provider-agnostic LLM interface.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Send a completion request. Returns the model's response.
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, StewardError>;

    /// Send a completion request with tool definitions. Returns response with potential tool calls.
    async fn complete_with_tools(
        &self,
        request: CompletionRequest,
        tools: &[ToolDefinition],
    ) -> Result<CompletionResponse, StewardError>;
}
```

### 0.4 Shared Data Types (steward-types/src/actions.rs)

```rust
// Core action types used across all modules.
// Define these in Phase 0 — parallel workers need them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A proposed action from the primary agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionProposal {
    pub id: Uuid,
    pub tool_name: String,
    pub parameters: serde_json::Value,
    pub reasoning: String,
    pub user_message_id: Uuid,
    pub timestamp: DateTime<Utc>,
}

/// Permission tier for an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionTier {
    AutoExecute,
    LogAndExecute,
    HumanApproval,
    Forbidden,
}

/// Guardian's verdict on a proposed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianVerdict {
    pub decision: GuardianDecision,
    pub reasoning: String,
    pub confidence: f64,
    pub injection_indicators: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardianDecision {
    Allow,
    Block,
    EscalateToHuman,
}

/// An event logged to the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub action: Option<ActionProposal>,
    pub guardian_verdict: Option<GuardianVerdict>,
    pub permission_tier: Option<PermissionTier>,
    pub outcome: ActionOutcome,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    ToolCall,
    GuardianReview,
    PermissionCheck,
    EgressBlock,
    IngressDetection,
    RateLimitHit,
    CircuitBreakerTrip,
    McpServerEvent,
    UserApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionOutcome {
    Executed,
    Blocked { reason: String },
    Pending,
    Failed { error: String },
    TimedOut,
}

/// Memory entry with provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: Option<MemoryId>,
    pub content: String,
    pub provenance: MemoryProvenance,
    pub trust_score: f64,
    pub created_at: DateTime<Utc>,
    pub embedding: Option<Vec<f32>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MemoryProvenance {
    UserInstruction,
    AgentObservation,
    ExternalContent,
    ToolResult,
}

pub type MemoryId = Uuid;

/// Circuit breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,   // Healthy — calls flowing normally
    Open,     // Broken — calls rejected
    HalfOpen, // Testing — limited probes allowed
}

// ... (additional types for RawContent, SanitizedContent, OutboundContent,
//      EgressDecision, SensitivePattern, ToolCall, ToolResult, ToolDefinition,
//      JsonRpcMessage, McpToolDef, ManifestDecision, InboundMessage,
//      OutboundMessage, CompletionRequest, CompletionResponse, etc.)
//
// Each parallel task will need specific types — flesh these out as stubs
// with TODO markers in Phase 0. Workers can expand them as needed.
```

### 0.5 CI Pipeline (.github/workflows/ci.yml)

```yaml
name: CI

on:
  push:
    branches: ['main', 'feat/**']
  pull_request:
    branches: ['main']

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  check:
    name: Check + Test
    runs-on: ubuntu-latest
    services:
      postgres:
        image: pgvector/pgvector:pg16
        env:
          POSTGRES_USER: steward
          POSTGRES_PASSWORD: steward_test
          POSTGRES_DB: steward_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2
      - name: Check formatting
        run: cargo fmt --all -- --check
      - name: Clippy
        run: cargo clippy --all-targets --all-features
      - name: Build
        run: cargo build --all-targets
      - name: Unit tests
        run: cargo test --all -- --skip integration
      - name: Integration tests
        run: cargo test --all -- integration
        env:
          DATABASE_URL: postgres://steward:steward_test@localhost:5432/steward_test
```

### 0.6 Phase 0 Checklist

Run this as a single Claude Code session on `main`:

- [ ] `cargo init` workspace with all crates
- [ ] All trait definitions in `steward-types/src/traits.rs`
- [ ] All shared data types in `steward-types/src/actions.rs` (with TODO stubs for types that parallel workers will expand)
- [ ] Error types in `steward-types/src/errors.rs`
- [ ] Config type stubs in `steward-types/src/config.rs`
- [ ] Stub `lib.rs` in every crate that re-exports its module structure
- [ ] Stub every `.rs` file with the correct module declaration + imports + TODO marker
- [ ] Default config files in `config/` (permissions.yaml, guardrails.yaml, identity.md)
- [ ] `.github/workflows/ci.yml`
- [ ] `CLAUDE.md` in repo root
- [ ] `docs/architecture.md` (copy from our design doc)
- [ ] `docs/implementation-plan.md` (this file)
- [ ] `Dockerfile` stub in `deploy/`
- [ ] `docker-compose.yml` with PostgreSQL + pgvector service
- [ ] Verify: `cargo build` succeeds, `cargo test` passes (even if all tests are trivial), CI pipeline green

**Everything after this point can run in parallel.**

---

## Batch 1: Security Leaf Modules (4 parallel worktrees)

These are pure functions/services with no dependencies on each other. Each takes well-defined input types and produces well-defined output types. Perfect for parallel development.

---

### TASK-1.1: Leak Detector

```
Branch:      feat/leak-detector
Crate:       steward-security
Files:       crates/steward-security/src/leak_detector.rs
Depends on:  Phase 0 merged to main
Tests:       Unit tests covering all pattern types
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 5.2 (Secret Broker) and 5.5 (Egress Filter) for context.
Read crates/steward-types/src/traits.rs for the LeakDetector trait you must implement.

Implement the LeakDetector in crates/steward-security/src/leak_detector.rs.

Requirements:
- Implement the LeakDetector trait from steward-types
- Pattern matching for: API keys (AWS, GCP, GitHub, Anthropic, OpenAI patterns),
  OAuth tokens, JWTs, private keys (RSA, EC, Ed25519), passwords in URLs,
  credit card numbers (Luhn check), SSNs, common secret formats
- Use regex for pattern matching — compile patterns once at construction time
  (lazy_static or OnceCell)
- The `scan` method returns Vec<LeakDetection> with: matched pattern name,
  byte offset, matched length, confidence score
- The `redact` method replaces detected secrets with [REDACTED:{pattern_name}]
- Must be fast — this runs on every I/O crossing a security boundary
- No async needed — this is pure CPU work

Write comprehensive unit tests:
- Test each credential pattern with real-world format examples
- Test that non-secrets don't trigger false positives (UUIDs, hex strings, etc.)
- Test redaction preserves non-secret content
- Test with content containing multiple secrets
- Test edge cases: empty input, very long input, overlapping patterns
```

---

### TASK-1.2: Ingress Sanitizer

```
Branch:      feat/ingress-sanitizer
Crate:       steward-security
Files:       crates/steward-security/src/ingress.rs
Depends on:  Phase 0 merged to main
Tests:       Unit tests for tagging, escaping, pattern detection, context budget
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 5.1 (Ingress Sanitizer) for requirements.
Read crates/steward-types/src/traits.rs for the IngressSanitizer trait.

Implement the IngressSanitizer in crates/steward-security/src/ingress.rs.

Requirements:
- Implement the IngressSanitizer trait from steward-types
- Content tagging: wrap external content in delimiters
  [EXTERNAL_CONTENT source="{source}" sender="{sender}"]...[/EXTERNAL_CONTENT]
- Injection pattern detection: detect common prompt injection patterns including
  "ignore previous instructions", "system:", "IMPORTANT:", role-playing attacks,
  delimiter manipulation, encoding tricks (base64 encoded instructions)
- Content escaping: neutralize characters that could break prompt boundaries
- Context budget: truncate external content to configurable max token count
  (approximate by character count / 4)
- Detection results should include: pattern name, confidence, matched text snippet
- Do NOT strip detected injections — flag them so the agent knows content was suspicious

Write comprehensive unit tests:
- Test content tagging with various source types (email, web, message)
- Test detection of known injection patterns (build a list of 10+)
- Test that normal content doesn't trigger false positives
- Test context budget enforcement
- Test nested/escaped content handling
```

---

### TASK-1.3: Audit Logger

```
Branch:      feat/audit-logger
Crate:       steward-security
Files:       crates/steward-security/src/audit.rs, SQL migration files
Depends on:  Phase 0 merged to main
Tests:       Unit tests with mock DB, integration test against PostgreSQL
```

**Prompt for Claude Code:**

```
Read docs/architecture.md sections on Ring 3 (Audit & Observability) and the
audit logger descriptions throughout. Read crates/steward-types/src/traits.rs
for the AuditLogger trait.

Implement the AuditLogger in crates/steward-security/src/audit.rs.

Requirements:
- Implement the AuditLogger trait from steward-types
- PostgreSQL-backed with sqlx (async)
- Append-only: the log method must INSERT only, never UPDATE or DELETE
- Create SQL migrations for the audit_events table:
  id (UUID), timestamp, event_type, action_json, guardian_verdict_json,
  permission_tier, outcome, metadata_json
  Add indexes on timestamp and event_type for query performance
- The query method supports filtering by: time range, event type, outcome,
  tool name (via JSON path query on action_json)
- Secrets in parameters must be redacted before logging — use the LeakDetector
  trait (accept it as a constructor dependency via trait object)
- Include a RotatingAuditLogger wrapper that handles table partitioning by month
  (stretch goal — mark as TODO if complex)

Write tests:
- Unit tests using a mock database (test serialization/deserialization)
- Integration test that connects to real PostgreSQL (gated behind a feature flag
  or env var DATABASE_URL), inserts events, queries them back
- Test that redaction is applied before storage
- Test query filters return correct subsets
```

---

### TASK-1.4: Permission Engine

```
Branch:      feat/permission-engine
Crate:       steward-core
Files:       crates/steward-core/src/permissions.rs
Depends on:  Phase 0 merged to main
Tests:       Unit tests for manifest parsing, classification, rate limiting
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section on Ring 1 (Permission Engine) including the
full permissions.yaml example. Read crates/steward-types/src/traits.rs for
the PermissionEngine trait.

Implement the PermissionEngine in crates/steward-core/src/permissions.rs.

Requirements:
- Implement the PermissionEngine trait from steward-types
- Parse permissions.yaml manifest using serde_yaml
- The manifest structure has four tiers: auto_execute, log_and_execute,
  human_approval, forbidden — each with a list of action patterns and constraints
- Action patterns support wildcards: "email.*" matches "email.read" and "email.send"
- classify() maps ActionProposal.tool_name to the correct tier
  Unknown actions default to human_approval (fail-closed)
- Rate limiting: token bucket algorithm per action, configurable per tier
  Store rate limit state in memory (HashMap<String, TokenBucket>)
- reload_manifest() re-reads the YAML file and hot-swaps the parsed config
  (use RwLock for concurrent access)
- Time-of-day restrictions: optional per-tier schedule
  (e.g., no auto_execute between 11pm-6am — escalate to human_approval)

Write tests:
- Test parsing the example permissions.yaml from the architecture doc
- Test wildcard pattern matching
- Test each tier classification
- Test unknown actions default to human_approval
- Test rate limiting (token bucket fills and drains correctly)
- Test hot-reload replaces config without dropping in-flight checks
- Test time-of-day restriction logic
```

---

## Batch 2: MCP Proxy Leaf Modules + Egress Filter (4 parallel worktrees)

Can start as soon as Batch 1 starts merging (only need Phase 0 for compile, but TASK-2.2 benefits from having leak_detector done for egress integration).

---

### TASK-2.1: MCP Manifest Parser

```
Branch:      feat/mcp-manifest
Crate:       steward-tools
Files:       crates/steward-tools/src/mcp/manifest.rs
Depends on:  Phase 0 merged to main
Tests:       Unit tests for manifest parsing, tool filtering, param blocking
```

**Prompt for Claude Code:**

```
Read docs/architecture.md sections 8.3 (Proxy Functions) and 8.9 (Tool List
Filtering and Schema Rewriting) for the manifest format and rewrite rules.
Read crates/steward-types/src/traits.rs for the McpManifest trait.

Implement the MCP manifest parser in crates/steward-tools/src/mcp/manifest.rs.

Requirements:
- Implement the McpManifest trait from steward-types
- Parse per-server YAML manifest files with this structure:
  server (name, url, transport, status), capabilities (allowed_tools with
  rate_limit and permission_tier overrides, blocked_tools), blocked_params
  (glob patterns like "*.bcc"), schema_rewrites (strip_params, constrain_params),
  egress_filter config, audit config, circuit_breaker config
- check_tool_call(): validate tool name is allowed, parameters don't include
  blocked params, rate limit not exceeded
- filter_tool_list(): remove blocked tools from a tools/list response AND
  rewrite input schemas to strip blocked parameters. If gmail.send has a "bcc"
  field in its inputSchema, remove that field from the JSON Schema before
  returning it to the agent
- Return ManifestDecision enum: Allow, Block { reason }, RateLimit { retry_after }

Write tests:
- Test parsing a complete Gmail manifest (use the example from architecture doc)
- Test tool filtering removes blocked tools
- Test schema rewriting strips blocked parameters from JSON Schema
- Test parameter constraint enforcement (max_recipients, max_size_bytes)
- Test glob pattern matching for blocked_params ("*.bcc" matches "arguments.bcc")
- Test rate limit checking
- Test permission tier overrides per tool
```

---

### TASK-2.2: Egress Filter

```
Branch:      feat/egress-filter
Crate:       steward-security
Files:       crates/steward-security/src/egress.rs
Depends on:  Phase 0 merged to main (uses LeakDetector trait from types)
Tests:       Unit tests for PII detection, secret scanning, recipient validation
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 5.5 (Egress Filter) for requirements.
Read crates/steward-types/src/traits.rs for the EgressFilter trait.

Implement the EgressFilter in crates/steward-security/src/egress.rs.

Requirements:
- Implement the EgressFilter trait from steward-types
- Accept a LeakDetector trait object as a constructor dependency (for secret scanning)
- PII detection: regex patterns for SSNs (XXX-XX-XXXX), credit cards (with Luhn),
  email addresses, phone numbers, physical addresses (best effort),
  health-related terms (ICD codes, medication names list)
- Secret scanning: delegate to LeakDetector
- Recipient validation: for communication tools (email.send, message.send),
  validate that the recipient matches expected patterns. Maintain a known
  contacts allowlist (configurable). Flag unknown recipients for review.
- Volume anomaly detection: track outbound message count per time window.
  If count exceeds threshold, block and alert. (Sliding window counter)
- Content policy check: basic heuristic — if tool type is "email.send" but
  content looks like a data dump (high entropy, structured data patterns),
  flag for review
- The filter method returns EgressDecision: Pass, Block { reason, patterns_found },
  or Warn { reason } (allow but flag in audit log)
- register_pattern() allows adding custom patterns at runtime

Write tests:
- Test PII detection for each pattern type
- Test false positive rates on normal content
- Test recipient validation with allowlist
- Test volume anomaly detection (simulate rapid sends)
- Test content policy heuristic
- Test that EgressDecision serializes correctly for audit logging
```

---

### TASK-2.3: MCP Schema Rewriter

```
Branch:      feat/mcp-schema-rewrite
Crate:       steward-tools
Files:       crates/steward-tools/src/mcp/schema_rewrite.rs
Depends on:  Phase 0 merged to main
Tests:       Unit tests for JSON Schema manipulation
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 8.9 (Tool List Filtering and Schema Rewriting).

Implement the MCP schema rewriter in crates/steward-tools/src/mcp/schema_rewrite.rs.

This module is used by the MCP manifest to rewrite tool input schemas. It operates
on JSON Schema objects (serde_json::Value) and removes or constrains properties.

Requirements:
- rewrite_schema(schema: &Value, rewrites: &SchemaRewriteConfig) -> Value
  Takes a JSON Schema and applies rewrite rules:
  - strip_params: remove named properties from the schema's "properties" object,
    also remove them from "required" if present
  - constrain_params: add or modify constraints on existing properties
    (e.g., set "maximum" on an integer field, set "maxItems" on an array field,
    set "maxLength" on a string field)
- strip_blocked_params(schema: &Value, patterns: &[String]) -> Value
  Remove all properties matching glob patterns from the schema.
  Pattern "*.bcc" matches any property named "bcc" at any depth.
  Pattern "arguments.forward_to" matches that exact path.
- The rewritten schema must remain valid JSON Schema
- Handle nested schemas (objects within objects)

Write tests:
- Test stripping a single property from a flat schema
- Test stripping from a nested schema
- Test glob pattern matching at multiple depths
- Test constraint application (add maximum, maxItems, maxLength)
- Test that required array is updated when properties are removed
- Test that an empty schema remains valid after rewriting
- Test real-world MCP tool schemas (Gmail send, Calendar create)
```

---

### TASK-2.4: Circuit Breaker

```
Branch:      feat/circuit-breaker
Crate:       steward-tools
Files:       crates/steward-tools/src/mcp/circuit_breaker.rs
Depends on:  Phase 0 merged to main
Tests:       Unit tests for state transitions, timing, recovery
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 8.11 (Connection Lifecycle and Circuit Breaker).
Read crates/steward-types/src/traits.rs for the CircuitBreaker trait.

Implement the circuit breaker in crates/steward-tools/src/mcp/circuit_breaker.rs.

Requirements:
- Implement the CircuitBreaker trait from steward-types
- Three states: Closed (healthy), Open (broken), HalfOpen (testing recovery)
- Configuration (from manifest YAML): error_threshold, error_window (duration),
  latency_threshold (duration), recovery_timeout (duration), recovery_probes (count),
  max_recovery_backoff (duration)
- Closed → Open: when consecutive errors in the error window exceed threshold
- Open → HalfOpen: after recovery_timeout elapses
- HalfOpen → Closed: after recovery_probes consecutive successes
- HalfOpen → Open: on any failure during probing
- Exponential backoff with jitter on recovery_timeout (capped at max_recovery_backoff)
- record_success() and record_failure() update internal state
- state() returns current CircuitState
- attempt_probe() returns true if a probe call should be allowed (HalfOpen state,
  and probe slot available)
- Thread-safe: use AtomicU64 or Mutex for state updates
- Include a method to get metrics: total_successes, total_failures,
  time_in_current_state, trips_count

Write tests:
- Test normal operation (closed state, recording successes)
- Test transition to open after threshold errors
- Test that calls are rejected in open state
- Test automatic transition to half-open after timeout
- Test successful recovery (half-open → closed)
- Test failed recovery (half-open → open with increased backoff)
- Test exponential backoff calculation with jitter
- Test concurrent access from multiple threads
```

---

## Batch 3: Memory System + MCP Transports (4 parallel worktrees)

---

### TASK-3.1: Memory Store (PostgreSQL + pgvector)

```
Branch:      feat/memory-store
Crate:       steward-memory
Files:       crates/steward-memory/src/workspace.rs, SQL migrations
Depends on:  Phase 0 merged to main
Tests:       Integration tests against PostgreSQL + pgvector
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 5.4 (Memory System with Provenance).
Read crates/steward-types/src/traits.rs for the MemoryStore trait.

Implement the memory store in crates/steward-memory/src/workspace.rs.

Requirements:
- Implement the MemoryStore trait from steward-types
- PostgreSQL-backed using sqlx with the pgvector extension
- Create SQL migrations for the memory_entries table:
  id (UUID PK), content (TEXT), provenance (TEXT enum), trust_score (FLOAT),
  embedding (vector(1536)), created_at (TIMESTAMPTZ), updated_at (TIMESTAMPTZ),
  metadata (JSONB)
- Add indexes: vector index (ivfflat or hnsw) on embedding, GIN index on
  content for full-text search, btree index on created_at and trust_score
- store() inserts a new entry (generate UUID if id is None)
- get() retrieves by ID
- update_trust() updates the trust_score for an entry
- Include a method for bulk retrieval: get_by_provenance(provenance, limit)
- Immutable core memory tier: entries with provenance=UserInstruction and
  trust_score=1.0 cannot be modified except by explicit user commands
  (enforce at the store level — reject update_trust for these entries)

Write tests:
- Integration tests that require DATABASE_URL env var
- Test store and retrieve round-trip
- Test provenance filtering
- Test trust score updates
- Test immutable core memory protection
- Test that vector embeddings are stored and retrievable
```

---

### TASK-3.2: Memory Search (Hybrid FTS + Vector)

```
Branch:      feat/memory-search
Crate:       steward-memory
Files:       crates/steward-memory/src/search.rs
Depends on:  Phase 0 merged to main
Tests:       Integration tests against PostgreSQL + pgvector
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 5.4 (Memory System with Provenance).
Read crates/steward-types/src/traits.rs for the MemorySearch trait.

Implement hybrid search in crates/steward-memory/src/search.rs.

Requirements:
- Implement the MemorySearch trait from steward-types
- Hybrid search combining PostgreSQL full-text search (tsvector/tsquery) with
  pgvector similarity search, fused using Reciprocal Rank Fusion (RRF)
- RRF formula: score = sum(1 / (k + rank_i)) where k=60 (standard constant)
  and rank_i is the rank from each retrieval method
- Full-text search: use ts_rank with websearch_to_tsquery for natural language queries
- Vector search: cosine similarity against pgvector embeddings
  (assumes embedding is pre-computed and passed as parameter — do NOT implement
  embedding generation here, just accept Vec<f32>)
- Results include: memory entry, combined RRF score, individual FTS rank,
  individual vector rank
- Trust score weighting: multiply RRF score by trust_score to penalize
  low-trust memories in ranking
- Configurable: FTS weight vs vector weight, k constant, max results

Write tests:
- Integration tests requiring DATABASE_URL
- Test FTS search returns relevant results
- Test vector search returns similar entries
- Test RRF fusion ranks combined results correctly
- Test trust score weighting penalizes low-trust entries
- Test empty results
- Test with limit parameter
```

---

### TASK-3.3: MCP stdio Transport

```
Branch:      feat/mcp-transport-stdio
Crate:       steward-tools
Files:       crates/steward-tools/src/mcp/transport_stdio.rs
Depends on:  Phase 0 merged to main
Tests:       Unit tests with mock child process, integration test with real MCP server
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 8.8 (Transport Abstraction Layer).
Read crates/steward-types/src/traits.rs for the McpTransport trait.

Implement the stdio transport in crates/steward-tools/src/mcp/transport_stdio.rs.

Requirements:
- Implement the McpTransport trait from steward-types
- Spawn an MCP server as a child process using tokio::process::Command
- Own the child's stdin (write JSON-RPC messages) and stdout (read JSON-RPC messages)
- JSON-RPC message framing: each message is a single line of JSON followed by newline
  (MCP stdio convention — no content-length headers like LSP)
- send(): serialize JsonRpcMessage to JSON, write to stdin + newline + flush
- recv(): read a line from stdout, parse as JsonRpcMessage
- Handle stderr: capture stderr in a background task, log as warnings
- close(): send SIGTERM to child, wait with timeout, then SIGKILL
- is_connected(): check if child process is still running
- Constructor takes: command path, arguments, environment variables, working directory
- Implement proper cleanup in Drop (or explicit close method)
- Handle the case where the child process crashes unexpectedly

Write tests:
- Unit test with a mock child process (e.g., spawn "cat" or a simple echo script)
- Test send/recv round trip with valid JSON-RPC messages
- Test handling of malformed output from child process
- Test close behavior (SIGTERM then SIGKILL after timeout)
- Test reconnection semantics (or error reporting on unexpected death)
- Test concurrent send/recv (messages should not interleave)
```

---

### TASK-3.4: MCP HTTP/SSE Transport

```
Branch:      feat/mcp-transport-http
Crate:       steward-tools
Files:       crates/steward-tools/src/mcp/transport_http.rs
Depends on:  Phase 0 merged to main
Tests:       Unit tests with mock HTTP server
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 8.8 (Transport Abstraction Layer).
Read crates/steward-types/src/traits.rs for the McpTransport trait.

Implement the HTTP/SSE transport in crates/steward-tools/src/mcp/transport_http.rs.

Requirements:
- Implement the McpTransport trait from steward-types
- Acts as an HTTP client to a remote MCP server using streamable HTTP transport
  (MCP 2025-11-25 spec)
- send(): HTTP POST with JSON-RPC message body to the server's endpoint
- recv(): receive from SSE event stream (server → client)
- Use reqwest for HTTP client, handle SSE stream parsing (text/event-stream)
- Session management: maintain Mcp-Session-Id header across requests
- Reconnection: support Last-Event-ID for SSE stream recovery
- close(): close the SSE connection, clean up HTTP client
- is_connected(): check if SSE stream is active
- Support configurable: base URL, auth headers, connection timeout, read timeout
- Handle HTTP errors gracefully (4xx → permanent error, 5xx → retryable)

Write tests:
- Unit tests with a mock HTTP server (use axum or wiremock for test server)
- Test send/recv round trip
- Test SSE stream parsing with multiple events
- Test session ID tracking
- Test reconnection with Last-Event-ID
- Test HTTP error handling (404, 500, timeout)
- Test TLS configuration (can be a config-only test)
```

---

## Batch 4: Core Agent Loop + Secret Broker + Config (3-4 parallel worktrees)

Batch 4 starts after Batches 1-2 are substantially merged, because the agent loop integrates security modules and the tool registry.

---

### TASK-4.1: Secret Broker

```
Branch:      feat/secret-broker
Crate:       steward-security
Files:       crates/steward-security/src/secret_broker.rs
Depends on:  Phase 0, TASK-1.1 (leak detector) merged
Tests:       Unit tests for encryption/decryption, token provisioning
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 5.2 (Secret Broker).
Read crates/steward-types/src/traits.rs for the SecretBroker trait.

Implement the secret broker in crates/steward-security/src/secret_broker.rs.

Requirements:
- Implement the SecretBroker trait from steward-types
- AES-256-GCM encryption for credential storage using the `aes-gcm` crate
- Master key derivation from system keychain or env var (for dev/testing)
  using HKDF (via `hkdf` crate)
- store(): encrypt credential with AES-256-GCM, store to PostgreSQL
  (encrypted_data, nonce, key_id, created_at, expires_at)
- provision_token(): create a scoped, time-limited wrapper around a stored
  credential. The ScopedToken includes: the credential reference (not the raw
  value), allowed scope (which tool, which endpoint), expiry time, single-use flag
- inject_credentials(): given a ToolRequest and a credential key, inject the
  actual credential value into the request at the transport boundary. The
  credential is decrypted only at this point and only exists in memory briefly.
- Credentials must never appear in logs — use the LeakDetector to verify
  that injected credentials don't leak into parameter logging
- Support credential rotation: update a stored credential without downtime

Write tests:
- Test encrypt/decrypt round trip
- Test that stored credentials are not readable without the master key
- Test scoped token creation with expiry
- Test credential injection into a mock tool request
- Test that expired tokens are rejected
- Test credential rotation
```

---

### TASK-4.2: LLM Provider (Claude + Ollama)

```
Branch:      feat/llm-provider
Crate:       steward-core
Files:       crates/steward-core/src/llm/ (new module with mod.rs, anthropic.rs, ollama.rs)
Depends on:  Phase 0 merged to main
Tests:       Unit tests with mock HTTP responses
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 11 (Model Support).
Read crates/steward-types/src/traits.rs for the LlmProvider trait.

Implement LLM providers in crates/steward-core/src/llm/.

Requirements:
- Create an llm/ module directory with mod.rs, anthropic.rs, ollama.rs
- Both implement the LlmProvider trait from steward-types
- AnthropicProvider: HTTP client to the Anthropic Messages API
  - Supports Claude Opus, Sonnet, Haiku
  - Handles tool_use responses (tool calls in assistant response)
  - Streaming support (optional, mark as TODO if complex)
  - API key injected via SecretBroker (accept as trait object dependency)
  - Respect rate limits from response headers
- OllamaProvider: HTTP client to the Ollama API
  - Supports any model available in the local Ollama instance
  - Convert between Ollama's chat format and Steward's CompletionRequest/Response
  - Tool calling via Ollama's function calling support
- Both providers must serialize/deserialize tool definitions to/from
  the provider's expected format
- Include a ProviderRouter that selects provider based on config
  (primary provider, fallback chain)

Write tests:
- Test request serialization for both providers
- Test response deserialization (including tool_use blocks)
- Test error handling (rate limit, auth failure, timeout)
- Test provider routing (primary → fallback on failure)
- Use mock HTTP server (wiremock) — do NOT call real APIs in tests
```

---

### TASK-4.3: Guardian LLM

```
Branch:      feat/guardian
Crate:       steward-core
Files:       crates/steward-core/src/guardian.rs
Depends on:  Phase 0, TASK-4.2 (llm provider) started but can develop in parallel
             using the LlmProvider trait interface
Tests:       Unit tests with mock LLM responses
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section on Ring 2 (Guardian LLM) and section 8.12
(Integration with Full Security Stack).
Read crates/steward-types/src/traits.rs for the Guardian trait.

Implement the guardian in crates/steward-core/src/guardian.rs.

Requirements:
- Implement the Guardian trait from steward-types
- Accept an LlmProvider trait object as constructor dependency
- Build the guardian prompt that receives:
  (a) the user's original message (text only — no raw external content)
  (b) the proposed action (tool name + parameters)
  (c) the primary agent's reasoning for the action
  (d) the current permission policy summary
- The guardian's system prompt must be hardened:
  - It should be adversarial: "Your job is to find reasons this action might be wrong"
  - It should never execute tool calls itself
  - It should ignore any instructions embedded in the action parameters
  - It should output structured JSON: { decision, reasoning, confidence, injection_indicators }
- Parse the LLM's response into a GuardianVerdict
- Handle parsing failures gracefully (if the guardian's output is malformed,
  default to EscalateToHuman — fail safe)
- Confidence threshold: if confidence < configurable threshold, escalate to human
  even if decision is Allow
- Include the guardian system prompt as a const string in the module

Write tests:
- Test with mock LLM that returns ALLOW verdict
- Test with mock LLM that returns BLOCK verdict
- Test with mock LLM that returns malformed output (should escalate)
- Test confidence threshold escalation
- Test that the guardian prompt construction doesn't leak raw external content
- Test that injection attempts in action parameters don't affect guardian behavior
  (mock the LLM to return what you'd expect from a real model seeing injection)
```

---

### TASK-4.4: Config Management

```
Branch:      feat/config-management
Crate:       steward-types (config module) + new config loader
Files:       crates/steward-types/src/config.rs (expand stubs)
Depends on:  Phase 0 merged to main
Tests:       Unit tests for config parsing and validation
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 5.7 (Configuration as Code) and the config/
directory structure. Read the permissions.yaml example and the MCP manifest
examples.

Expand the config types in crates/steward-types/src/config.rs and implement
a config loader.

Requirements:
- Full serde types for:
  - PermissionsConfig (parsing permissions.yaml — tiers, actions, constraints,
    rate limits, time-of-day restrictions)
  - GuardrailsConfig (parsing guardrails.yaml — forbidden patterns, circuit breakers)
  - McpManifestConfig (parsing mcp-manifests/*.yaml — the full MCP manifest schema
    from architecture doc section 8.3)
  - IdentityConfig (parsing identity.md — agent personality, behavioral boundaries)
- ConfigLoader struct that:
  - Reads all config from a directory path
  - Validates config on load (e.g., no duplicate action patterns, rate limits are positive)
  - Supports hot-reload via file watching (notify crate)
  - Emits config change events via a channel (tokio::sync::watch)
- Default config files in config/ directory (ship with sensible defaults)

Write tests:
- Test parsing each config file type
- Test validation catches invalid configs
- Test hot-reload detects file changes
- Test default configs parse successfully
- Test error messages are helpful for invalid YAML
```

---

## Batch 5: Integration — MCP Proxy Core + Agent Loop (2-3 parallel worktrees)

This batch assembles the leaf modules into working subsystems. Requires most of Batches 1-4 merged.

---

### TASK-5.1: MCP Proxy Core

```
Branch:      feat/mcp-proxy-core
Crate:       steward-tools
Files:       crates/steward-tools/src/mcp/proxy.rs, crates/steward-tools/src/mcp/mod.rs
Depends on:  TASK-2.1, TASK-2.3, TASK-2.4, TASK-3.3, TASK-3.4 merged
Tests:       Integration tests with mock MCP server
```

**Prompt for Claude Code:**

```
Read docs/architecture.md sections 8.7 through 8.12 (the complete MCP proxy spec).
Read the MCP module files that have already been implemented:
- mcp/manifest.rs (TASK-2.1)
- mcp/schema_rewrite.rs (TASK-2.3)
- mcp/circuit_breaker.rs (TASK-2.4)
- mcp/transport_stdio.rs (TASK-3.3)
- mcp/transport_http.rs (TASK-3.4)

Implement the MCP proxy core in crates/steward-tools/src/mcp/proxy.rs.

This is the integration point — it wires together all MCP leaf modules into
the complete enforcement pipeline described in architecture doc section 8.10.

Requirements:
- McpProxy struct that manages multiple MCP server connections
- Each server has: a manifest (McpManifest), a transport (McpTransport),
  a circuit breaker (CircuitBreaker), and a connection state
- Connection lifecycle: REGISTERED → CONNECTING → INTROSPECTING → ACTIVE →
  CIRCUIT_BROKEN → DISCONNECTED (state machine from section 8.11)
- On tools/list: aggregate tool lists from all active servers, apply manifest
  filtering and schema rewriting, return unified list
- On tools/call: route to correct server by tool name, run through enforcement
  pipeline (manifest check → rate limit → egress filter → forward → response scan →
  audit log → return)
- Accept EgressFilter and AuditLogger as trait object dependencies
- Hot-reload manifests: watch for manifest file changes, update without restart
- add_server() / remove_server() methods for dynamic MCP server management
- Transparent to the agent: expose a simple call(tool_name, params) → result interface

Write tests:
- Integration test with a mock MCP server (spawn a simple stdio process)
- Test tools/list filtering across multiple servers
- Test tools/call routing to correct server
- Test enforcement pipeline (blocked tool, blocked param, rate limit)
- Test circuit breaker integration (server failure → circuit open → rejection)
- Test add/remove server dynamically
```

---

### TASK-5.2: Agent Core Loop

```
Branch:      feat/agent-core
Crate:       steward-core
Files:       crates/steward-core/src/agent.rs, crates/steward-core/src/router.rs
Depends on:  TASK-1.2, TASK-1.4, TASK-4.2, TASK-4.3 merged (security + LLM + guardian)
Tests:       Integration tests with mock LLM and mock tools
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 3 (High-Level Architecture) for the full
request flow, section 6 (Agent Model: Generalist with Delegation) for the
generalist architecture.

Implement the agent core loop in crates/steward-core/src/agent.rs and the
router in crates/steward-core/src/router.rs.

This is the main orchestrator — it receives user messages, generates action
proposals via LLM, runs them through the security pipeline, and executes them.

Requirements:
- Agent struct that wires together: LlmProvider, Guardian, PermissionEngine,
  ToolRegistry, EgressFilter, IngressSanitizer, AuditLogger, MemorySearch
  (all as trait objects)
- Main loop:
  1. Receive inbound message (from channel)
  2. Run through IngressSanitizer
  3. Retrieve relevant context from MemorySearch
  4. Build LLM prompt with: system prompt, user message, sanitized context,
     available tools
  5. Call LlmProvider.complete_with_tools()
  6. Parse response — extract ActionProposal(s) from tool_use blocks
  7. For each proposal: Guardian.review() → PermissionEngine.classify() →
     if approved: ToolRegistry.execute() → EgressFilter.filter() on result
  8. Build response message from results
  9. AuditLogger.log() for every step
- Handle multi-turn tool use: if the LLM wants to call multiple tools in
  sequence, loop through steps 5-8
- Handle human approval flow: when PermissionEngine returns HumanApproval,
  send approval request via channel and wait for response
- Error handling: any failure at any stage should be logged and result in a
  graceful error message to the user (never crash the loop)
- Router (router.rs): simple intent classification that determines if the
  message needs tool use or is just conversation. Can start as a heuristic
  (look for action verbs, question marks, etc.) — LLM-based routing is a
  stretch goal.

Write tests:
- Test full request flow with mock LLM + mock tools (happy path)
- Test guardian blocks an action (verify action not executed)
- Test human approval flow (mock channel approval)
- Test multi-turn tool use
- Test error handling (LLM fails, tool fails, etc.)
- Test that every step produces an audit log entry
```

---

### TASK-5.3: Tool Registry

```
Branch:      feat/tool-registry
Crate:       steward-tools
Files:       crates/steward-tools/src/registry.rs
Depends on:  TASK-5.1 (MCP proxy) merged or in progress
Tests:       Unit tests for registration, routing, listing
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 5 (Key Subsystems) for tool categorization:
built-in, WASM, MCP. Read crates/steward-types/src/traits.rs for ToolRegistry.

Implement the tool registry in crates/steward-tools/src/registry.rs.

Requirements:
- Implement the ToolRegistry trait from steward-types
- Manages three categories of tools:
  (a) Built-in tools (direct function calls, trusted)
  (b) WASM tools (sandboxed, capability-manifest-enforced) — stub for now
  (c) MCP tools (proxied through McpProxy)
- list_tools(): aggregate tools from all sources into a unified list.
  Each tool has a ToolDefinition with: name, description, input schema,
  source (BuiltIn/Wasm/Mcp), permission tier
- execute(): route tool call to correct backend based on tool source.
  Built-in → direct call. MCP → delegate to McpProxy. WASM → stub/TODO.
- register(): add a new tool (for MCP discovery and WASM deployment)
- unregister(): remove a tool
- Thread-safe: tools can be added/removed while the agent is running

Write tests:
- Test listing tools from multiple sources
- Test routing to correct backend
- Test registration and unregistration
- Test thread-safe concurrent access
- Test that unknown tools return a clear error
```

---

## Batch 6: Channel Adapters + End-to-End Integration (2-3 worktrees)

---

### TASK-6.1: WhatsApp Channel Adapter

```
Branch:      feat/whatsapp-channel
Crate:       steward-channels
Files:       crates/steward-channels/src/whatsapp.rs, crates/steward-channels/src/confirmation.rs
Depends on:  Phase 0, TASK-4.4 (config) useful but not required
Tests:       Unit tests with mock webhook server
```

**Prompt for Claude Code:**

```
Read docs/architecture.md section 10 (Communication Layer).
Read crates/steward-types/src/traits.rs for ChannelAdapter.

Implement the WhatsApp adapter in crates/steward-channels/src/whatsapp.rs
and the approval UX in crates/steward-channels/src/confirmation.rs.

Requirements:
- Implement ChannelAdapter trait for WhatsApp
- Use WhatsApp Business Cloud API (HTTP API — not Baileys/websocket for v1)
- Inbound: webhook endpoint (axum HTTP server) that receives WhatsApp webhook events,
  verifies webhook signature, parses message payloads
- send_message(): POST to WhatsApp Business API to send text messages
- request_approval(): send a structured approval message with the action details
  and interactive buttons (Approve / Reject). Wait for button callback response
  with configurable timeout.
- Webhook signature verification using HMAC-SHA256
- Handle WhatsApp message types: text, image (extract URL), document (extract URL)
- Rate limiting: respect WhatsApp's messaging rate limits
- Include the axum webhook router as a separate function that can be mounted
  into a larger web server

Write tests:
- Test webhook signature verification (valid and invalid)
- Test message parsing for different WhatsApp payload types
- Test approval flow (mock the webhook callback)
- Test timeout on approval (no response within window)
- Test rate limiting
```

---

### TASK-6.2: End-to-End Smoke Test

```
Branch:      feat/e2e-smoke
Files:       tests/integration/smoke_test.rs
Depends on:  Batches 1-5 substantially merged
Tests:       Full integration test of the complete pipeline
```

**Prompt for Claude Code:**

```
Create an end-to-end smoke test in tests/integration/smoke_test.rs that
exercises the complete Steward pipeline.

The test should:
1. Set up: PostgreSQL (from docker-compose), mock LLM server (returns
   predetermined tool calls), mock MCP server (simple echo tools)
2. Initialize all components: Agent, Guardian (with mock LLM), PermissionEngine
   (with test permissions.yaml), IngressSanitizer, EgressFilter, AuditLogger,
   McpProxy (with mock MCP server), ToolRegistry
3. Send a simulated user message through the pipeline
4. Verify: ingress sanitization ran, guardian was consulted, permission was checked,
   tool was called through MCP proxy, egress filter scanned the result,
   audit log captured all events, response was generated
5. Send a simulated injection attack and verify it was detected and blocked
6. Verify the audit trail contains all expected events in the correct order

This is a "does the whole thing wire together" test, not a comprehensive
security test. Keep it focused on proving integration works.

Requires DATABASE_URL env var for PostgreSQL connection.
Tag the test with #[ignore] unless DATABASE_URL is set.
```

---

## Worktree Quick Reference

### Setup

```bash
# After Phase 0 is merged to main:
cd ~/projects/steward

# Create worktrees for Batch 1 (all at once if you want 4 parallel runs)
git worktree add ../steward-wt-1-1 -b feat/leak-detector
git worktree add ../steward-wt-1-2 -b feat/ingress-sanitizer
git worktree add ../steward-wt-1-3 -b feat/audit-logger
git worktree add ../steward-wt-1-4 -b feat/permission-engine

# Start Claude Code in each:
cd ../steward-wt-1-1 && claude   # give it TASK-1.1 prompt
cd ../steward-wt-1-2 && claude   # give it TASK-1.2 prompt
cd ../steward-wt-1-3 && claude   # give it TASK-1.3 prompt
cd ../steward-wt-1-4 && claude   # give it TASK-1.4 prompt
```

### Teardown After Merge

```bash
# After PRs are merged:
cd ~/projects/steward
git worktree remove ../steward-wt-1-1
git worktree remove ../steward-wt-1-2
# ... etc

# Delete merged branches:
git branch -d feat/leak-detector feat/ingress-sanitizer feat/audit-logger feat/permission-engine

# Pull main with all merged changes:
git pull origin main

# Create worktrees for next batch:
git worktree add ../steward-wt-2-1 -b feat/mcp-manifest
# ... etc
```

### Overnight Workflow Script

```bash
#!/bin/bash
# run-batch.sh — Launch parallel Claude Code instances for a batch
# Usage: ./run-batch.sh <batch-number>

set -e

BATCH=$1
REPO_DIR=~/projects/steward

# Define tasks per batch
declare -A BATCH_1=(
  ["leak-detector"]="TASK-1.1"
  ["ingress-sanitizer"]="TASK-1.2"
  ["audit-logger"]="TASK-1.3"
  ["permission-engine"]="TASK-1.4"
)

# Select batch
declare -n TASKS="BATCH_${BATCH}"

for branch in "${!TASKS[@]}"; do
  task="${TASKS[$branch]}"
  wt_dir="${REPO_DIR}-wt-${BATCH}-${branch}"

  echo "Setting up worktree for ${task} on feat/${branch}..."
  cd "$REPO_DIR"
  git worktree add "$wt_dir" -b "feat/${branch}" 2>/dev/null || \
    git worktree add "$wt_dir" "feat/${branch}"

  echo "Launching Claude Code for ${task}..."
  # Launch in background terminal / tmux pane
  # Adjust this for your terminal setup:
  tmux new-window -t steward -n "${branch}" \
    "cd ${wt_dir} && claude --task '$(cat docs/tasks/${task}.md)'"
done

echo "All ${#TASKS[@]} instances launched."
```

---

## Task File Convention

For the overnight workflow, store each task prompt as a separate file that Claude Code can read:

```
docs/tasks/
├── TASK-1.1.md    # Leak detector prompt
├── TASK-1.2.md    # Ingress sanitizer prompt
├── TASK-1.3.md    # Audit logger prompt
├── TASK-1.4.md    # Permission engine prompt
├── TASK-2.1.md    # MCP manifest parser prompt
├── ...
```

Each file contains exactly the "Prompt for Claude Code" text from the corresponding task card above. Claude Code reads it and executes.

---

## Timeline Estimate

| Batch | Tasks | Parallel Workers | Calendar Time | Cumulative |
|-------|-------|-----------------|---------------|------------|
| Phase 0 | Skeleton + traits | 1 (you + CC) | 1 evening | Day 1 |
| Batch 1 | Security leaves + perms | 4 | 1-2 nights | Day 2-3 |
| Batch 2 | MCP leaves + egress | 4 | 1-2 nights | Day 3-5 |
| Batch 3 | Memory + transports | 4 | 1-2 nights | Day 5-7 |
| Batch 4 | Secret broker + LLM + guardian + config | 4 | 2 nights | Day 7-9 |
| Batch 5 | MCP proxy core + agent loop + registry | 3 | 2-3 nights | Day 9-12 |
| Batch 6 | WhatsApp + E2E smoke test | 2 | 1-2 nights | Day 12-14 |

**Aggressive estimate: ~2 weeks of evenings to a working prototype.**

This doesn't include: WASM sandbox (can defer), additional channel adapters, dashboard, Dockerfile hardening, or open-source prep. Those are Phase 2+ when the core loop is working end-to-end.

---

## Merge Strategy

- **Leaf modules (Batches 1-3):** Merge freely — these don't conflict because they're in separate files and only depend on `steward-types`.
- **Integration modules (Batches 4-5):** Merge sequentially. TASK-5.2 (agent core) should be last because it imports everything.
- **If merge conflicts arise:** Rebase the feature branch on main before creating PR. Claude Code can do this: `git fetch origin main && git rebase origin/main`.
- **PR review checklist:** Tests pass in CI? Clippy clean? Implements the trait correctly? Doc comments on public types? No unwrap() in production code paths?
