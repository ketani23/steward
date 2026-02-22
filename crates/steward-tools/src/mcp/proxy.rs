//! MCP proxy core implementation.
//!
//! Wires together all MCP subsystem modules into the complete enforcement pipeline:
//! manifest check → rate limit → egress filter → forward → response scan → audit log
//!
//! This is the integration point — it manages multiple MCP server connections and
//! presents a unified tool interface to the agent. The proxy is transparent: the agent
//! sees MCP tools identically to built-in tools.
//!
//! See `docs/architecture.md` sections 8.7-8.12 for the full specification.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use steward_types::actions::{
    ActionOutcome, AuditEvent, AuditEventType, CircuitState, EgressDecision, JsonRpcMessage,
    ManifestDecision, McpToolDef, OutboundContent, ToolDefinition, ToolResult, ToolSource,
};
use steward_types::errors::StewardError;
use steward_types::traits::{AuditLogger, CircuitBreaker, EgressFilter, McpManifest, McpTransport};

use crate::mcp::circuit_breaker::McpCircuitBreaker;
use crate::mcp::manifest::McpManifestImpl;

// ============================================================
// Connection State Machine
// ============================================================

/// Connection lifecycle states for an MCP server (section 8.11).
///
/// ```text
/// REGISTERED → CONNECTING → INTROSPECTING → ACTIVE → (CIRCUIT_BROKEN) → DISCONNECTED
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Manifest approved, server config stored.
    Registered,
    /// Proxy establishing transport.
    Connecting,
    /// Proxy sending initialize + tools/list to verify server matches manifest.
    Introspecting,
    /// Normal operation — tool calls flowing through the enforcement pipeline.
    Active,
    /// Server failing — proxy stops routing calls, returns clean errors.
    CircuitBroken,
    /// Clean shutdown, user revocation, or unrecoverable failure.
    Disconnected,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Registered => write!(f, "REGISTERED"),
            ConnectionState::Connecting => write!(f, "CONNECTING"),
            ConnectionState::Introspecting => write!(f, "INTROSPECTING"),
            ConnectionState::Active => write!(f, "ACTIVE"),
            ConnectionState::CircuitBroken => write!(f, "CIRCUIT_BROKEN"),
            ConnectionState::Disconnected => write!(f, "DISCONNECTED"),
        }
    }
}

// ============================================================
// Server Entry
// ============================================================

/// A managed MCP server connection with all associated state.
pub struct McpServerEntry {
    /// The server name.
    pub name: String,
    /// The capability manifest.
    pub manifest: McpManifestImpl,
    /// The transport for communicating with the server.
    pub transport: Box<dyn McpTransport>,
    /// The circuit breaker for this server.
    pub circuit_breaker: McpCircuitBreaker,
    /// Current connection state.
    pub state: ConnectionState,
    /// Cached tool list from the server (post-filtering).
    pub cached_tools: Vec<McpToolDef>,
    /// Next JSON-RPC request ID.
    next_id: u64,
}

impl McpServerEntry {
    /// Allocate the next JSON-RPC request ID for this server.
    fn next_request_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

// ============================================================
// McpProxy
// ============================================================

/// MCP proxy core — security gateway for all MCP server communication.
///
/// Manages multiple MCP server connections, each with its own manifest,
/// transport, circuit breaker, and connection state. Presents a unified
/// tool interface to the agent through the enforcement pipeline.
pub struct McpProxy {
    /// Managed MCP servers keyed by server name.
    servers: Arc<RwLock<HashMap<String, McpServerEntry>>>,
    /// Shared egress filter for scanning outbound content.
    egress_filter: Arc<dyn EgressFilter>,
    /// Shared audit logger for recording all MCP events.
    audit_logger: Arc<dyn AuditLogger>,
}

impl McpProxy {
    /// Create a new MCP proxy with the given dependencies.
    pub fn new(egress_filter: Arc<dyn EgressFilter>, audit_logger: Arc<dyn AuditLogger>) -> Self {
        Self {
            servers: Arc::new(RwLock::new(HashMap::new())),
            egress_filter,
            audit_logger,
        }
    }

    /// Add a new MCP server to the proxy.
    ///
    /// The server starts in `Registered` state. Call [`connect_server`] to
    /// establish the transport and transition to `Active`.
    pub async fn add_server(
        &self,
        name: String,
        manifest: McpManifestImpl,
        transport: Box<dyn McpTransport>,
        circuit_breaker: McpCircuitBreaker,
    ) -> Result<(), StewardError> {
        let mut servers = self.servers.write().await;
        if servers.contains_key(&name) {
            return Err(StewardError::Mcp(format!(
                "server '{}' is already registered",
                name
            )));
        }

        info!(server = %name, "adding MCP server to proxy");

        servers.insert(
            name.clone(),
            McpServerEntry {
                name,
                manifest,
                transport,
                circuit_breaker,
                state: ConnectionState::Registered,
                cached_tools: Vec::new(),
                next_id: 0,
            },
        );

        Ok(())
    }

    /// Remove an MCP server from the proxy.
    ///
    /// Closes the transport and removes all state.
    pub async fn remove_server(&self, name: &str) -> Result<(), StewardError> {
        let mut servers = self.servers.write().await;
        match servers.remove(name) {
            Some(mut entry) => {
                info!(server = %name, "removing MCP server from proxy");
                entry.state = ConnectionState::Disconnected;
                let _ = entry.transport.close().await;
                Ok(())
            }
            None => Err(StewardError::Mcp(format!(
                "server '{}' is not registered",
                name
            ))),
        }
    }

    /// Connect to a registered server: transition through Connecting → Introspecting → Active.
    ///
    /// Sends the MCP `initialize` handshake, then `tools/list` to discover and cache tools.
    pub async fn connect_server(&self, name: &str) -> Result<(), StewardError> {
        let mut servers = self.servers.write().await;
        let entry = servers
            .get_mut(name)
            .ok_or_else(|| StewardError::Mcp(format!("server '{}' is not registered", name)))?;

        if entry.state != ConnectionState::Registered
            && entry.state != ConnectionState::Disconnected
        {
            return Err(StewardError::Mcp(format!(
                "server '{}' is in state {}, expected Registered or Disconnected",
                name, entry.state
            )));
        }

        // Transition to Connecting.
        entry.state = ConnectionState::Connecting;
        info!(server = %name, "connecting to MCP server");

        // Transition to Introspecting — send initialize.
        entry.state = ConnectionState::Introspecting;
        let init_id = entry.next_request_id();
        let init_request = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(init_id)),
            method: Some("initialize".to_string()),
            params: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "steward-mcp-proxy",
                    "version": "0.1.0"
                }
            })),
            result: None,
            error: None,
        };

        entry.transport.send(init_request).await.map_err(|e| {
            entry.state = ConnectionState::Disconnected;
            StewardError::Mcp(format!("failed to send initialize to '{}': {}", name, e))
        })?;

        let init_response = entry.transport.recv().await.map_err(|e| {
            entry.state = ConnectionState::Disconnected;
            StewardError::Mcp(format!(
                "failed to receive initialize response from '{}': {}",
                name, e
            ))
        })?;

        if init_response.error.is_some() {
            entry.state = ConnectionState::Disconnected;
            return Err(StewardError::Mcp(format!(
                "server '{}' returned error on initialize: {:?}",
                name, init_response.error
            )));
        }

        // Send tools/list to discover available tools.
        let list_id = entry.next_request_id();
        let list_request = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(list_id)),
            method: Some("tools/list".to_string()),
            params: Some(json!({})),
            result: None,
            error: None,
        };

        entry.transport.send(list_request).await.map_err(|e| {
            entry.state = ConnectionState::Disconnected;
            StewardError::Mcp(format!("failed to send tools/list to '{}': {}", name, e))
        })?;

        let list_response = entry.transport.recv().await.map_err(|e| {
            entry.state = ConnectionState::Disconnected;
            StewardError::Mcp(format!(
                "failed to receive tools/list response from '{}': {}",
                name, e
            ))
        })?;

        // Parse the tool list from the response.
        let raw_tools = parse_tools_list_response(&list_response)?;

        // Apply manifest filtering and schema rewriting.
        let filtered_tools = entry.manifest.filter_tool_list(raw_tools);
        debug!(
            server = %name,
            tool_count = filtered_tools.len(),
            "cached filtered tool list"
        );

        entry.cached_tools = filtered_tools;

        // Transition to Active.
        entry.state = ConnectionState::Active;
        info!(server = %name, "MCP server is now Active");

        Ok(())
    }

    /// List all available tools across all active servers.
    ///
    /// Aggregates cached tool lists from all servers in Active state,
    /// applying manifest filtering and schema rewriting.
    pub async fn list_tools(&self) -> Result<Vec<ToolDefinition>, StewardError> {
        let servers = self.servers.read().await;
        let mut all_tools = Vec::new();

        for (server_name, entry) in servers.iter() {
            if entry.state != ConnectionState::Active {
                debug!(
                    server = %server_name,
                    state = %entry.state,
                    "skipping non-active server for tool listing"
                );
                continue;
            }

            for tool in &entry.cached_tools {
                all_tools.push(ToolDefinition {
                    name: tool.name.clone(),
                    description: tool.description.clone().unwrap_or_default(),
                    input_schema: tool.input_schema.clone(),
                    source: ToolSource::Mcp {
                        server_name: server_name.clone(),
                    },
                    permission_tier: entry
                        .manifest
                        .permission_tier_for(&tool.name)
                        .unwrap_or(steward_types::actions::PermissionTier::LogAndExecute),
                });
            }
        }

        Ok(all_tools)
    }

    /// Call a tool through the enforcement pipeline (section 8.10).
    ///
    /// Pipeline stages:
    /// 1. Route to correct server by tool name
    /// 2. Manifest check (allowed tool? allowed params?)
    /// 3. Rate limit check
    /// 4. Egress filter (outbound scan)
    /// 5. Forward to MCP server
    /// 6. Response scan (inbound)
    /// 7. Audit log
    /// 8. Return to agent
    pub async fn call_tool(
        &self,
        tool_name: &str,
        params: serde_json::Value,
    ) -> Result<ToolResult, StewardError> {
        // Stage 1: Route to the correct server.
        let server_name = self.find_server_for_tool(tool_name).await?;

        let mut servers = self.servers.write().await;
        let entry = servers.get_mut(&server_name).ok_or_else(|| {
            StewardError::Mcp(format!("server '{}' disappeared during call", server_name))
        })?;

        // Check connection state.
        if entry.state == ConnectionState::CircuitBroken {
            // Check if the circuit breaker has recovered.
            if entry.circuit_breaker.state() == CircuitState::HalfOpen {
                info!(
                    server = %server_name,
                    tool = %tool_name,
                    "circuit breaker is half-open, allowing probe call"
                );
                if !entry.circuit_breaker.attempt_probe() {
                    return Err(StewardError::Mcp(format!(
                        "server '{}' circuit breaker is not ready for probes",
                        server_name
                    )));
                }
            } else {
                return Err(StewardError::Mcp(format!(
                    "server '{}' is circuit-broken, tool '{}' is unavailable",
                    server_name, tool_name
                )));
            }
        } else if entry.state != ConnectionState::Active {
            return Err(StewardError::Mcp(format!(
                "server '{}' is in state {}, cannot call tools",
                server_name, entry.state
            )));
        }

        // Stage 2: Manifest check.
        let manifest_decision = entry.manifest.check_tool_call(tool_name, &params);
        match manifest_decision {
            ManifestDecision::Allow => {}
            ManifestDecision::Block { reason } => {
                warn!(
                    server = %server_name,
                    tool = %tool_name,
                    reason = %reason,
                    "manifest blocked tool call"
                );
                let _ = self
                    .log_tool_call(
                        tool_name,
                        &params,
                        &server_name,
                        ActionOutcome::Blocked {
                            reason: reason.clone(),
                        },
                    )
                    .await;
                return Ok(ToolResult {
                    success: false,
                    output: json!({"error": reason}),
                    error: Some(reason),
                });
            }
            ManifestDecision::RateLimit { retry_after_secs } => {
                let reason = format!(
                    "rate limit exceeded for tool '{}', retry after {}s",
                    tool_name, retry_after_secs
                );
                warn!(
                    server = %server_name,
                    tool = %tool_name,
                    retry_after_secs = retry_after_secs,
                    "rate limit exceeded"
                );
                let _ = self
                    .log_tool_call(
                        tool_name,
                        &params,
                        &server_name,
                        ActionOutcome::Blocked {
                            reason: reason.clone(),
                        },
                    )
                    .await;
                return Ok(ToolResult {
                    success: false,
                    output: json!({"error": reason, "retry_after_secs": retry_after_secs}),
                    error: Some(reason),
                });
            }
        }

        // Stage 3: Egress filter (outbound scan).
        let outbound = OutboundContent {
            text: serde_json::to_string(&params).unwrap_or_default(),
            action_type: format!("mcp:{}", tool_name),
            recipient: Some(server_name.clone()),
            metadata: json!({"server": server_name, "tool": tool_name}),
        };

        let egress_decision = self.egress_filter.filter(&outbound).await?;
        match egress_decision {
            EgressDecision::Pass => {}
            EgressDecision::Block {
                reason,
                patterns_found,
            } => {
                warn!(
                    server = %server_name,
                    tool = %tool_name,
                    reason = %reason,
                    patterns = ?patterns_found,
                    "egress filter blocked tool call"
                );
                let _ = self
                    .log_tool_call(
                        tool_name,
                        &params,
                        &server_name,
                        ActionOutcome::Blocked {
                            reason: reason.clone(),
                        },
                    )
                    .await;
                return Ok(ToolResult {
                    success: false,
                    output: json!({"error": reason, "patterns": patterns_found}),
                    error: Some(reason),
                });
            }
            EgressDecision::Warn { reason } => {
                warn!(
                    server = %server_name,
                    tool = %tool_name,
                    reason = %reason,
                    "egress filter warned on tool call"
                );
            }
        }

        // Stage 4: Forward to MCP server.
        let call_id = entry.next_request_id();
        let call_request = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(call_id)),
            method: Some("tools/call".to_string()),
            params: Some(json!({
                "name": tool_name,
                "arguments": params,
            })),
            result: None,
            error: None,
        };

        let send_result = entry.transport.send(call_request).await;
        if let Err(e) = send_result {
            entry.circuit_breaker.record_failure();
            if entry.circuit_breaker.state() == CircuitState::Open {
                entry.state = ConnectionState::CircuitBroken;
                warn!(
                    server = %server_name,
                    "circuit breaker tripped, server is now CIRCUIT_BROKEN"
                );
            }
            let _ = self
                .log_tool_call(
                    tool_name,
                    &params,
                    &server_name,
                    ActionOutcome::Failed {
                        error: e.to_string(),
                    },
                )
                .await;
            return Err(StewardError::Mcp(format!(
                "failed to send tool call to '{}': {}",
                server_name, e
            )));
        }

        let recv_result = entry.transport.recv().await;
        let response = match recv_result {
            Ok(resp) => resp,
            Err(e) => {
                entry.circuit_breaker.record_failure();
                if entry.circuit_breaker.state() == CircuitState::Open {
                    entry.state = ConnectionState::CircuitBroken;
                    warn!(
                        server = %server_name,
                        "circuit breaker tripped, server is now CIRCUIT_BROKEN"
                    );
                }
                let _ = self
                    .log_tool_call(
                        tool_name,
                        &params,
                        &server_name,
                        ActionOutcome::Failed {
                            error: e.to_string(),
                        },
                    )
                    .await;
                return Err(StewardError::Mcp(format!(
                    "failed to receive tool call response from '{}': {}",
                    server_name, e
                )));
            }
        };

        // Record success with the circuit breaker.
        entry.circuit_breaker.record_success();
        if entry.state == ConnectionState::CircuitBroken
            && entry.circuit_breaker.state() == CircuitState::Closed
        {
            entry.state = ConnectionState::Active;
            info!(
                server = %server_name,
                "circuit breaker recovered, server is now ACTIVE"
            );
        }

        // Stage 5: Parse the response.
        if let Some(error) = &response.error {
            let error_msg = format!(
                "MCP server '{}' returned error for '{}': {} (code: {})",
                server_name, tool_name, error.message, error.code
            );
            let _ = self
                .log_tool_call(
                    tool_name,
                    &params,
                    &server_name,
                    ActionOutcome::Failed {
                        error: error_msg.clone(),
                    },
                )
                .await;
            return Ok(ToolResult {
                success: false,
                output: json!({
                    "error": error.message,
                    "code": error.code,
                }),
                error: Some(error_msg),
            });
        }

        let result_value = response.result.unwrap_or(json!(null));

        // Stage 6: Response scan (inbound egress filter).
        let inbound = OutboundContent {
            text: serde_json::to_string(&result_value).unwrap_or_default(),
            action_type: format!("mcp_response:{}", tool_name),
            recipient: None,
            metadata: json!({"server": server_name, "tool": tool_name, "direction": "inbound"}),
        };

        if let Ok(EgressDecision::Block { reason, .. }) = self.egress_filter.filter(&inbound).await
        {
            warn!(
                server = %server_name,
                tool = %tool_name,
                reason = %reason,
                "egress filter blocked inbound response from MCP server"
            );
        }

        // Stage 7: Audit log.
        let _ = self
            .log_tool_call(tool_name, &params, &server_name, ActionOutcome::Executed)
            .await;

        // Stage 8: Return to agent.
        Ok(ToolResult {
            success: true,
            output: result_value,
            error: None,
        })
    }

    /// Refresh a server's cached tool list by re-sending tools/list.
    pub async fn refresh_tool_list(&self, name: &str) -> Result<(), StewardError> {
        let mut servers = self.servers.write().await;
        let entry = servers
            .get_mut(name)
            .ok_or_else(|| StewardError::Mcp(format!("server '{}' is not registered", name)))?;

        if entry.state != ConnectionState::Active {
            return Err(StewardError::Mcp(format!(
                "server '{}' is in state {}, cannot refresh tools",
                name, entry.state
            )));
        }

        let list_id = entry.next_request_id();
        let list_request = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(list_id)),
            method: Some("tools/list".to_string()),
            params: Some(json!({})),
            result: None,
            error: None,
        };

        entry.transport.send(list_request).await?;
        let response = entry.transport.recv().await?;
        let raw_tools = parse_tools_list_response(&response)?;
        entry.cached_tools = entry.manifest.filter_tool_list(raw_tools);

        debug!(
            server = %name,
            tool_count = entry.cached_tools.len(),
            "refreshed tool list"
        );

        Ok(())
    }

    /// Hot-reload a server's manifest without disconnecting.
    ///
    /// Updates the manifest and refreshes the cached tool list with the new
    /// filtering/rewriting rules.
    pub async fn reload_manifest(
        &self,
        name: &str,
        new_manifest: McpManifestImpl,
    ) -> Result<(), StewardError> {
        let mut servers = self.servers.write().await;
        let entry = servers
            .get_mut(name)
            .ok_or_else(|| StewardError::Mcp(format!("server '{}' is not registered", name)))?;

        info!(server = %name, "hot-reloading manifest");

        // Re-filter the existing cached tools against the new manifest.
        // We need to get the unfiltered list, but since we only have the filtered
        // one, we'll re-send tools/list if active.
        entry.manifest = new_manifest;

        if entry.state == ConnectionState::Active {
            let list_id = entry.next_request_id();
            let list_request = JsonRpcMessage {
                jsonrpc: "2.0".to_string(),
                id: Some(json!(list_id)),
                method: Some("tools/list".to_string()),
                params: Some(json!({})),
                result: None,
                error: None,
            };

            if entry.transport.send(list_request).await.is_ok() {
                if let Ok(response) = entry.transport.recv().await {
                    if let Ok(raw_tools) = parse_tools_list_response(&response) {
                        entry.cached_tools = entry.manifest.filter_tool_list(raw_tools);
                        info!(
                            server = %name,
                            tool_count = entry.cached_tools.len(),
                            "manifest reloaded, tool list updated"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Get the current connection state for a server.
    pub async fn server_state(&self, name: &str) -> Option<ConnectionState> {
        let servers = self.servers.read().await;
        servers.get(name).map(|e| e.state)
    }

    /// Get a list of all registered server names.
    pub async fn server_names(&self) -> Vec<String> {
        let servers = self.servers.read().await;
        servers.keys().cloned().collect()
    }

    /// Find which server provides a given tool.
    async fn find_server_for_tool(&self, tool_name: &str) -> Result<String, StewardError> {
        let servers = self.servers.read().await;
        for (name, entry) in servers.iter() {
            if (entry.state == ConnectionState::Active
                || entry.state == ConnectionState::CircuitBroken)
                && entry.cached_tools.iter().any(|t| t.name == tool_name)
            {
                return Ok(name.clone());
            }
        }
        Err(StewardError::Mcp(format!(
            "no active server provides tool '{}'",
            tool_name
        )))
    }

    /// Log a tool call to the audit logger.
    async fn log_tool_call(
        &self,
        tool_name: &str,
        params: &serde_json::Value,
        server_name: &str,
        outcome: ActionOutcome,
    ) -> Result<(), StewardError> {
        let event = AuditEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            event_type: AuditEventType::ToolCall,
            action: None,
            guardian_verdict: None,
            permission_tier: None,
            outcome,
            metadata: json!({
                "tool_name": tool_name,
                "server": server_name,
                "params_summary": summarize_params(params),
            }),
        };
        if let Err(e) = self.audit_logger.log(event).await {
            error!(error = %e, "failed to log audit event for MCP tool call");
        }
        Ok(())
    }
}

// ============================================================
// Helper Functions
// ============================================================

/// Parse a `tools/list` JSON-RPC response into a list of tool definitions.
fn parse_tools_list_response(response: &JsonRpcMessage) -> Result<Vec<McpToolDef>, StewardError> {
    if let Some(ref error) = response.error {
        return Err(StewardError::Mcp(format!(
            "tools/list error: {} (code: {})",
            error.message, error.code
        )));
    }

    let result = response
        .result
        .as_ref()
        .ok_or_else(|| StewardError::Mcp("tools/list response has no result".to_string()))?;

    let tools_value = result
        .get("tools")
        .ok_or_else(|| StewardError::Mcp("tools/list result has no 'tools' field".to_string()))?;

    let tools: Vec<McpToolDef> = serde_json::from_value(tools_value.clone())
        .map_err(|e| StewardError::Mcp(format!("failed to parse tools list: {}", e)))?;

    Ok(tools)
}

/// Summarize tool call parameters for audit logging (avoid logging full content).
fn summarize_params(params: &serde_json::Value) -> serde_json::Value {
    match params {
        serde_json::Value::Object(map) => {
            let keys: Vec<&String> = map.keys().collect();
            json!({
                "param_count": keys.len(),
                "param_names": keys,
            })
        }
        _ => json!({"type": "non-object"}),
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::manifest::ManifestConfig;
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::Mutex;
    use steward_types::actions::{AuditFilter, JsonRpcError, SensitivePattern};
    use steward_types::config::CircuitBreakerConfig;

    // ── Mock Transport ────────────────────────────────────────

    /// A mock transport that replays pre-programmed responses.
    struct MockTransport {
        responses: Mutex<Vec<JsonRpcMessage>>,
        sent: Mutex<Vec<JsonRpcMessage>>,
        connected: Mutex<bool>,
    }

    impl MockTransport {
        fn new(responses: Vec<JsonRpcMessage>) -> Self {
            Self {
                responses: Mutex::new(responses),
                sent: Mutex::new(Vec::new()),
                connected: Mutex::new(true),
            }
        }

    }

    #[async_trait]
    impl McpTransport for MockTransport {
        async fn send(&mut self, message: JsonRpcMessage) -> Result<(), StewardError> {
            let connected = *self.connected.lock().unwrap();
            if !connected {
                return Err(StewardError::Mcp("transport is closed".to_string()));
            }
            self.sent.lock().unwrap().push(message);
            Ok(())
        }

        async fn recv(&mut self) -> Result<JsonRpcMessage, StewardError> {
            let connected = *self.connected.lock().unwrap();
            if !connected {
                return Err(StewardError::Mcp("transport is closed".to_string()));
            }
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Err(StewardError::Mcp("no more mock responses".to_string()))
            } else {
                Ok(responses.remove(0))
            }
        }

        async fn close(&mut self) -> Result<(), StewardError> {
            *self.connected.lock().unwrap() = false;
            Ok(())
        }

        fn is_connected(&self) -> bool {
            *self.connected.lock().unwrap()
        }
    }

    // ── Mock Transport that always fails ──────────────────────

    struct FailingTransport;

    #[async_trait]
    impl McpTransport for FailingTransport {
        async fn send(&mut self, _message: JsonRpcMessage) -> Result<(), StewardError> {
            Err(StewardError::Mcp("connection refused".to_string()))
        }
        async fn recv(&mut self) -> Result<JsonRpcMessage, StewardError> {
            Err(StewardError::Mcp("connection refused".to_string()))
        }
        async fn close(&mut self) -> Result<(), StewardError> {
            Ok(())
        }
        fn is_connected(&self) -> bool {
            false
        }
    }

    // ── Mock Egress Filter ────────────────────────────────────

    struct MockEgressFilter {
        /// If set, the filter blocks everything with this reason.
        block_reason: Option<String>,
    }

    impl MockEgressFilter {
        fn pass() -> Self {
            Self { block_reason: None }
        }

        fn blocking(reason: &str) -> Self {
            Self {
                block_reason: Some(reason.to_string()),
            }
        }
    }

    #[async_trait]
    impl EgressFilter for MockEgressFilter {
        async fn filter(&self, _content: &OutboundContent) -> Result<EgressDecision, StewardError> {
            match &self.block_reason {
                None => Ok(EgressDecision::Pass),
                Some(reason) => Ok(EgressDecision::Block {
                    reason: reason.clone(),
                    patterns_found: vec!["mock_pattern".to_string()],
                }),
            }
        }

        fn register_pattern(&mut self, _pattern: SensitivePattern) {}
    }

    // ── Mock Audit Logger ─────────────────────────────────────

    struct MockAuditLogger {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl MockAuditLogger {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }

        fn event_count(&self) -> usize {
            self.events.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl AuditLogger for MockAuditLogger {
        async fn log(&self, event: AuditEvent) -> Result<(), StewardError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }

        async fn query(&self, _filter: AuditFilter) -> Result<Vec<AuditEvent>, StewardError> {
            Ok(self.events.lock().unwrap().clone())
        }
    }

    // ── Helpers ───────────────────────────────────────────────

    fn make_init_response(id: u64) -> JsonRpcMessage {
        JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(id)),
            method: None,
            params: None,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "test-server", "version": "1.0"}
            })),
            error: None,
        }
    }

    fn make_tools_list_response(id: u64, tools: Vec<McpToolDef>) -> JsonRpcMessage {
        JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(id)),
            method: None,
            params: None,
            result: Some(json!({"tools": tools})),
            error: None,
        }
    }

    fn make_tool_call_response(id: u64, result: serde_json::Value) -> JsonRpcMessage {
        JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(id)),
            method: None,
            params: None,
            result: Some(result),
            error: None,
        }
    }

    fn make_tool_call_error_response(id: u64, code: i64, message: &str) -> JsonRpcMessage {
        JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(id)),
            method: None,
            params: None,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }

    fn make_gmail_manifest() -> McpManifestImpl {
        let config: ManifestConfig = serde_yaml::from_str(
            r#"
server: gmail-mcp
transport: stdio
allowed_tools:
  - name: gmail.search
    allowed: true
    rate_limit: "30/minute"
  - name: gmail.read
    allowed: true
  - name: gmail.send
    allowed: true
    requires_approval: true
    rate_limit: "3/minute"
  - name: gmail.delete
    allowed: false
blocked_tools:
  - gmail.create_filter
blocked_params:
  - "*.bcc"
  - "*.forward_to"
"#,
        )
        .unwrap();
        McpManifestImpl::from_config(config).unwrap()
    }

    fn make_calendar_manifest() -> McpManifestImpl {
        let config: ManifestConfig = serde_yaml::from_str(
            r#"
server: calendar-mcp
transport: stdio
allowed_tools:
  - name: calendar.list
    allowed: true
  - name: calendar.create
    allowed: true
    requires_approval: true
blocked_tools: []
blocked_params: []
"#,
        )
        .unwrap();
        McpManifestImpl::from_config(config).unwrap()
    }

    fn gmail_tools() -> Vec<McpToolDef> {
        vec![
            McpToolDef {
                name: "gmail.search".to_string(),
                description: Some("Search emails".to_string()),
                input_schema: json!({"type": "object", "properties": {"query": {"type": "string"}}}),
            },
            McpToolDef {
                name: "gmail.read".to_string(),
                description: Some("Read an email".to_string()),
                input_schema: json!({"type": "object", "properties": {"id": {"type": "string"}}}),
            },
            McpToolDef {
                name: "gmail.send".to_string(),
                description: Some("Send an email".to_string()),
                input_schema: json!({"type": "object", "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}}),
            },
            McpToolDef {
                name: "gmail.delete".to_string(),
                description: Some("Delete an email".to_string()),
                input_schema: json!({"type": "object", "properties": {"id": {"type": "string"}}}),
            },
            McpToolDef {
                name: "gmail.create_filter".to_string(),
                description: Some("Create a filter".to_string()),
                input_schema: json!({"type": "object", "properties": {}}),
            },
        ]
    }

    fn calendar_tools() -> Vec<McpToolDef> {
        vec![
            McpToolDef {
                name: "calendar.list".to_string(),
                description: Some("List events".to_string()),
                input_schema: json!({"type": "object", "properties": {"date": {"type": "string"}}}),
            },
            McpToolDef {
                name: "calendar.create".to_string(),
                description: Some("Create an event".to_string()),
                input_schema: json!({"type": "object", "properties": {"title": {"type": "string"}}}),
            },
        ]
    }

    fn default_cb() -> McpCircuitBreaker {
        McpCircuitBreaker::new(CircuitBreakerConfig {
            error_threshold: 3,
            error_window_secs: 60,
            latency_threshold_secs: 30,
            recovery_timeout_secs: 0,
            recovery_probes: 1,
            max_recovery_backoff_secs: 60,
        })
    }

    fn create_proxy() -> (McpProxy, Arc<MockAuditLogger>) {
        let audit = Arc::new(MockAuditLogger::new());
        let egress = Arc::new(MockEgressFilter::pass());
        let proxy = McpProxy::new(egress, audit.clone());
        (proxy, audit)
    }

    fn create_proxy_with_blocking_egress(reason: &str) -> (McpProxy, Arc<MockAuditLogger>) {
        let audit = Arc::new(MockAuditLogger::new());
        let egress = Arc::new(MockEgressFilter::blocking(reason));
        let proxy = McpProxy::new(egress, audit.clone());
        (proxy, audit)
    }

    /// Register and connect a mock server with canned responses.
    async fn setup_server(
        proxy: &McpProxy,
        name: &str,
        manifest: McpManifestImpl,
        tools: Vec<McpToolDef>,
    ) {
        // init response (id=1) + tools/list response (id=2)
        let transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, tools),
        ]));
        proxy
            .add_server(name.to_string(), manifest, transport, default_cb())
            .await
            .unwrap();
        proxy.connect_server(name).await.unwrap();
    }

    // ── Test: tools/list filtering across multiple servers ────

    #[tokio::test]
    async fn test_list_tools_multiple_servers() {
        let (proxy, _audit) = create_proxy();

        setup_server(&proxy, "gmail-mcp", make_gmail_manifest(), gmail_tools()).await;
        setup_server(
            &proxy,
            "calendar-mcp",
            make_calendar_manifest(),
            calendar_tools(),
        )
        .await;

        let tools = proxy.list_tools().await.unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

        // Gmail: search, read, send allowed; delete + create_filter filtered out.
        assert!(names.contains(&"gmail.search"));
        assert!(names.contains(&"gmail.read"));
        assert!(names.contains(&"gmail.send"));
        assert!(
            !names.contains(&"gmail.delete"),
            "delete should be filtered"
        );
        assert!(
            !names.contains(&"gmail.create_filter"),
            "create_filter should be filtered"
        );

        // Calendar: list and create both allowed.
        assert!(names.contains(&"calendar.list"));
        assert!(names.contains(&"calendar.create"));

        // Verify sources.
        let gmail_tool = tools.iter().find(|t| t.name == "gmail.search").unwrap();
        match &gmail_tool.source {
            ToolSource::Mcp { server_name } => assert_eq!(server_name, "gmail-mcp"),
            _ => panic!("expected MCP source"),
        }
    }

    // ── Test: tools/call routing to correct server ────────────

    #[tokio::test]
    async fn test_call_tool_routes_to_correct_server() {
        let (proxy, audit) = create_proxy();

        // Gmail server with a tool call response for gmail.search.
        let gmail_transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
            make_tool_call_response(3, json!({"emails": [{"id": "1", "subject": "Hello"}]})),
        ]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                gmail_transport,
                default_cb(),
            )
            .await
            .unwrap();
        proxy.connect_server("gmail-mcp").await.unwrap();

        // Calendar server with a tool call response for calendar.list.
        let cal_transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, calendar_tools()),
            make_tool_call_response(3, json!({"events": []})),
        ]));
        proxy
            .add_server(
                "calendar-mcp".to_string(),
                make_calendar_manifest(),
                cal_transport,
                default_cb(),
            )
            .await
            .unwrap();
        proxy.connect_server("calendar-mcp").await.unwrap();

        // Call gmail.search → should route to gmail-mcp.
        let result = proxy
            .call_tool("gmail.search", json!({"query": "from:alice"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.get("emails").is_some());

        // Call calendar.list → should route to calendar-mcp.
        let result = proxy
            .call_tool("calendar.list", json!({"date": "2026-02-22"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.get("events").is_some());

        // Audit events should be logged.
        assert!(audit.event_count() >= 2);
    }

    // ── Test: blocked tool is rejected ────────────────────────

    #[tokio::test]
    async fn test_blocked_tool_rejected() {
        let (proxy, _audit) = create_proxy();
        setup_server(&proxy, "gmail-mcp", make_gmail_manifest(), gmail_tools()).await;

        // gmail.delete is not in the filtered tool list, but let's try to call it.
        let result = proxy
            .call_tool("gmail.delete", json!({"id": "msg-123"}))
            .await;

        // Should fail because no server provides gmail.delete (it was filtered).
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no active server provides tool"),
            "unexpected error: {}",
            err_msg
        );
    }

    // ── Test: blocked parameter is rejected ───────────────────

    #[tokio::test]
    async fn test_blocked_param_rejected() {
        let (proxy, _audit) = create_proxy();

        // Set up gmail-mcp with a response for tools/call (though it shouldn't reach it).
        let transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
            // This shouldn't be consumed because the manifest blocks the call.
            make_tool_call_response(3, json!({"sent": true})),
        ]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();
        proxy.connect_server("gmail-mcp").await.unwrap();

        // Try to call gmail.send with a bcc field (blocked by manifest).
        let result = proxy
            .call_tool(
                "gmail.send",
                json!({
                    "to": "alice@example.com",
                    "subject": "Test",
                    "body": "Hello",
                    "bcc": "hidden@example.com"
                }),
            )
            .await
            .unwrap();

        assert!(!result.success);
        assert!(
            result.error.as_ref().unwrap().contains("blocked"),
            "expected blocked error, got: {:?}",
            result.error
        );
    }

    // ── Test: rate limit enforcement ──────────────────────────

    #[tokio::test]
    async fn test_rate_limit_enforcement() {
        let (proxy, _audit) = create_proxy();

        // gmail.send has rate_limit: "3/minute"
        // Prepare enough responses for multiple calls.
        let mut responses = vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
        ];
        for id in 3..10 {
            responses.push(make_tool_call_response(id, json!({"sent": true})));
        }

        let transport = Box::new(MockTransport::new(responses));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();
        proxy.connect_server("gmail-mcp").await.unwrap();

        let send_params = json!({
            "to": "alice@example.com",
            "subject": "Test",
            "body": "Hello"
        });

        // First 3 calls should succeed.
        for _ in 0..3 {
            let result = proxy
                .call_tool("gmail.send", send_params.clone())
                .await
                .unwrap();
            assert!(result.success, "expected success, got: {:?}", result.error);
        }

        // 4th call should be rate-limited.
        let result = proxy
            .call_tool("gmail.send", send_params.clone())
            .await
            .unwrap();
        assert!(!result.success);
        assert!(
            result.error.as_ref().unwrap().contains("rate limit"),
            "expected rate limit error, got: {:?}",
            result.error
        );
    }

    // ── Test: egress filter blocks tool call ──────────────────

    #[tokio::test]
    async fn test_egress_filter_blocks_tool_call() {
        let (proxy, _audit) = create_proxy_with_blocking_egress("PII detected in parameters");

        let transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
        ]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();
        proxy.connect_server("gmail-mcp").await.unwrap();

        let result = proxy
            .call_tool("gmail.search", json!({"query": "SSN: 123-45-6789"}))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(
            result.error.as_ref().unwrap().contains("PII detected"),
            "expected egress block, got: {:?}",
            result.error
        );
    }

    // ── Test: circuit breaker integration ─────────────────────

    #[tokio::test]
    async fn test_circuit_breaker_integration() {
        let (proxy, _audit) = create_proxy();

        // Use a circuit breaker with threshold of 2.
        let cb = McpCircuitBreaker::new(CircuitBreakerConfig {
            error_threshold: 2,
            error_window_secs: 60,
            latency_threshold_secs: 30,
            recovery_timeout_secs: 0, // immediate recovery for testing
            recovery_probes: 1,
            max_recovery_backoff_secs: 60,
        });

        // Server responds to init + tools/list, then fails on tool calls.
        let transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
            // Tool call will fail (transport error, simulated by empty responses).
        ]));

        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                cb,
            )
            .await
            .unwrap();
        proxy.connect_server("gmail-mcp").await.unwrap();

        // First call: transport will run out of responses → error → record failure.
        let result = proxy
            .call_tool("gmail.search", json!({"query": "test"}))
            .await;
        assert!(result.is_err());

        // The server should still be active (1 failure < threshold of 2).
        let state = proxy.server_state("gmail-mcp").await.unwrap();
        assert_eq!(state, ConnectionState::Active);
    }

    // ── Test: add and remove server dynamically ───────────────

    #[tokio::test]
    async fn test_add_remove_server() {
        let (proxy, _audit) = create_proxy();

        // Initially no servers.
        assert!(proxy.server_names().await.is_empty());

        // Add a server.
        let transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
        ]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();

        assert_eq!(proxy.server_names().await.len(), 1);
        assert_eq!(
            proxy.server_state("gmail-mcp").await.unwrap(),
            ConnectionState::Registered
        );

        // Connect the server.
        proxy.connect_server("gmail-mcp").await.unwrap();
        assert_eq!(
            proxy.server_state("gmail-mcp").await.unwrap(),
            ConnectionState::Active
        );

        // List tools.
        let tools = proxy.list_tools().await.unwrap();
        assert!(!tools.is_empty());

        // Remove the server.
        proxy.remove_server("gmail-mcp").await.unwrap();
        assert!(proxy.server_names().await.is_empty());
        assert!(proxy.server_state("gmail-mcp").await.is_none());
    }

    // ── Test: duplicate server add fails ──────────────────────

    #[tokio::test]
    async fn test_duplicate_server_add_fails() {
        let (proxy, _audit) = create_proxy();

        let transport1 = Box::new(MockTransport::new(vec![]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport1,
                default_cb(),
            )
            .await
            .unwrap();

        let transport2 = Box::new(MockTransport::new(vec![]));
        let result = proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport2,
                default_cb(),
            )
            .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("already registered"));
    }

    // ── Test: remove nonexistent server fails ─────────────────

    #[tokio::test]
    async fn test_remove_nonexistent_server_fails() {
        let (proxy, _audit) = create_proxy();

        let result = proxy.remove_server("nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not registered"));
    }

    // ── Test: connection state transitions ────────────────────

    #[tokio::test]
    async fn test_connection_state_transitions() {
        let (proxy, _audit) = create_proxy();

        let transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
        ]));

        // Add → Registered.
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();
        assert_eq!(
            proxy.server_state("gmail-mcp").await.unwrap(),
            ConnectionState::Registered
        );

        // Connect → Active.
        proxy.connect_server("gmail-mcp").await.unwrap();
        assert_eq!(
            proxy.server_state("gmail-mcp").await.unwrap(),
            ConnectionState::Active
        );

        // Remove → gone.
        proxy.remove_server("gmail-mcp").await.unwrap();
        assert!(proxy.server_state("gmail-mcp").await.is_none());
    }

    // ── Test: call to nonexistent tool returns error ──────────

    #[tokio::test]
    async fn test_call_nonexistent_tool() {
        let (proxy, _audit) = create_proxy();
        setup_server(&proxy, "gmail-mcp", make_gmail_manifest(), gmail_tools()).await;

        let result = proxy.call_tool("nonexistent.tool", json!({})).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no active server provides tool"));
    }

    // ── Test: call tool when server is not active ─────────────

    #[tokio::test]
    async fn test_call_tool_on_registered_server() {
        let (proxy, _audit) = create_proxy();

        let transport = Box::new(MockTransport::new(vec![]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();

        // Server is Registered, not Active — no tools in cached list.
        let result = proxy
            .call_tool("gmail.search", json!({"query": "test"}))
            .await;
        assert!(result.is_err());
    }

    // ── Test: non-active servers excluded from tool listing ───

    #[tokio::test]
    async fn test_non_active_servers_excluded_from_listing() {
        let (proxy, _audit) = create_proxy();

        // Add a server but don't connect it.
        let transport = Box::new(MockTransport::new(vec![]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();

        // Tool list should be empty because server is not Active.
        let tools = proxy.list_tools().await.unwrap();
        assert!(tools.is_empty());
    }

    // ── Test: MCP server error response handled ───────────────

    #[tokio::test]
    async fn test_mcp_server_error_response() {
        let (proxy, _audit) = create_proxy();

        let transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
            make_tool_call_error_response(3, -32600, "invalid params"),
        ]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();
        proxy.connect_server("gmail-mcp").await.unwrap();

        let result = proxy
            .call_tool("gmail.search", json!({"query": "test"}))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("invalid params"));
    }

    // ── Test: audit events are logged ─────────────────────────

    #[tokio::test]
    async fn test_audit_events_logged() {
        let (proxy, audit) = create_proxy();

        let transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
            make_tool_call_response(3, json!({"emails": []})),
        ]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();
        proxy.connect_server("gmail-mcp").await.unwrap();

        let _result = proxy
            .call_tool("gmail.search", json!({"query": "test"}))
            .await
            .unwrap();

        assert!(audit.event_count() > 0, "expected at least one audit event");
    }

    // ── Test: hot-reload manifest ─────────────────────────────

    #[tokio::test]
    async fn test_hot_reload_manifest() {
        let (proxy, _audit) = create_proxy();

        // Start with a manifest that allows gmail.search, gmail.read, gmail.send.
        let transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
            // Response for re-fetching tools/list after reload.
            make_tools_list_response(3, gmail_tools()),
        ]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();
        proxy.connect_server("gmail-mcp").await.unwrap();

        let tools_before = proxy.list_tools().await.unwrap();
        let names_before: Vec<&str> = tools_before.iter().map(|t| t.name.as_str()).collect();
        assert!(names_before.contains(&"gmail.send"));

        // Hot-reload with a more restrictive manifest that blocks gmail.send.
        let new_config: ManifestConfig = serde_yaml::from_str(
            r#"
server: gmail-mcp
transport: stdio
allowed_tools:
  - name: gmail.search
    allowed: true
  - name: gmail.read
    allowed: true
  - name: gmail.send
    allowed: false
blocked_tools: []
blocked_params: []
"#,
        )
        .unwrap();
        let new_manifest = McpManifestImpl::from_config(new_config).unwrap();
        proxy
            .reload_manifest("gmail-mcp", new_manifest)
            .await
            .unwrap();

        let tools_after = proxy.list_tools().await.unwrap();
        let names_after: Vec<&str> = tools_after.iter().map(|t| t.name.as_str()).collect();
        assert!(
            !names_after.contains(&"gmail.send"),
            "gmail.send should be filtered after manifest reload"
        );
        assert!(names_after.contains(&"gmail.search"));
        assert!(names_after.contains(&"gmail.read"));
    }

    // ── Test: connection failure transitions to Disconnected ──

    #[tokio::test]
    async fn test_connection_failure_transitions_to_disconnected() {
        let (proxy, _audit) = create_proxy();

        // Transport that fails on init.
        let transport = Box::new(FailingTransport);
        proxy
            .add_server(
                "bad-server".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();

        let result = proxy.connect_server("bad-server").await;
        assert!(result.is_err());

        let state = proxy.server_state("bad-server").await.unwrap();
        assert_eq!(state, ConnectionState::Disconnected);
    }

    // ── Test: parse_tools_list_response ───────────────────────

    #[test]
    fn test_parse_tools_list_response_success() {
        let response = make_tools_list_response(1, gmail_tools());
        let tools = parse_tools_list_response(&response).unwrap();
        assert_eq!(tools.len(), 5);
        assert_eq!(tools[0].name, "gmail.search");
    }

    #[test]
    fn test_parse_tools_list_response_error() {
        let response = make_tool_call_error_response(1, -32600, "bad request");
        let result = parse_tools_list_response(&response);
        assert!(result.is_err());
    }

    // ── Test: summarize_params ────────────────────────────────

    #[test]
    fn test_summarize_params() {
        let params = json!({"to": "alice", "subject": "Hi", "body": "Hello"});
        let summary = summarize_params(&params);
        assert_eq!(summary["param_count"], 3);

        let non_obj = json!("just a string");
        let summary = summarize_params(&non_obj);
        assert_eq!(summary["type"], "non-object");
    }

    // ── Test: successful tool call with full pipeline ─────────

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let (proxy, audit) = create_proxy();

        let transport = Box::new(MockTransport::new(vec![
            make_init_response(1),
            make_tools_list_response(2, gmail_tools()),
            make_tool_call_response(
                3,
                json!({"emails": [{"id": "1", "subject": "Meeting", "from": "boss@company.com"}]}),
            ),
        ]));
        proxy
            .add_server(
                "gmail-mcp".to_string(),
                make_gmail_manifest(),
                transport,
                default_cb(),
            )
            .await
            .unwrap();
        proxy.connect_server("gmail-mcp").await.unwrap();

        let result = proxy
            .call_tool("gmail.search", json!({"query": "from:boss"}))
            .await
            .unwrap();

        assert!(result.success);
        assert!(result.error.is_none());
        assert!(result.output["emails"].is_array());
        assert_eq!(result.output["emails"][0]["subject"], "Meeting");

        // Verify audit was logged.
        assert!(audit.event_count() > 0);
    }
}
