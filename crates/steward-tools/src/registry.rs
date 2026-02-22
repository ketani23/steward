//! Tool registry implementation.
//!
//! Central registry managing three categories of tools:
//! - Built-in tools (direct function calls, trusted)
//! - WASM tools (sandboxed, capability-manifest-enforced) — stub for now
//! - MCP tools (proxied through McpProxy)
//!
//! The registry provides unified tool discovery via [`ToolRegistryImpl::list_tools`] and
//! source-based execution routing via [`ToolRegistryImpl::execute`]. Tools can be
//! registered and unregistered at runtime with thread-safe concurrent access.
//!
//! See `docs/architecture.md` section 5 for tool categorization.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use steward_types::actions::{ToolCall, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;
use steward_types::traits::ToolRegistry;

/// Handler for built-in tool execution.
///
/// Each built-in tool registers a handler that implements this trait.
/// The handler receives the tool parameters and returns the execution result.
#[async_trait]
pub trait BuiltInHandler: Send + Sync {
    /// Execute the built-in tool with the given parameters.
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError>;
}

/// Interface for delegating tool calls to MCP servers.
///
/// The tool registry uses this to forward MCP tool calls to the MCP proxy,
/// which handles manifest enforcement, egress filtering, and transport.
#[async_trait]
pub trait McpExecutor: Send + Sync {
    /// Execute a tool call through the MCP proxy for a given server.
    async fn execute_tool(
        &self,
        server_name: &str,
        tool_name: &str,
        parameters: serde_json::Value,
    ) -> Result<ToolResult, StewardError>;
}

/// Central tool registry managing built-in, WASM, and MCP tools.
///
/// Provides unified tool discovery and execution routing. Uses [`RwLock`] for
/// thread-safe concurrent access — tools can be registered and unregistered
/// while the agent is running without blocking concurrent read operations.
pub struct ToolRegistryImpl {
    /// All registered tool definitions, keyed by tool name.
    tools: RwLock<HashMap<String, ToolDefinition>>,
    /// Handlers for built-in tools, keyed by tool name.
    built_in_handlers: RwLock<HashMap<String, Arc<dyn BuiltInHandler>>>,
    /// Optional MCP executor for delegating MCP tool calls.
    mcp_executor: Option<Arc<dyn McpExecutor>>,
}

impl Default for ToolRegistryImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistryImpl {
    /// Create a new empty tool registry.
    pub fn new() -> Self {
        Self {
            tools: RwLock::new(HashMap::new()),
            built_in_handlers: RwLock::new(HashMap::new()),
            mcp_executor: None,
        }
    }

    /// Create a new tool registry with an MCP executor for proxied tool calls.
    pub fn with_mcp_executor(mcp_executor: Arc<dyn McpExecutor>) -> Self {
        Self {
            tools: RwLock::new(HashMap::new()),
            built_in_handlers: RwLock::new(HashMap::new()),
            mcp_executor: Some(mcp_executor),
        }
    }

    /// Register a built-in tool with its execution handler.
    ///
    /// The tool definition must have [`ToolSource::BuiltIn`] as its source.
    /// The handler is stored separately and invoked when the tool is executed.
    pub async fn register_built_in(
        &self,
        definition: ToolDefinition,
        handler: Arc<dyn BuiltInHandler>,
    ) -> Result<(), StewardError> {
        if !matches!(definition.source, ToolSource::BuiltIn) {
            return Err(StewardError::Tool(
                "cannot register non-built-in tool with register_built_in".to_string(),
            ));
        }
        let name = definition.name.clone();
        self.tools.write().await.insert(name.clone(), definition);
        self.built_in_handlers
            .write()
            .await
            .insert(name.clone(), handler);
        info!(tool_name = %name, "registered built-in tool");
        Ok(())
    }

    /// Unregister a tool by name, removing it from the registry.
    ///
    /// Returns an error if the tool is not found. Also removes any associated
    /// built-in handler.
    pub async fn unregister(&self, tool_name: &str) -> Result<(), StewardError> {
        let removed = self.tools.write().await.remove(tool_name);
        self.built_in_handlers.write().await.remove(tool_name);
        match removed {
            Some(_) => {
                info!(tool_name = %tool_name, "unregistered tool");
                Ok(())
            }
            None => Err(StewardError::Tool(format!("tool not found: {tool_name}"))),
        }
    }
}

#[async_trait]
impl ToolRegistry for ToolRegistryImpl {
    /// List all registered tools from all sources.
    async fn list_tools(&self) -> Result<Vec<ToolDefinition>, StewardError> {
        let tools = self.tools.read().await;
        Ok(tools.values().cloned().collect())
    }

    /// Execute a tool call, routing to the correct backend based on tool source.
    ///
    /// - [`ToolSource::BuiltIn`] → direct call via registered handler
    /// - [`ToolSource::Mcp`] → delegate to MCP executor
    /// - [`ToolSource::Wasm`] → returns error (not yet implemented)
    async fn execute(&self, call: ToolCall) -> Result<ToolResult, StewardError> {
        let tools = self.tools.read().await;
        let tool_def = tools
            .get(&call.tool_name)
            .ok_or_else(|| StewardError::Tool(format!("unknown tool: {}", call.tool_name)))?;

        match &tool_def.source {
            ToolSource::BuiltIn => {
                // Release tools read lock before acquiring handlers read lock
                drop(tools);
                let handlers = self.built_in_handlers.read().await;
                let handler = handlers.get(&call.tool_name).ok_or_else(|| {
                    StewardError::Tool(format!(
                        "no handler registered for built-in tool: {}",
                        call.tool_name
                    ))
                })?;
                debug!(tool_name = %call.tool_name, "executing built-in tool");
                handler.execute(call.parameters).await
            }
            ToolSource::Mcp { server_name } => {
                let server_name = server_name.clone();
                let tool_name = call.tool_name.clone();
                drop(tools);
                let executor = self
                    .mcp_executor
                    .as_ref()
                    .ok_or_else(|| StewardError::Mcp("no MCP executor configured".to_string()))?;
                debug!(
                    tool_name = %tool_name,
                    server = %server_name,
                    "executing MCP tool"
                );
                executor
                    .execute_tool(&server_name, &tool_name, call.parameters)
                    .await
            }
            ToolSource::Wasm { module_path } => {
                warn!(
                    tool_name = %call.tool_name,
                    module_path = %module_path,
                    "WASM tool execution not yet implemented"
                );
                Err(StewardError::Tool(format!(
                    "WASM tool execution not yet implemented: {}",
                    call.tool_name
                )))
            }
        }
    }

    /// Register a new tool definition in the registry.
    ///
    /// For built-in tools, prefer [`ToolRegistryImpl::register_built_in`] which
    /// also registers the execution handler.
    async fn register(&mut self, tool: ToolDefinition) -> Result<(), StewardError> {
        let name = tool.name.clone();
        let source = match &tool.source {
            ToolSource::BuiltIn => "BuiltIn".to_string(),
            ToolSource::Mcp { server_name } => format!("Mcp({})", server_name),
            ToolSource::Wasm { module_path } => format!("Wasm({})", module_path),
        };
        self.tools.write().await.insert(name.clone(), tool);
        info!(tool_name = %name, source = %source, "registered tool");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use steward_types::actions::PermissionTier;
    use uuid::Uuid;

    /// A mock built-in handler that echoes back the parameters.
    struct EchoHandler;

    #[async_trait]
    impl BuiltInHandler for EchoHandler {
        async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
            Ok(ToolResult {
                success: true,
                output: serde_json::json!({ "echo": parameters }),
                error: None,
            })
        }
    }

    /// A mock built-in handler that always fails.
    struct FailingHandler;

    #[async_trait]
    impl BuiltInHandler for FailingHandler {
        async fn execute(
            &self,
            _parameters: serde_json::Value,
        ) -> Result<ToolResult, StewardError> {
            Err(StewardError::Tool("handler error".to_string()))
        }
    }

    /// A mock MCP executor that records calls and returns a fixed result.
    struct MockMcpExecutor;

    #[async_trait]
    impl McpExecutor for MockMcpExecutor {
        async fn execute_tool(
            &self,
            server_name: &str,
            tool_name: &str,
            parameters: serde_json::Value,
        ) -> Result<ToolResult, StewardError> {
            Ok(ToolResult {
                success: true,
                output: serde_json::json!({
                    "server": server_name,
                    "tool": tool_name,
                    "params": parameters,
                }),
                error: None,
            })
        }
    }

    fn make_built_in_tool(name: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: format!("Built-in tool: {name}"),
            input_schema: serde_json::json!({"type": "object"}),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::AutoExecute,
        }
    }

    fn make_mcp_tool(name: &str, server: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: format!("MCP tool: {name}"),
            input_schema: serde_json::json!({"type": "object"}),
            source: ToolSource::Mcp {
                server_name: server.to_string(),
            },
            permission_tier: PermissionTier::HumanApproval,
        }
    }

    fn make_wasm_tool(name: &str, module: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: format!("WASM tool: {name}"),
            input_schema: serde_json::json!({"type": "object"}),
            source: ToolSource::Wasm {
                module_path: module.to_string(),
            },
            permission_tier: PermissionTier::LogAndExecute,
        }
    }

    fn make_tool_call(name: &str) -> ToolCall {
        ToolCall {
            tool_name: name.to_string(),
            parameters: serde_json::json!({"key": "value"}),
            proposal_id: Uuid::new_v4(),
        }
    }

    // ---- Listing tools from multiple sources ----

    #[tokio::test]
    async fn test_list_tools_empty() {
        let registry = ToolRegistryImpl::new();
        let tools = registry.list_tools().await.unwrap();
        assert!(tools.is_empty());
    }

    #[tokio::test]
    async fn test_list_tools_multiple_sources() {
        let registry = ToolRegistryImpl::new();

        // Register built-in tool
        registry
            .register_built_in(make_built_in_tool("shell.exec"), Arc::new(EchoHandler))
            .await
            .unwrap();

        // Register MCP tool via interior mutability on RwLock
        registry.tools.write().await.insert(
            "gmail.send".to_string(),
            make_mcp_tool("gmail.send", "gmail"),
        );

        // Register WASM tool
        registry.tools.write().await.insert(
            "custom.plugin".to_string(),
            make_wasm_tool("custom.plugin", "/tools/plugin.wasm"),
        );

        let tools = registry.list_tools().await.unwrap();
        assert_eq!(tools.len(), 3);

        let names: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();
        assert!(names.contains(&"shell.exec".to_string()));
        assert!(names.contains(&"gmail.send".to_string()));
        assert!(names.contains(&"custom.plugin".to_string()));
    }

    // ---- Routing to correct backend ----

    #[tokio::test]
    async fn test_execute_built_in_tool() {
        let registry = ToolRegistryImpl::new();
        registry
            .register_built_in(make_built_in_tool("shell.exec"), Arc::new(EchoHandler))
            .await
            .unwrap();

        let call = make_tool_call("shell.exec");
        let result = registry.execute(call).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.output,
            serde_json::json!({ "echo": {"key": "value"} })
        );
    }

    #[tokio::test]
    async fn test_execute_mcp_tool() {
        let executor = Arc::new(MockMcpExecutor);
        let registry = ToolRegistryImpl::with_mcp_executor(executor);

        registry.tools.write().await.insert(
            "gmail.send".to_string(),
            make_mcp_tool("gmail.send", "gmail"),
        );

        let call = make_tool_call("gmail.send");
        let result = registry.execute(call).await.unwrap();
        assert!(result.success);
        assert_eq!(result.output["server"], "gmail");
        assert_eq!(result.output["tool"], "gmail.send");
    }

    #[tokio::test]
    async fn test_execute_mcp_tool_without_executor() {
        let registry = ToolRegistryImpl::new();
        registry.tools.write().await.insert(
            "gmail.send".to_string(),
            make_mcp_tool("gmail.send", "gmail"),
        );

        let call = make_tool_call("gmail.send");
        let err = registry.execute(call).await.unwrap_err();
        assert!(err.to_string().contains("no MCP executor configured"));
    }

    #[tokio::test]
    async fn test_execute_wasm_tool_returns_stub_error() {
        let registry = ToolRegistryImpl::new();
        registry.tools.write().await.insert(
            "custom.plugin".to_string(),
            make_wasm_tool("custom.plugin", "/tools/plugin.wasm"),
        );

        let call = make_tool_call("custom.plugin");
        let err = registry.execute(call).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("WASM tool execution not yet implemented"));
    }

    #[tokio::test]
    async fn test_execute_built_in_handler_error_propagates() {
        let registry = ToolRegistryImpl::new();
        registry
            .register_built_in(make_built_in_tool("fail.tool"), Arc::new(FailingHandler))
            .await
            .unwrap();

        let call = make_tool_call("fail.tool");
        let err = registry.execute(call).await.unwrap_err();
        assert!(err.to_string().contains("handler error"));
    }

    // ---- Registration and unregistration ----

    #[tokio::test]
    async fn test_register_via_trait() {
        let mut registry = ToolRegistryImpl::new();
        let tool = make_mcp_tool("gcal.read", "gcal");

        ToolRegistry::register(&mut registry, tool).await.unwrap();

        let tools = registry.list_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "gcal.read");
    }

    #[tokio::test]
    async fn test_register_built_in_with_handler() {
        let registry = ToolRegistryImpl::new();
        registry
            .register_built_in(make_built_in_tool("search.web"), Arc::new(EchoHandler))
            .await
            .unwrap();

        let tools = registry.list_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "search.web");
    }

    #[tokio::test]
    async fn test_register_built_in_rejects_non_built_in() {
        let registry = ToolRegistryImpl::new();
        let mcp_tool = make_mcp_tool("gmail.send", "gmail");

        let err = registry
            .register_built_in(mcp_tool, Arc::new(EchoHandler))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-built-in"));
    }

    #[tokio::test]
    async fn test_register_overwrites_existing() {
        let mut registry = ToolRegistryImpl::new();
        let tool1 = ToolDefinition {
            name: "tool.a".to_string(),
            description: "version 1".to_string(),
            input_schema: serde_json::json!({}),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::AutoExecute,
        };
        let tool2 = ToolDefinition {
            name: "tool.a".to_string(),
            description: "version 2".to_string(),
            input_schema: serde_json::json!({}),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::AutoExecute,
        };

        ToolRegistry::register(&mut registry, tool1).await.unwrap();
        ToolRegistry::register(&mut registry, tool2).await.unwrap();

        let tools = registry.list_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].description, "version 2");
    }

    #[tokio::test]
    async fn test_unregister_existing_tool() {
        let registry = ToolRegistryImpl::new();
        registry
            .register_built_in(make_built_in_tool("shell.exec"), Arc::new(EchoHandler))
            .await
            .unwrap();

        assert_eq!(registry.list_tools().await.unwrap().len(), 1);

        registry.unregister("shell.exec").await.unwrap();

        assert!(registry.list_tools().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_unregister_removes_handler() {
        let registry = ToolRegistryImpl::new();
        registry
            .register_built_in(make_built_in_tool("shell.exec"), Arc::new(EchoHandler))
            .await
            .unwrap();

        registry.unregister("shell.exec").await.unwrap();

        // Verify handler is also gone by re-registering without a handler
        // and trying to execute — should fail with "no handler"
        registry
            .tools
            .write()
            .await
            .insert("shell.exec".to_string(), make_built_in_tool("shell.exec"));

        let call = make_tool_call("shell.exec");
        let err = registry.execute(call).await.unwrap_err();
        assert!(err.to_string().contains("no handler"));
    }

    #[tokio::test]
    async fn test_unregister_unknown_tool() {
        let registry = ToolRegistryImpl::new();
        let err = registry.unregister("nonexistent").await.unwrap_err();
        assert!(err.to_string().contains("tool not found"));
    }

    // ---- Unknown tools return clear error ----

    #[tokio::test]
    async fn test_execute_unknown_tool() {
        let registry = ToolRegistryImpl::new();
        let call = make_tool_call("nonexistent.tool");
        let err = registry.execute(call).await.unwrap_err();
        assert!(err.to_string().contains("unknown tool: nonexistent.tool"));
    }

    // ---- Thread-safe concurrent access ----

    #[tokio::test]
    async fn test_concurrent_reads() {
        let registry = Arc::new(ToolRegistryImpl::new());

        // Register some tools
        registry
            .register_built_in(make_built_in_tool("tool.a"), Arc::new(EchoHandler))
            .await
            .unwrap();
        registry
            .register_built_in(make_built_in_tool("tool.b"), Arc::new(EchoHandler))
            .await
            .unwrap();

        // Spawn multiple concurrent reads
        let mut handles = Vec::new();
        for _ in 0..10 {
            let reg = Arc::clone(&registry);
            handles.push(tokio::spawn(async move {
                let tools = reg.list_tools().await.unwrap();
                assert_eq!(tools.len(), 2);
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_concurrent_reads_and_executions() {
        let registry = Arc::new(ToolRegistryImpl::new());

        registry
            .register_built_in(make_built_in_tool("echo"), Arc::new(EchoHandler))
            .await
            .unwrap();

        let mut handles = Vec::new();
        for i in 0..20 {
            let reg = Arc::clone(&registry);
            handles.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    // Concurrent list
                    let tools = reg.list_tools().await.unwrap();
                    assert!(!tools.is_empty());
                } else {
                    // Concurrent execute
                    let call = ToolCall {
                        tool_name: "echo".to_string(),
                        parameters: serde_json::json!({"i": i}),
                        proposal_id: Uuid::new_v4(),
                    };
                    let result = reg.execute(call).await.unwrap();
                    assert!(result.success);
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_concurrent_register_and_list() {
        let registry = Arc::new(ToolRegistryImpl::new());

        let mut handles = Vec::new();

        // Spawn registrations via register_built_in (uses interior mutability)
        for i in 0..10 {
            let reg = Arc::clone(&registry);
            handles.push(tokio::spawn(async move {
                let name = format!("tool.{i}");
                reg.register_built_in(make_built_in_tool(&name), Arc::new(EchoHandler))
                    .await
                    .unwrap();
            }));
        }

        // Spawn concurrent reads
        for _ in 0..10 {
            let reg = Arc::clone(&registry);
            handles.push(tokio::spawn(async move {
                // May see 0..10 tools depending on timing — that's fine
                let _ = reg.list_tools().await.unwrap();
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        // After all registrations complete, should have exactly 10 tools
        let tools = registry.list_tools().await.unwrap();
        assert_eq!(tools.len(), 10);
    }
}
