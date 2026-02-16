/// Tool subsystem for the Steward agent framework.
///
/// Manages all tool execution backends:
/// - **Registry**: Central tool discovery and routing
/// - **MCP proxy**: Security gateway for external MCP servers
/// - **WASM sandbox**: Sandboxed execution for untrusted tools
/// - **Staging**: Staged file writes with diff preview
/// - **Sub-agent**: Sub-agent pool for task delegation
/// - **Built-in tools**: Trusted in-process tools
pub mod built_in;
pub mod mcp;
pub mod registry;
pub mod staging;
pub mod subagent;
pub mod wasm_sandbox;
