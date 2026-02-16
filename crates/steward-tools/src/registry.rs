//! Tool registry implementation.
//!
//! Central registry managing three categories of tools:
//! - Built-in tools (direct function calls, trusted)
//! - WASM tools (sandboxed, capability-manifest-enforced)
//! - MCP tools (proxied through McpProxy)
//!
//! See `docs/architecture.md` section 5 for tool categorization.

// TODO: Implement ToolRegistry trait from steward-types
