//! MCP HTTP/SSE transport implementation.
//!
//! HTTP client for remote MCP servers using streamable HTTP transport:
//! - HTTP POST for JSON-RPC requests
//! - SSE stream for server responses
//! - Session management via Mcp-Session-Id header
//! - Reconnection with Last-Event-ID support
//!
//! See `docs/architecture.md` section 8.8 for transport specification.

// TODO: Implement McpTransport trait for HTTP/SSE
