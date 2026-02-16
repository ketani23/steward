//! MCP stdio transport implementation.
//!
//! Spawns MCP servers as child processes and communicates via stdin/stdout:
//! - JSON-RPC message framing (one JSON object per line)
//! - Child process lifecycle management
//! - Stderr capture and logging
//!
//! See `docs/architecture.md` section 8.8 for transport specification.

// TODO: Implement McpTransport trait for stdio
