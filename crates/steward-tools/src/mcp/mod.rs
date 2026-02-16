/// MCP (Model Context Protocol) proxy subsystem.
///
/// Security gateway that mediates all communication between the agent and MCP servers:
/// - Per-server capability manifests
/// - Bidirectional egress filtering
/// - Tool list filtering and schema rewriting
/// - Circuit breaker for connection health
/// - Full audit logging
///
/// See `docs/architecture.md` section 8 for the complete MCP proxy specification.
pub mod circuit_breaker;
pub mod introspect;
pub mod manifest;
pub mod proxy;
pub mod schema_rewrite;
pub mod transport_http;
pub mod transport_stdio;
