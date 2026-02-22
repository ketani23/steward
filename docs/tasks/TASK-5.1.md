Read docs/architecture.md sections 8.7 through 8.12 (the complete MCP proxy spec).
Read the MCP module files that have already been implemented:
- crates/steward-tools/src/mcp/manifest.rs
- crates/steward-tools/src/mcp/schema_rewrite.rs
- crates/steward-tools/src/mcp/circuit_breaker.rs
- crates/steward-tools/src/mcp/transport_stdio.rs
- crates/steward-tools/src/mcp/transport_http.rs

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
- Test tools/list filtering across multiple servers (use mock implementations)
- Test tools/call routing to correct server
- Test enforcement pipeline (blocked tool, blocked param, rate limit)
- Test circuit breaker integration (server failure → circuit open → rejection)
- Test add/remove server dynamically
- Test connection state machine transitions

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-tools` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(tools): implement MCP proxy core with enforcement pipeline and connection lifecycle"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(tools): implement MCP proxy core" --body "Implements McpProxy integrating manifest, schema rewriter, circuit breaker, and transports into the complete enforcement pipeline with connection lifecycle state machine." --base main`
