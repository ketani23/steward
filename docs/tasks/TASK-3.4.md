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

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-tools` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(tools): implement MCP HTTP/SSE transport with session management"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(tools): implement MCP HTTP/SSE transport" --body "Implements McpTransport trait for HTTP/SSE-based MCP servers with reqwest client, SSE stream parsing, session ID tracking, reconnection support, and graceful error handling." --base main`
