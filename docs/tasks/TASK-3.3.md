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

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-tools` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(tools): implement MCP stdio transport with child process management"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(tools): implement MCP stdio transport" --body "Implements McpTransport trait for stdio-based MCP servers with child process spawning, JSON-RPC framing, stderr capture, and graceful shutdown." --base main`
