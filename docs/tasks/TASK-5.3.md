Read docs/architecture.md section 5 (Key Subsystems) for tool categorization:
built-in, WASM, MCP. Read crates/steward-types/src/traits.rs for ToolRegistry.

Implement the tool registry in crates/steward-tools/src/registry.rs.

Requirements:
- Implement the ToolRegistry trait from steward-types
- Manages three categories of tools:
  (a) Built-in tools (direct function calls, trusted)
  (b) WASM tools (sandboxed, capability-manifest-enforced) — stub for now
  (c) MCP tools (proxied through McpProxy)
- list_tools(): aggregate tools from all sources into a unified list.
  Each tool has a ToolDefinition with: name, description, input schema,
  source (BuiltIn/Wasm/Mcp), permission tier
- execute(): route tool call to correct backend based on tool source.
  Built-in → direct call. MCP → delegate to McpProxy. WASM → stub/TODO.
- register(): add a new tool (for MCP discovery and WASM deployment)
- unregister(): remove a tool
- Thread-safe: tools can be added/removed while the agent is running
  (use RwLock for the tool map)

Write tests:
- Test listing tools from multiple sources
- Test routing to correct backend
- Test registration and unregistration
- Test thread-safe concurrent access
- Test that unknown tools return a clear error

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-tools` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(tools): implement tool registry with multi-source routing and thread-safe management"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(tools): implement tool registry" --body "Implements ToolRegistry trait with built-in, WASM (stub), and MCP tool sources, unified listing, source-based routing, and thread-safe registration/unregistration." --base main`
