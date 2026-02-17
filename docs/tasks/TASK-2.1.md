Read docs/architecture.md sections 8.3 (Proxy Functions) and 8.9 (Tool List Filtering and Schema Rewriting) for the manifest format and rewrite rules.
Read crates/steward-types/src/traits.rs for the McpManifest trait.

Implement the MCP manifest parser in crates/steward-tools/src/mcp/manifest.rs.

Requirements:
- Implement the McpManifest trait from steward-types
- Parse per-server YAML manifest files with this structure:
  server (name, url, transport, status), capabilities (allowed_tools with
  rate_limit and permission_tier overrides, blocked_tools), blocked_params
  (glob patterns like "*.bcc"), schema_rewrites (strip_params, constrain_params),
  egress_filter config, audit config, circuit_breaker config
- check_tool_call(): validate tool name is allowed, parameters don't include
  blocked params, rate limit not exceeded
- filter_tool_list(): remove blocked tools from a tools/list response AND
  rewrite input schemas to strip blocked parameters. If gmail.send has a "bcc"
  field in its inputSchema, remove that field from the JSON Schema before
  returning it to the agent
- Return ManifestDecision enum: Allow, Block { reason }, RateLimit { retry_after }

Write tests:
- Test parsing a complete Gmail manifest (use the example from architecture doc)
- Test tool filtering removes blocked tools
- Test schema rewriting strips blocked parameters from JSON Schema
- Test parameter constraint enforcement (max_recipients, max_size_bytes)
- Test glob pattern matching for blocked_params ("*.bcc" matches "arguments.bcc")
- Test rate limit checking
- Test permission tier overrides per tool

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-tools` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(tools): implement MCP manifest parser with tool filtering and schema rewriting"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(tools): implement MCP manifest parser" --body "Implements McpManifest trait with YAML parsing, tool filtering, schema rewriting, rate limiting, and glob pattern matching for blocked params." --base main`
