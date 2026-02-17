Read docs/architecture.md section 8.9 (Tool List Filtering and Schema Rewriting).

Implement the MCP schema rewriter in crates/steward-tools/src/mcp/schema_rewrite.rs.

This module is used by the MCP manifest to rewrite tool input schemas. It operates
on JSON Schema objects (serde_json::Value) and removes or constrains properties.

Requirements:
- rewrite_schema(schema: &Value, rewrites: &SchemaRewriteConfig) -> Value
  Takes a JSON Schema and applies rewrite rules:
  - strip_params: remove named properties from the schema's "properties" object,
    also remove them from "required" if present
  - constrain_params: add or modify constraints on existing properties
    (e.g., set "maximum" on an integer field, set "maxItems" on an array field,
    set "maxLength" on a string field)
- strip_blocked_params(schema: &Value, patterns: &[String]) -> Value
  Remove all properties matching glob patterns from the schema.
  Pattern "*.bcc" matches any property named "bcc" at any depth.
  Pattern "arguments.forward_to" matches that exact path.
- The rewritten schema must remain valid JSON Schema
- Handle nested schemas (objects within objects)

Write tests:
- Test stripping a single property from a flat schema
- Test stripping from a nested schema
- Test glob pattern matching at multiple depths
- Test constraint application (add maximum, maxItems, maxLength)
- Test that required array is updated when properties are removed
- Test that an empty schema remains valid after rewriting
- Test real-world MCP tool schemas (Gmail send, Calendar create)

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-tools` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(tools): implement MCP schema rewriter with property stripping and constraint enforcement"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(tools): implement MCP schema rewriter" --body "Implements schema rewriting for MCP tool input schemas: property stripping, glob pattern matching, constraint enforcement, and nested schema handling." --base main`
