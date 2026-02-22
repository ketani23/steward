Read docs/architecture.md section 5.7 (Configuration as Code) and the config/
directory structure. Read the permissions.yaml example and the MCP manifest
examples. Read the existing config types in crates/steward-types/src/config.rs.

Expand the config types in crates/steward-types/src/config.rs and implement
a config loader.

Requirements:
- Full serde types for:
  - PermissionsConfig (parsing permissions.yaml — tiers, actions, constraints,
    rate limits, time-of-day restrictions)
  - GuardrailsConfig (parsing guardrails.yaml — forbidden patterns, circuit breakers)
  - McpManifestConfig (parsing mcp-manifests/*.yaml — the full MCP manifest schema
    from architecture doc section 8.3)
  - IdentityConfig (parsing identity.md — agent personality, behavioral boundaries)
- ConfigLoader struct that:
  - Reads all config from a directory path
  - Validates config on load (e.g., no duplicate action patterns, rate limits are positive)
  - Supports hot-reload via file watching (notify crate)
  - Emits config change events via a channel (tokio::sync::watch)
- Default config files in config/ directory (ship with sensible defaults)
- Note: other modules may have already expanded some config types. Read the current
  state of config.rs first and build on what exists rather than replacing it.

Write tests:
- Test parsing each config file type
- Test validation catches invalid configs
- Test hot-reload detects file changes
- Test default configs parse successfully
- Test error messages are helpful for invalid YAML

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-types` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(types): implement config management with hot-reload and validation"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(types): implement config management" --body "Expands config types with full serde structs for permissions, guardrails, MCP manifests, and identity. Adds ConfigLoader with directory-based loading, validation, and hot-reload via file watching." --base main`
