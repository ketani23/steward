//! MCP capability manifest parser and enforcer.
//!
//! Parses per-server YAML manifests that declare:
//! - Which tools the agent can call
//! - Parameter restrictions and blocked patterns
//! - Rate limits per tool
//! - Permission tier overrides
//!
//! See `docs/architecture.md` section 8.3 for manifest format.

// TODO: Implement McpManifest trait from steward-types
