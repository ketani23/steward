Create an end-to-end smoke test in tests/integration/smoke_test.rs that
exercises the complete Steward pipeline.

Read all the implemented modules to understand the concrete types available:
- crates/steward-security/src/ (ingress, egress, leak_detector, audit, secret_broker)
- crates/steward-core/src/ (agent, guardian, permissions, llm/, router)
- crates/steward-tools/src/ (registry, mcp/)
- crates/steward-memory/src/ (workspace, search)
- crates/steward-types/src/ (traits, actions, errors, config)

The test should:
1. Create mock implementations of external dependencies (LLM, MCP server)
   that return predetermined responses — do NOT require any external services
   or DATABASE_URL for the main smoke tests
2. Initialize all components: Agent, Guardian (with mock LLM), PermissionEngine
   (with test permissions.yaml), IngressSanitizer, EgressFilter (with LeakDetector),
   AuditLogger (in-memory), ToolRegistry
3. Send a simulated user message through the Agent pipeline
4. Verify: ingress sanitization ran, guardian was consulted, permission was checked,
   tool was called, egress filter scanned the result, audit log captured events,
   response was generated
5. Send a simulated injection attack and verify it was detected and blocked
6. Verify the audit trail contains expected events

This is a "does the whole thing wire together" test, not a comprehensive
security test. Keep it focused on proving integration works.

For any tests that truly need PostgreSQL, gate them behind DATABASE_URL env var
and use #[ignore] attribute. But prefer in-memory/mock implementations for
the smoke test so it runs in CI without a database.

You will need to add the test file to the workspace. Create tests/integration/smoke_test.rs
and ensure the root Cargo.toml or a test crate can find it. You may need to create
a [[test]] entry in the root Cargo.toml or create a small test crate.

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run the smoke test and ensure it passes
- Stage and commit: `git add -A && git commit -m "test: add end-to-end smoke test for complete Steward pipeline"`
- Push and create PR: `git push origin HEAD && gh pr create --title "test: end-to-end smoke test" --body "Adds integration smoke test exercising the complete Steward pipeline: ingress sanitization, guardian review, permission check, tool execution, egress filtering, and audit logging. Uses mock LLM and in-memory implementations." --base main`
