Read docs/architecture.md section 3 (High-Level Architecture) for the full
request flow, section 6 (Agent Model: Generalist with Delegation) for the
generalist architecture.

Implement the agent core loop in crates/steward-core/src/agent.rs and the
router in crates/steward-core/src/router.rs.

This is the main orchestrator — it receives user messages, generates action
proposals via LLM, runs them through the security pipeline, and executes them.

Requirements:
- Agent struct that wires together: LlmProvider, Guardian, PermissionEngine,
  ToolRegistry, EgressFilter, IngressSanitizer, AuditLogger, MemorySearch
  (all as trait objects via Arc<dyn Trait>)
- Main loop:
  1. Receive inbound message (from channel)
  2. Run through IngressSanitizer
  3. Retrieve relevant context from MemorySearch
  4. Build LLM prompt with: system prompt, user message, sanitized context,
     available tools
  5. Call LlmProvider.complete_with_tools()
  6. Parse response — extract ActionProposal(s) from tool_use blocks
  7. For each proposal: Guardian.review() → PermissionEngine.classify() →
     if approved: ToolRegistry.execute() → EgressFilter.filter() on result
  8. Build response message from results
  9. AuditLogger.log() for every step
- Handle multi-turn tool use: if the LLM wants to call multiple tools in
  sequence, loop through steps 5-8
- Handle human approval flow: when PermissionEngine returns HumanApproval,
  send approval request via channel and wait for response
- Error handling: any failure at any stage should be logged and result in a
  graceful error message to the user (never crash the loop)
- Router (router.rs): simple intent classification that determines if the
  message needs tool use or is just conversation. Can start as a heuristic
  (look for action verbs, question marks, etc.) — LLM-based routing is a
  stretch goal.

Write tests:
- Test full request flow with mock LLM + mock tools (happy path)
- Test guardian blocks an action (verify action not executed)
- Test human approval flow (mock channel approval)
- Test multi-turn tool use
- Test error handling (LLM fails, tool fails, etc.)
- Test that every step produces an audit log entry
- Test router classifies messages correctly

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-core` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(core): implement agent core loop with full security pipeline and multi-turn tool use"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(core): implement agent core loop" --body "Implements the main Agent orchestrator wiring LLM, Guardian, PermissionEngine, ToolRegistry, EgressFilter, IngressSanitizer, AuditLogger, and MemorySearch into the complete request flow with multi-turn tool use and human approval." --base main`
