//! Main agent loop implementation.
//!
//! Orchestrates the full request pipeline:
//! 1. Receive inbound message from channel
//! 2. Run through ingress sanitizer
//! 3. Retrieve relevant context from memory
//! 4. Build LLM prompt and call provider
//! 5. Parse action proposals from LLM response
//! 6. Guardian review → Permission check → Tool execution → Egress filter
//! 7. Build and send response
//! 8. Audit log every step
//!
//! See `docs/architecture.md` section 3 for the high-level architecture.

// TODO: Implement main agent loop
