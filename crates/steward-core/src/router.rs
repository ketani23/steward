//! Intent classification and job routing.
//!
//! Determines how to handle an inbound message:
//! - Conversational response (no tool use needed)
//! - Single tool call
//! - Multi-step workflow requiring multiple tool calls
//! - Sub-agent delegation for long-running tasks
//!
//! See `docs/architecture.md` section 6 for the generalist architecture.

// TODO: Implement intent router
