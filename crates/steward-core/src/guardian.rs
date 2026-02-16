//! Guardian LLM implementation.
//!
//! Secondary model that reviews every proposed action before execution:
//! - Receives distilled action summary (never raw external content)
//! - Adversarial review: "Does this match user intent?"
//! - Structured verdict: ALLOW / BLOCK / ESCALATE_TO_HUMAN
//! - Fails safe: malformed output defaults to ESCALATE_TO_HUMAN
//!
//! See `docs/architecture.md` Ring 2 (Guardian LLM) for specification.

// TODO: Implement Guardian trait from steward-types
