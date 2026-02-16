//! Leak detector implementation.
//!
//! Scans I/O for credential patterns in both directions:
//! - API keys (AWS, GCP, GitHub, Anthropic, OpenAI)
//! - OAuth tokens and JWTs
//! - Private keys (RSA, EC, Ed25519)
//! - Passwords in URLs
//! - Credit card numbers (with Luhn check)
//! - SSNs and common secret formats
//!
//! See `docs/architecture.md` sections 5.2 and 5.5 for context.

// TODO: Implement LeakDetector trait from steward-types
