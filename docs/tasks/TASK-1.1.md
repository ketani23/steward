# TASK-1.1: Leak Detector

**Branch:** `feat/leak-detector`
**Crate:** `steward-security`
**File:** `crates/steward-security/src/leak_detector.rs`

## Instructions

1. Read `docs/architecture.md` sections 5.2 (Secret Broker) and 5.5 (Egress Filter) for context on how the leak detector fits into the system.
2. Read `crates/steward-types/src/traits.rs` for the `LeakDetector` trait you must implement.
3. Read `crates/steward-types/src/actions.rs` for the `LeakDetection` type.
4. Implement the leak detector in `crates/steward-security/src/leak_detector.rs`.
5. Write comprehensive tests.
6. Verify with `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test -p steward-security`.
7. Commit, push, and create a PR.

## Requirements

- Implement the `LeakDetector` trait from `steward-types`
- Create a `PatternLeakDetector` struct that compiles regex patterns once at construction time (use `once_cell::sync::Lazy` or compile in `new()`)
- Pattern matching for at minimum these 12 credential types:
  - AWS access keys (`AKIA[0-9A-Z]{16}`)
  - AWS secret keys (40-char base64 after known prefixes)
  - GCP API keys (`AIza[0-9A-Za-z_-]{35}`)
  - GitHub tokens (`ghp_[0-9a-zA-Z]{36}`, `gho_`, `ghu_`, `ghs_`, `ghr_` variants)
  - Anthropic API keys (`sk-ant-[0-9a-zA-Z-]{80,}`)
  - OpenAI API keys (`sk-[0-9a-zA-Z]{40,}`)
  - Generic OAuth bearer tokens (`bearer [a-zA-Z0-9_-]+`)
  - JWTs (`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
  - RSA/EC/Ed25519 private keys (`-----BEGIN.*PRIVATE KEY-----`)
  - Passwords in URLs (`://[^:]+:[^@]+@`)
  - Credit card numbers (13-19 digit sequences with Luhn check)
  - SSNs (`\d{3}-\d{2}-\d{4}`)
- The `scan` method returns `Vec<LeakDetection>` with: pattern_name, byte offset, matched length, confidence score
- The `redact` method replaces detected secrets with `[REDACTED:{pattern_name}]`
- Must be fast — this runs on every I/O crossing a security boundary
- No `unwrap()` or `expect()` in production code paths
- Use `tracing` for any logging

## Tests

Write tests in a `#[cfg(test)] mod tests` block within the same file:

- Test each credential pattern with realistic format examples
- Test that non-secrets don't trigger false positives (UUIDs, hex strings, base64 data, normal URLs)
- Test redaction preserves non-secret content
- Test with content containing multiple secrets
- Test edge cases: empty input, very long input, overlapping patterns
- Test Luhn check for credit card numbers (valid and invalid)

## Completion

After implementation and all tests pass:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test -p steward-security
git add -A
git commit -m "feat(security): implement leak detector with pattern matching for 12+ credential types"
git push -u origin feat/leak-detector
gh pr create --title "feat(security): implement leak detector" --body "## Summary
- Implements LeakDetector trait with regex pattern matching for 12+ credential types
- Includes scan() and redact() methods
- Comprehensive test suite covering all patterns, false positives, and edge cases

## Test plan
- [x] cargo fmt --all
- [x] cargo clippy -- -D warnings
- [x] cargo test -p steward-security (all tests pass)"
```
