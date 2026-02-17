Read docs/architecture.md section 5.5 (Egress Filter) for requirements.
Read crates/steward-types/src/traits.rs for the EgressFilter trait.

Implement the EgressFilter in crates/steward-security/src/egress.rs.

Requirements:
- Implement the EgressFilter trait from steward-types
- Accept a LeakDetector trait object as a constructor dependency (for secret scanning)
- PII detection: regex patterns for SSNs (XXX-XX-XXXX), credit cards (with Luhn),
  email addresses, phone numbers, physical addresses (best effort),
  health-related terms (ICD codes, medication names list)
- Secret scanning: delegate to LeakDetector
- Recipient validation: for communication tools (email.send, message.send),
  validate that the recipient matches expected patterns. Maintain a known
  contacts allowlist (configurable). Flag unknown recipients for review.
- Volume anomaly detection: track outbound message count per time window.
  If count exceeds threshold, block and alert. (Sliding window counter)
- Content policy check: basic heuristic — if tool type is "email.send" but
  content looks like a data dump (high entropy, structured data patterns),
  flag for review
- The filter method returns EgressDecision: Pass, Block { reason, patterns_found },
  or Warn { reason } (allow but flag in audit log)
- register_pattern() allows adding custom patterns at runtime

Write tests:
- Test PII detection for each pattern type
- Test false positive rates on normal content
- Test recipient validation with allowlist
- Test volume anomaly detection (simulate rapid sends)
- Test content policy heuristic
- Test that EgressDecision serializes correctly for audit logging

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-security` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(security): implement egress filter with PII detection, recipient validation, and volume anomaly detection"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(security): implement egress filter" --body "Implements EgressFilter trait with PII detection, secret scanning via LeakDetector, recipient validation, volume anomaly detection, and content policy checks." --base main`
