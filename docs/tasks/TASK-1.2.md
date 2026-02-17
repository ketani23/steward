# TASK-1.2: Ingress Sanitizer

**Branch:** `feat/ingress-sanitizer`
**Crate:** `steward-security`
**File:** `crates/steward-security/src/ingress.rs`

## Instructions

1. Read `docs/architecture.md` section 5.1 (Ingress Sanitizer) for full requirements.
2. Read `crates/steward-types/src/traits.rs` for the `IngressSanitizer` trait you must implement.
3. Read `crates/steward-types/src/actions.rs` for `RawContent`, `SanitizedContent`, and `InjectionDetection` types.
4. Implement the ingress sanitizer in `crates/steward-security/src/ingress.rs`.
5. Write comprehensive tests.
6. Verify with `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test -p steward-security`.
7. Commit, push, and create a PR.

## Requirements

- Implement the `IngressSanitizer` trait from `steward-types`
- Create a `DefaultIngressSanitizer` struct with configurable options

### Content Tagging
- Wrap external content in delimiters: `[EXTERNAL_CONTENT source="{source}" sender="{sender}"]...[/EXTERNAL_CONTENT]`

### Injection Pattern Detection
Detect at minimum these patterns (compile regexes once at construction time):
- "ignore previous instructions" / "ignore prior instructions" / "disregard above"
- "system:" / "SYSTEM:" at the start of a line
- "IMPORTANT:" followed by instruction-like text
- Role-playing attacks: "you are now", "act as", "pretend to be"
- Delimiter manipulation: attempts to close/reopen XML tags, markdown code blocks with system prompts
- Base64-encoded instructions (detect base64 blocks and flag them)
- Unicode direction override characters (RLO, LRO, etc.)
- Excessive whitespace/newlines used to push content out of visible context
- Markdown/HTML injection: `<script>`, `javascript:`, `data:text/html`
- Repeated instruction patterns: "do not", "you must", "always", "never" in suspicious density

### Content Escaping
- Escape characters that could break prompt boundaries
- Neutralize Unicode direction overrides
- Normalize excessive whitespace

### Context Budget
- Truncate external content to configurable max character count (default: 100,000 chars, ~25k tokens)
- Set `truncated: true` in the output when content is truncated

### Important
- Do NOT strip detected injections — flag them so the agent knows content was suspicious
- Detection results include: pattern_name, confidence, matched_text snippet, byte offset

## Tests

Write tests in a `#[cfg(test)] mod tests` block:

- Test content tagging with various source types (email, web, whatsapp)
- Test detection of each injection pattern listed above (10+ test cases)
- Test that normal content doesn't trigger false positives (regular emails, casual messages, technical docs)
- Test context budget enforcement (content over limit is truncated)
- Test nested content handling (external content containing tags)
- Test Unicode direction override detection
- Test empty input and very long input

## Completion

After implementation and all tests pass:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test -p steward-security
git add -A
git commit -m "feat(security): implement ingress sanitizer with injection detection for 10+ patterns"
git push -u origin feat/ingress-sanitizer
gh pr create --title "feat(security): implement ingress sanitizer" --body "## Summary
- Implements IngressSanitizer trait with content tagging, injection detection, escaping, and context budget
- Detects 10+ injection patterns including role-play, delimiter manipulation, base64, Unicode overrides
- Flags suspicious content without stripping it

## Test plan
- [x] cargo fmt --all
- [x] cargo clippy -- -D warnings
- [x] cargo test -p steward-security (all tests pass)"
```
