# TASK-1.4: Permission Engine

**Branch:** `feat/permission-engine`
**Crate:** `steward-core`
**File:** `crates/steward-core/src/permissions.rs`

## Instructions

1. Read `docs/architecture.md` section on Ring 1 (Permission Engine) including the full `permissions.yaml` example.
2. Read `crates/steward-types/src/traits.rs` for the `PermissionEngine` trait you must implement.
3. Read `crates/steward-types/src/actions.rs` for `ActionProposal` and `PermissionTier` types.
4. Read `crates/steward-types/src/errors.rs` for the `RateLimitExceeded` type.
5. Read `config/permissions.yaml` for the default permission manifest.
6. Implement the permission engine in `crates/steward-core/src/permissions.rs`.
7. Write comprehensive tests.
8. Verify with `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test -p steward-core`.
9. Commit, push, and create a PR.

## Requirements

- Implement the `PermissionEngine` trait from `steward-types`
- Create a `YamlPermissionEngine` struct

### Manifest Parsing
- Parse `permissions.yaml` using `serde_yaml`
- The manifest has four tiers: `auto_execute`, `log_and_execute`, `human_approval`, `forbidden`
- Each tier has a `description`, a list of `actions` (string patterns), and optional `constraints`
- You may need to expand the config types in `steward-types/src/config.rs` — if so, add what you need there

### Action Classification (`classify` method)
- Map `ActionProposal.tool_name` to the correct `PermissionTier`
- Support wildcard patterns: `"email.*"` matches `"email.read"` and `"email.send"`
- Support exact matches: `"calendar.read"` matches only `"calendar.read"`
- **Unknown actions default to `HumanApproval`** (fail-closed design)
- Check tiers in order: `forbidden` first (highest priority), then `human_approval`, then `log_and_execute`, then `auto_execute`

### Rate Limiting (`check_rate_limit` method)
- Token bucket algorithm per action pattern
- Store rate limit state in memory: `HashMap<String, TokenBucket>` behind a `Mutex` or `RwLock`
- Token bucket: configurable capacity and refill rate, parsed from the `rate_limit` field (e.g., "60/minute" → 60 tokens, refills 1/second)
- Return `Ok(())` if within limits, `Err(RateLimitExceeded)` if exceeded

### Hot Reload (`reload_manifest` method)
- Re-read the YAML file from disk and hot-swap the parsed config
- Use `RwLock` for concurrent access — readers don't block during reload
- Preserve rate limit state across reloads (don't reset token buckets)

### Constructor
- `YamlPermissionEngine::new(manifest_path: &Path) -> Result<Self, StewardError>`
- Load and parse the manifest on construction

## Tests

Write tests in a `#[cfg(test)] mod tests` block:

- Test parsing the default `config/permissions.yaml` (read it from disk in tests using a relative path or include_str!)
- Test wildcard pattern matching: `"email.*"` matches `"email.read"`, `"email.send"`, but NOT `"email"`
- Test exact pattern matching
- Test each tier classification with example actions from the default manifest
- Test unknown actions default to `HumanApproval`
- Test forbidden actions (e.g., `"credentials.read_raw"`) are classified as `Forbidden`
- Test rate limiting: consume all tokens, verify next call returns `RateLimitExceeded`
- Test rate limiting: verify tokens refill over time (use `tokio::time::sleep` or mock time)
- Test hot-reload: modify manifest content, reload, verify new classification
- Test tier priority: if an action matches multiple tiers, the most restrictive wins

## Completion

After implementation and all tests pass:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test -p steward-core
git add -A
git commit -m "feat(core): implement permission engine with YAML manifest, wildcards, and token bucket rate limiting"
git push -u origin feat/permission-engine
gh pr create --title "feat(core): implement permission engine" --body "## Summary
- Implements PermissionEngine trait with YAML manifest parsing
- Wildcard action pattern matching (e.g., email.* matches email.read)
- Token bucket rate limiting per action
- Hot-reload manifest from disk without losing rate limit state
- Unknown actions fail-closed to HumanApproval

## Test plan
- [x] cargo fmt --all
- [x] cargo clippy -- -D warnings
- [x] cargo test -p steward-core (all tests pass)"
```
