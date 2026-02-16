# Project Steward — Claude Code Instructions

## Project Overview

Steward is a security-hardened autonomous AI agent framework written in Rust. Security is the core value proposition — not an afterthought. Read `docs/architecture.md` for the full design and `docs/implementation-plan.md` for the task breakdown.

## Architecture Quick Reference

The system has five layers: Communication (channel adapters) → Ingress Security (sanitization) → Agent Core (LLM + Guardian + Permissions) → Execution (tools via MCP proxy, WASM sandbox, built-ins) → Egress Security (PII/secret filtering on all outbound content). Cross-cutting: audit logger, memory system, config management.

Every capability passes through controlled chokepoints. The agent is treated as an untrusted employee with graduated permissions.

## Crate Structure

```
crates/
├── steward-types/     # Shared traits, types, errors — ALL modules depend on this
├── steward-security/  # Ingress, egress, secret broker, leak detection, audit
├── steward-memory/    # PostgreSQL + pgvector memory with provenance
├── steward-tools/     # Tool registry, MCP proxy, WASM sandbox, staging
├── steward-core/      # Agent loop, guardian LLM, permissions, LLM providers
└── steward-channels/  # WhatsApp, Telegram, Slack adapters
```

## Conventions

### Language & Dependencies
- **Rust** edition 2021, stable toolchain
- **Async:** `tokio` (multi-threaded runtime)
- **Error handling:** `thiserror` for library error types, `anyhow` for binary/integration code
- **Serialization:** `serde` + `serde_json` + `serde_yaml`
- **HTTP client:** `reqwest` with `rustls`
- **HTTP server:** `axum`
- **Database:** `sqlx` (async, compile-time checked queries) with PostgreSQL + pgvector
- **Crypto:** `aes-gcm`, `hkdf`, `sha2`
- **Testing:** built-in `#[cfg(test)]` modules + `tests/` directory for integration tests

### Code Style
- All public types and functions need doc comments (`///`)
- No `unwrap()` or `expect()` in production code paths — use proper error propagation with `?`
- `unwrap()` is fine in tests
- Use `tracing` for structured logging (not `println!` or `log`)
- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` before committing — zero warnings policy
- Prefer `impl Trait` in function signatures over concrete types where it helps testability
- Accept dependencies as trait objects (`Arc<dyn Trait>`) for testability

### Trait Contract Pattern
All module interfaces are defined as traits in `crates/steward-types/src/traits.rs`. When implementing a module, you implement the trait from that file. This is what enables parallel development — every module codes against shared interfaces, not against each other's concrete types.

### Testing
- Unit tests: in-module `#[cfg(test)] mod tests { ... }`
- Integration tests requiring PostgreSQL: gate behind `DATABASE_URL` env var, use `#[ignore]` attribute
- Mock dependencies using trait objects — pass mock implementations of dependencies
- Aim for >80% coverage on security-critical modules (ingress, egress, leak detector, permissions)
- Test file naming: match the module name (`leak_detector.rs` tests in that same file)

## Workflow Instructions

You are working on a specific feature branch in a git worktree.

1. **Read the task:** Your task is described either in the conversation or in a file under `docs/tasks/TASK-X.X.md`. Read it carefully.
2. **Read the architecture:** Reference `docs/architecture.md` for design context. The relevant section numbers are mentioned in your task description.
3. **Read the trait:** Check `crates/steward-types/src/traits.rs` for the trait you need to implement.
4. **Implement:** Write the implementation in the specified file(s).
5. **Test:** Write comprehensive tests as described in the task.
6. **Verify:** Run `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` (for your crate at minimum: `cargo test -p steward-security` etc.).
7. **Commit:** Use a descriptive commit message following conventional commits: `feat(security): implement leak detector with pattern matching for 12 credential types`
8. **Push + PR:** Push the branch and create a PR:
   ```bash
   git push origin HEAD
   gh pr create --title "feat: <brief description>" --body "<what was implemented, what was tested>" --base main
   ```

## Boundaries

- Do NOT modify files outside your module's scope unless the task explicitly says to
- Do NOT modify `steward-types/src/traits.rs` — those are the shared contracts
- Do NOT modify `docs/architecture.md` or `docs/implementation-plan.md`
- If you need a new type in `steward-types`, add it to the appropriate file (`actions.rs`, `config.rs`, etc.) and document why
- If the trait contract seems wrong or insufficient for your implementation, note this in your PR description rather than changing it

## Common Patterns

### Creating a new struct that implements a trait:

```rust
use std::sync::Arc;
use steward_types::traits::*;
use steward_types::actions::*;
use steward_types::errors::StewardError;

pub struct MyModule {
    // Accept dependencies as trait objects
    leak_detector: Arc<dyn LeakDetector>,
    config: MyModuleConfig,
}

impl MyModule {
    pub fn new(leak_detector: Arc<dyn LeakDetector>, config: MyModuleConfig) -> Self {
        Self { leak_detector, config }
    }
}

#[async_trait::async_trait]
impl SomeTrait for MyModule {
    async fn some_method(&self, input: Input) -> Result<Output, StewardError> {
        // implementation
    }
}
```

### Database access with sqlx:

```rust
use sqlx::PgPool;

pub struct AuditLoggerImpl {
    pool: PgPool,
}

impl AuditLoggerImpl {
    pub async fn new(database_url: &str) -> Result<Self, StewardError> {
        let pool = PgPool::connect(database_url).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }
}
```

### Testing with mock dependencies:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    struct MockLeakDetector;

    impl LeakDetector for MockLeakDetector {
        fn scan(&self, _content: &str) -> Vec<LeakDetection> {
            vec![] // no leaks found
        }
        fn redact(&self, content: &str) -> String {
            content.to_string() // no redaction
        }
    }

    #[tokio::test]
    async fn test_something() {
        let detector = Arc::new(MockLeakDetector);
        let module = MyModule::new(detector, default_config());
        let result = module.some_method(test_input()).await.unwrap();
        assert_eq!(result, expected_output());
    }
}
```
