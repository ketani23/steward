# Steward

A security-hardened autonomous AI agent framework written in Rust.

Security is the core value proposition — not an afterthought. Every capability passes through controlled chokepoints. The agent is treated as an untrusted employee with graduated permissions.

## Architecture

```
Communication (channels) → Ingress Security (sanitization)
    → Agent Core (LLM + Guardian + Permissions)
    → Execution (tools via MCP proxy, WASM sandbox, built-ins)
    → Egress Security (PII/secret filtering on all outbound content)
```

**Five layers of defense:**

- **Ingress Sanitizer** — Content tagging, injection pattern detection, context budget enforcement
- **Guardian LLM** — Secondary model reviews every proposed action before execution
- **Permission Engine** — Declarative YAML manifest with four tiers: auto-execute, log-and-execute, human-approval, forbidden
- **MCP Proxy** — Security gateway wrapping all external tool servers with per-server capability manifests
- **Egress Filter** — PII/secret scanning on ALL outbound content before it leaves the system

## Crate Structure

```
crates/
├── steward-types/     # Shared traits, types, errors — all modules depend on this
├── steward-security/  # Ingress, egress, secret broker, leak detection, audit
├── steward-memory/    # PostgreSQL + pgvector memory with provenance tracking
├── steward-tools/     # Tool registry, MCP proxy, WASM sandbox, staging
├── steward-core/      # Agent loop, guardian LLM, permissions, LLM providers
└── steward-channels/  # WhatsApp, Telegram, Slack adapters
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Rust** | Memory safety, single binary, no runtime dependency. Prevents entire classes of vulnerabilities. |
| **WASM tool sandbox** | Lightweight (~ms startup), capability-based permissions for untrusted tools. |
| **Guardian LLM** | Secondary model on clean context — harder to inject than the primary agent. |
| **MCP Proxy** | MCP servers have full system access by default. The proxy adds capability manifests, egress filtering, and audit logging. |
| **PostgreSQL + pgvector** | Production-ready hybrid search (full-text + vector) with append-only audit logging. |
| **YAML permission manifests** | Human-readable, auditable, diffable in git, no code changes to adjust policy. |

## Threat Model

Steward defends against: prompt injection, credential exfiltration, unauthorized actions, data leakage, memory poisoning, and supply chain/plugin compromise. See [docs/architecture.md](docs/architecture.md) for the full threat model.

## Getting Started

### Prerequisites

- Rust stable toolchain (1.75+)
- PostgreSQL 16 with pgvector extension (for memory and audit)
- Docker (optional, for development database)

### Build

```bash
cargo build --all-targets
```

### Development Database

```bash
docker compose -f deploy/docker-compose.yml up -d
```

### Test

```bash
cargo test --all
```

### Lint

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features
```

## Project Status

**Phase 0 complete** — Workspace skeleton, trait contracts, and stubs for all modules. See [docs/implementation-plan.md](docs/implementation-plan.md) for the full roadmap.

## License

MIT OR Apache-2.0
