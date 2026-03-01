# Getting Started with Steward

## Prerequisites

- **Rust** (1.75+ stable) — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Docker & Docker Compose** — for PostgreSQL + pgvector
- **Anthropic API key** — get one at https://console.anthropic.com

## Quick Start (Local Development)

### 1. Start PostgreSQL

```bash
cd deploy
docker compose up -d postgres
```

This starts PostgreSQL 16 with pgvector on `localhost:5432`.

### 2. Build Steward

```bash
cargo build --release -p steward-server
```

The binary is at `target/release/steward`.

### 3. Run Steward

```bash
# Minimal — in-memory mode (no database, no persistence)
ANTHROPIC_API_KEY=sk-ant-... ./target/release/steward

# With PostgreSQL for audit logging and memory
DATABASE_URL=postgres://steward:steward_dev@localhost:5432/steward_dev \
ANTHROPIC_API_KEY=sk-ant-... \
./target/release/steward
```

Steward starts an HTTP server on port 8080 with a `/health` endpoint.

### 4. Verify it's running

```bash
curl http://localhost:8080/health
# => ok
```

## Configuration

All configuration files live in the `config/` directory (override with `--config-dir` or `STEWARD_CONFIG_DIR`):

| File | Purpose |
|------|---------|
| `permissions.yaml` | Permission tiers for all tools (AutoExecute, LogAndExecute, HumanApproval, Forbidden) |
| `guardrails.yaml` | Global safety constraints, circuit breaker defaults |
| `identity.md` | Agent personality and behavioral boundaries |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes | — | Anthropic API key for LLM calls |
| `DATABASE_URL` | No | — | PostgreSQL connection URL. Without it, audit logs and memory are in-memory only |
| `STEWARD_CONFIG_DIR` | No | `config` | Path to config directory |
| `STEWARD_MODEL` | No | `claude-sonnet-4-5-20250929` | Primary agent model |
| `STEWARD_GUARDIAN_MODEL` | No | `claude-haiku-4-5-20251001` | Guardian review model |
| `STEWARD_HOST` | No | `0.0.0.0` | HTTP server bind address |
| `STEWARD_PORT` | No | `8080` | HTTP server port |
| `STEWARD_LOG_FORMAT` | No | `pretty` | Log format: `pretty` or `json` |
| `RUST_LOG` | No | `steward=info` | Log level filter |

### WhatsApp Integration (Optional)

| Variable | Description |
|----------|-------------|
| `WHATSAPP_ACCESS_TOKEN` | WhatsApp Business API access token |
| `WHATSAPP_PHONE_NUMBER_ID` | Phone number ID from WhatsApp Business |
| `WHATSAPP_APP_SECRET` | App secret for webhook signature verification |
| `WHATSAPP_VERIFY_TOKEN` | Webhook verification token |

## Docker Deployment

### Full stack with Docker Compose

```bash
# Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# Start everything (PostgreSQL + Steward)
cd deploy
docker compose up -d
```

### Build the Docker image manually

```bash
docker build -f deploy/Dockerfile -t steward:latest .
```

## Architecture

Steward processes messages through a security pipeline:

```
Inbound Message
  → Ingress Sanitizer (injection detection, content tagging)
  → Memory Search (context retrieval)
  → LLM (generates response or tool calls)
  → For each tool call:
      → Guardian LLM (adversarial review)
      → Permission Engine (tier classification)
      → Tool Execution (via registry)
      → Egress Filter (PII/secret scanning)
  → Final Egress Filter on response
  → Send Response
  → Audit Log (every step)
```

See `docs/architecture.md` for the full design.

## Development

### Run tests

```bash
# All tests
cargo test --all

# Single crate
cargo test -p steward-security

# Integration tests (requires DATABASE_URL for some)
cargo test -p steward-integration-tests
```

### Code quality

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

## Crate Structure

| Crate | Purpose |
|-------|---------|
| `steward-types` | Shared traits, types, errors — all crates depend on this |
| `steward-security` | Ingress sanitizer, egress filter, leak detector, secret broker, audit logger |
| `steward-core` | Agent loop, guardian LLM, permission engine, LLM providers |
| `steward-tools` | Tool registry, MCP proxy, WASM sandbox |
| `steward-memory` | PostgreSQL + pgvector memory with provenance tracking |
| `steward-channels` | WhatsApp, Telegram, Slack adapters |
| `steward-server` | Server binary that wires everything together |
