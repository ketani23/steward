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

### Telegram Integration (Optional)

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Bot token from [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_ALLOWED_USER_IDS` | Comma-delimited list of Telegram user IDs allowed to interact with the bot (deny-all if empty) |
| `TELEGRAM_API_BASE_URL` | Telegram Bot API base URL (default: `https://api.telegram.org`) |

To set up Telegram:

1. Create a bot via [@BotFather](https://t.me/BotFather) and copy the bot token
2. Send a message to your bot, then call `https://api.telegram.org/bot<TOKEN>/getUpdates` to find your user ID
3. Run Steward with the Telegram env vars:

```bash
ANTHROPIC_API_KEY=sk-ant-... \
TELEGRAM_BOT_TOKEN=123456:ABC-DEF... \
TELEGRAM_ALLOWED_USER_IDS=your_user_id \
./target/release/steward
```

The bot uses long-polling (`getUpdates`) — no webhook or public URL required.

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

## VPS Deployment (DigitalOcean)

Run Steward 24/7 on a VPS, fully isolated from your local machine.

### Prerequisites

- A DigitalOcean droplet (or any Ubuntu 22.04+ VPS) with SSH access
- Your Anthropic API key
- (Optional) Telegram bot token and user IDs

### Automated Setup with Claude Code

The easiest way to set up a VPS is with the Claude Code prompt:

1. SSH into your VPS
2. Install Claude Code if not already available
3. Open the prompt at [`deploy/VPS_SETUP_PROMPT.md`](../deploy/VPS_SETUP_PROMPT.md)
4. Paste it into Claude Code — it will walk you through the full setup interactively

### Manual Setup

```bash
# 1. Install Docker (if not installed)
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# 2. Create service user
useradd --system --create-home --home-dir /opt/steward --shell /usr/sbin/nologin steward
usermod -aG docker steward

# 3. Clone and configure
git clone https://github.com/<OWNER>/steward.git /opt/steward/steward
cd /opt/steward/steward
cp .env.example .env

# 4. Edit .env — set your API keys, generate a Postgres password:
#    openssl rand -base64 32
chmod 600 .env
chown steward:steward .env

# 5. Firewall
ufw allow 22/tcp
ufw allow 8080/tcp
ufw --force enable

# 6. Build and start
cd deploy
docker compose up -d --build

# 7. Verify
docker compose ps
curl http://localhost:8080/health
```

### Security Notes

The production Docker setup includes several hardening measures:

- **Non-root container:** Steward runs as UID 10001, not root
- **Read-only filesystem:** The container root filesystem is mounted read-only; only `/tmp` and `/tmp/workspace` are writable (via tmpfs)
- **Dropped capabilities:** All Linux capabilities are dropped (`cap_drop: ALL`)
- **No privilege escalation:** `no-new-privileges` security option is set
- **Network isolation:** PostgreSQL is only accessible within the Docker network — its port is not exposed to the host
- **Secret management:** All secrets live in `.env` (chmod 600, owned by the service user) — never in docker-compose.yml

### Useful Commands

```bash
cd /opt/steward/steward/deploy

# View logs
docker compose logs -f

# Restart
docker compose restart

# Update to latest
cd .. && git pull && cd deploy && docker compose up -d --build

# Stop
docker compose down

# Check status
docker compose ps
```

### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `POSTGRES_PASSWORD not set` | Ensure `.env` exists and has `POSTGRES_PASSWORD` set |
| Health check failing | Check logs: `docker compose logs steward` |
| Permission denied on `.env` | `chmod 600 .env && chown steward:steward .env` |
| Port 8080 unreachable | Check firewall: `ufw status` |
| Container keeps restarting | Check logs for startup errors: `docker compose logs --tail=50 steward` |

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
