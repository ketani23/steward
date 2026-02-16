# Project Steward: Architecture for a Security-Hardened Autonomous AI Agent

> **Status:** Design Phase — v0.3 Draft
> **Author:** Aniket + Claude (brainstorming sessions, Feb 2026)
> **Goal:** Build and open-source a production-grade autonomous AI agent with security as the core value proposition, not an afterthought.
>
> **v0.2 Changes:** Resolved multi-agent vs. generalist architecture (generalist + delegation). Added three-tier self-expansion pipeline, sub-agent pool design, MCP proxy security layer, and day-one capability stack.

---

## 1. Design Philosophy

**Treat the agent as an untrusted employee with graduated permissions.**

Every architectural decision flows from this mental model. The agent is powerful and helpful, but it operates under constraints that assume it can be compromised at any time — via prompt injection, poisoned memory, malicious tool inputs, or adversarial external content. The system's job is to limit blast radius, enforce least-privilege, and keep a human in the loop for anything consequential.

### Core Principles

- **Security by default, not by opt-in.** Sandboxing is on. Permissions are denied unless declared. Secrets are never directly accessible.
- **Mediated access over direct access.** Every capability the agent exercises passes through a controlled chokepoint where policy enforcement, auditing, and filtering happen.
- **Provider-agnostic.** No vendor lock-in. Supports Llama, Claude, GPT, Gemini, DeepSeek, and local models via Ollama/vLLM. No mandatory cloud auth dependency.
- **Defense in depth.** No single security mechanism is trusted to be sufficient. Layered defenses ensure that a bypass at one layer is caught by the next.
- **Auditable by design.** Every action, every decision, every blocked attempt is logged in append-only storage. Trust is built through transparency.

---

## 2. Threat Model

Before any code is written, these are the adversaries and attack vectors we defend against:

### 2.1 Prompt Injection (Highest Priority)

Malicious content embedded in emails, calendar invites, WhatsApp messages, web pages, or documents that hijacks the agent's instructions. This is the #1 attack vector for autonomous agents. OpenClaw's ecosystem has demonstrated this repeatedly — researchers achieved persistent backdoors via indirect injection through native features, and shell script injection via HEARTBEAT.md files.

### 2.2 Credential Exfiltration

The agent leaking API keys, OAuth tokens, or personal data through a crafted prompt that convinces it to include secrets in outbound messages, URL parameters, or API calls. OpenClaw's file-based plaintext credential storage made this trivially exploitable — deleted keys persisted in .bak files.

### 2.3 Unauthorized Actions

The agent sending emails, modifying files, making purchases, or invoking APIs the user didn't intend — either through injection, hallucination, or misconfigured permissions. The "find ~" incident (agent dumping a home directory to a group chat) illustrates this class.

### 2.4 Data Leakage

Personal context (health information, financial data, social graph, conversation history) being included in outbound communications, tool calls, or logs inappropriately. Particularly dangerous with persistent memory that accumulates sensitive context over time.

### 2.5 Memory Poisoning

Malicious content that gets stored in the agent's persistent memory via indirect prompt injection, then influences behavior across future sessions. No existing agent framework defends against this.

### 2.6 Supply Chain / Plugin Compromise

Malicious tools, skills, or dependencies. In OpenClaw's ecosystem, ~20% of ClawHub skills were found to be malicious, targeting crypto wallets, browser passwords, and system keychains. The triple rebrand (Clawdbot → Moltbot → OpenClaw) led to npm package name hijacking.

### 2.7 Infrastructure Compromise

The host server, container, or third-party APIs being compromised. 135,000+ OpenClaw instances were found exposed to the public internet, many running unpatched versions with known RCE vulnerabilities.

---

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        COMMUNICATION LAYER                              │
│  ┌───────────┐ ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │
│  │ WhatsApp  │ │ Telegram  │ │  Slack   │ │  Signal  │ │ Web Chat  │  │
│  └─────┬─────┘ └─────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬─────┘  │
│        └──────────────┴────────────┴─────────────┴─────────────┘        │
│                                    │                                    │
│                        ┌───────────▼───────────┐                        │
│                        │  INGRESS SANITIZER    │ ← Input preprocessing  │
│                        │  (Injection defense)  │   Content tagging      │
│                        └───────────┬───────────┘   Pattern detection    │
└────────────────────────────────────┼────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                          AGENT CORE                                     │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │              GENERALIST AGENT (Primary LLM)                     │    │
│  │                                                                 │    │
│  │  Single agent with unified memory + context across all domains  │    │
│  │  Skill files loaded into system prompt for task routing          │    │
│  │  Uses RAG for scoped context retrieval (not full context dump)  │    │
│  └──────────┬──────────────────────────────────┬───────────────────┘    │
│             │                                  │                        │
│    Direct execution                   Sub-agent delegation              │
│    (simple, fast tasks)               (parallel/heavy/coding)           │
│             │                                  │                        │
│             │                  ┌────────────────▼──────────────────┐    │
│             │                  │         SUB-AGENT POOL            │    │
│             │                  │                                   │    │
│             │                  │  • Research worker (long-running) │    │
│             │                  │  • Claude Code (builds new tools) │    │
│             │                  │  • Sandboxed task executor        │    │
│             │                  │                                   │    │
│             │                  │  Cannot spawn sub-agents          │    │
│             │                  │  (no recursive fan-out)           │    │
│             │                  │  Results announced → main agent   │    │
│             │                  │  Auto-archived after timeout      │    │
│             │                  └────────────────┬─────────────────┘    │
│             │                                   │                      │
│             └───────────────┬───────────────────┘                      │
│                              │                                          │
│                    ┌─────────▼─────────┐                                │
│                    │  ACTION PROPOSAL  │  Structured output:            │
│                    │  (Tool + Params)  │  {tool, params, reasoning}     │
│                    └─────────┬─────────┘                                │
│                              │                                          │
│              ┌───────────────▼───────────────┐                          │
│              │      ★ GUARDIAN LLM ★         │ ← NOVEL: No existing    │
│              │                               │   framework has this     │
│              │  Secondary model that reviews │                          │
│              │  each proposed action against: │                          │
│              │  - User's original intent     │                          │
│              │  - Permission policy          │                          │
│              │  - Injection indicators       │                          │
│              │  - Behavioral anomalies       │                          │
│              │                               │                          │
│              │  Verdict: ALLOW / BLOCK /     │                          │
│              │           ESCALATE_TO_HUMAN   │                          │
│              └───────────────┬───────────────┘                          │
│                              │                                          │
│                    ┌─────────▼─────────┐                                │
│                    │ PERMISSION ENGINE │  Declarative YAML manifest:    │
│                    │                   │  - Action tier classification  │
│                    │  Auto-execute     │  - Per-tool capability grants  │
│                    │  Log + execute    │  - Rate limits                 │
│                    │  Human approval   │  - Time-of-day restrictions    │
│                    │  Hard block       │  - Cooldown periods            │
│                    └─────────┬─────────┘                                │
│                              │                                          │
└──────────────────────────────┼──────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                       EXECUTION LAYER                                   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    SECRET BROKER                                  │   │
│  │  Encrypted vault (AES-256-GCM) → Short-lived token provisioning  │   │
│  │  Agent never sees raw credentials → Injected at call boundary    │   │
│  │  Leak detection on all requests and responses                    │   │
│  └──────────────────────────┬───────────────────────────────────────┘   │
│                              │                                          │
│         ┌────────────────────┼────────────────────┐                     │
│         │                    │                    │                     │
│  ┌──────▼──────┐   ┌────────▼────────┐   ┌──────▼──────┐              │
│  │ WASM Tools  │   │  Built-in Tools │   │★ MCP PROXY ★│              │
│  │ (Sandboxed) │   │  (Trusted,      │   │  (Security  │              │
│  │             │   │   in-process)   │   │   gateway)  │              │
│  │ Capability  │   │                 │   │             │              │
│  │ manifests   │   │  Shell, files,  │   │ Per-server  │              │
│  │ enforced    │   │  browser, search│   │ capability  │              │
│  │             │   │  email, calendar│   │ manifests   │              │
│  │             │   │                 │   │ Egress      │              │
│  │             │   │                 │   │ filtering   │              │
│  │             │   │                 │   │ Full audit  │              │
│  └──────┬──────┘   └────────┬────────┘   └──────┬──────┘              │
│         └────────────────────┼────────────────────┘                     │
│                              │                                          │
│                   ┌──────────▼──────────┐                               │
│                   │  STAGING AREA       │ ← File writes go here first  │
│                   │  (Diff + Approval)  │   User reviews before commit │
│                   └──────────┬──────────┘                               │
│                              │                                          │
│  ┌───────────────────────────┴──────────────────────────────────────┐   │
│  │              SELF-EXPANSION PIPELINE                              │   │
│  │                                                                   │   │
│  │  Tier 1: Skill files — agent drafts SKILL.md → user approves    │   │
│  │  Tier 2: MCP discovery — find server → proxy manifest → approve │   │
│  │  Tier 3: Code gen — Claude Code sub-agent → WASM tool → review  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
└──────────────────────────────┼──────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                        EGRESS LAYER                                     │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                  EGRESS FILTER                                    │   │
│  │  Scans ALL outbound content (messages, API calls, file writes)   │   │
│  │  before it leaves the system:                                    │   │
│  │  - PII detection (names, addresses, SSNs, health info)           │   │
│  │  - Secret pattern matching (API keys, tokens, passwords)         │   │
│  │  - Anomaly detection (unexpected recipients, unusual volume)     │   │
│  │  - Content policy enforcement (nothing the user wouldn't want    │   │
│  │    sent on their behalf)                                         │   │
│  └──────────────────────────┬───────────────────────────────────────┘   │
│                              │                                          │
│                    ┌─────────▼─────────┐                                │
│                    │  CHANNEL OUTPUT   │ → Messages delivered to        │
│                    │                   │   WhatsApp, Telegram, etc.     │
│                    └───────────────────┘                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                     CROSS-CUTTING CONCERNS                              │
│                                                                         │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────────────────┐  │
│  │  AUDIT LOGGER   │  │  MEMORY SYSTEM   │  │  CONFIG MANAGEMENT    │  │
│  │                 │  │                  │  │                       │  │
│  │  Append-only    │  │  PostgreSQL +    │  │  Git-backed YAML     │  │
│  │  Every action   │  │  pgvector        │  │  Version-controlled  │  │
│  │  Every block    │  │  Hybrid search   │  │  Human-approved PRs  │  │
│  │  Every decision │  │  Provenance tags │  │  for config changes  │  │
│  │  Anomaly alerts │  │  Integrity audit │  │                       │  │
│  └─────────────────┘  └──────────────────┘  └───────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Security Ring Architecture

### Ring 0: Infrastructure Isolation

The agent runs in a hardened container with:

- **Read-only root filesystem** with ephemeral tmpfs scratch at `/tmp/workspace` (wiped on restart)
- **Network egress allowlisting** — only explicitly approved outbound domains
- **Secrets in encrypted vault** — never in environment variables the agent process can read
- **gVisor or Firecracker** for stronger sandbox isolation beyond Docker (stretch goal)

### Ring 1: Permission Engine

A declarative YAML manifest classifies every possible action into tiers:

```yaml
# permissions.yaml
tiers:
  auto_execute:
    description: "Safe read-only operations"
    actions:
      - calendar.read
      - email.read
      - weather.check
      - memory.search
    constraints:
      rate_limit: 60/minute

  log_and_execute:
    description: "Low-risk writes, auto-allowed but audited"
    actions:
      - reminder.create
      - note.create
      - message.draft  # draft only, not send
    constraints:
      rate_limit: 30/minute

  human_approval:
    description: "High-risk actions requiring explicit confirmation"
    actions:
      - email.send
      - message.send
      - file.modify
      - calendar.create
      - purchase.any
    confirmation:
      channel: same_as_request  # Ask on WhatsApp if request came from WhatsApp
      show: [action, params, reasoning, guardian_verdict]
      timeout: 5m

  forbidden:
    description: "Hard-blocked regardless of LLM output"
    actions:
      - credentials.read_raw
      - system_prompt.modify
      - permissions.modify
      - data.bulk_delete
      - agent.self_modify
```

### Ring 2: Guardian LLM (Novel — detailed design TBD)

A secondary, smaller model (e.g., Haiku-class) that reviews every proposed action before execution. The guardian receives:

- The user's original message
- The proposed action (tool + parameters)
- The primary agent's reasoning
- The current permission policy

The guardian's job is narrow and adversarial: "Does this action match what the user actually asked for, or does it look like it was influenced by injected instructions?" It outputs a structured verdict: ALLOW, BLOCK (with reason), or ESCALATE_TO_HUMAN.

The guardian never sees the raw external content that the primary agent processed — it only sees the distilled action proposal. This architectural separation is key to its injection resistance.

### Ring 3: Audit & Observability

Every LLM call, tool invocation, action decision, guardian verdict, and blocked attempt is logged to append-only PostgreSQL storage. A monitoring layer runs continuously (not point-in-time) and alerts on:

- Unusual action patterns (sudden spike in email sends)
- Guardian BLOCK rate exceeding threshold
- Repeated injection detection events
- Tool invocations outside normal hours
- Outbound traffic to unexpected domains

---

## 5. Key Subsystems

### 5.1 Ingress Sanitizer

Before any external content reaches the primary LLM:

1. **Content tagging** — All external content (email bodies, web scrapes, incoming messages from third parties) is wrapped in clear delimiters: `[EXTERNAL_CONTENT source="email" sender="john@example.com"]...[/EXTERNAL_CONTENT]`
2. **Pattern detection** — Known injection patterns are flagged (not silently stripped — the agent should know content was suspicious)
3. **Content escaping** — Special characters and formatting that could break prompt boundaries are neutralized
4. **Context budget** — External content is truncated to prevent context window flooding attacks

### 5.2 Secret Broker

Inspired by IronClaw's credential injection pattern, but extended:

1. **Encrypted vault** — All credentials stored AES-256-GCM encrypted, keyed to system keychain or HSM
2. **Short-lived tokens** — The broker provisions scoped, time-limited tokens rather than raw credentials
3. **Injection at call boundary** — The agent requests "send authenticated email" and the broker handles credential injection in a separate process
4. **Bidirectional leak scanning** — Every outbound request and every inbound response is scanned for credential patterns before being passed to/from the agent
5. **External vault integration** — Optional connection to HashiCorp Vault, AWS Secrets Manager, or 1Password Connect for teams

### 5.3 WASM Tool Sandbox

Adopting IronClaw's approach — all untrusted/third-party tools run in WebAssembly containers:

- **Capability manifests** (`tool.capabilities.json`) declare required permissions
- **Endpoint allowlisting** — HTTP requests only to declared hosts/paths
- **Resource limits** — Memory, CPU, execution time, network request count
- **No direct secret access** — Credentials injected by the host at the boundary
- **Leak detection** on all I/O crossing the sandbox boundary

### 5.4 Memory System with Provenance

PostgreSQL + pgvector for hybrid full-text + vector search, with critical additions:

- **Provenance tagging** — Every memory entry is tagged with its origin: `user_instruction`, `agent_observation`, `external_content`, `tool_result`
- **Trust scoring** — Memories derived from external content have lower trust scores and can be flagged for review
- **Integrity auditing** — Periodic background job that scans memory for anomalous entries (e.g., entries that look like injected instructions, entries that contradict established user preferences)
- **Immutable core memories** — User-defined facts (name, preferences, key relationships) are stored in a protected tier that can only be modified through explicit user commands, never through agent inference
- **Decay and review** — External-sourced memories decay in influence over time unless reinforced by user confirmation

### 5.5 Egress Filter

The last line of defense before any content leaves the system:

- **PII scanner** — Regex + NER model to detect names, addresses, SSNs, health information, financial data
- **Secret pattern matcher** — Detects API keys, tokens, passwords, private keys in outbound content
- **Recipient validation** — For email/messaging, validates that the recipient matches the user's intent (prevents injection-driven misdirection)
- **Volume anomaly detection** — Flags unusual outbound patterns (many messages in short period, messages to new recipients)
- **Content policy check** — Ensures outbound content matches the expected action type (an email should contain email-like content, not a data dump)

### 5.6 Staged File Writes

All file modifications go through a staging workflow:

1. Agent writes proposed changes to a staging directory
2. System generates a diff (or full preview for new files)
3. Diff is presented to user via chat channel with approve/reject/modify options
4. Only on explicit approval are changes committed to the real filesystem
5. All committed changes are logged with before/after snapshots for rollback

### 5.7 Configuration as Code

All agent configuration lives in a git repository:

- `permissions.yaml` — Action tier classifications
- `integrations.yaml` — Connected services and their scoped OAuth tokens
- `guardrails.yaml` — Forbidden patterns, rate limits, circuit breakers
- `identity.md` — Agent personality and behavioral boundaries (equivalent to SOUL.md)
- `tools/` — Tool capability manifests

The agent can *propose* configuration changes (by drafting a diff and sending it via chat), but only the user can merge and trigger redeployment. This enables agent self-improvement while keeping humans in the loop for behavioral changes.

---

## 6. Agent Model: Generalist with Delegation

### 6.1 Architecture Decision: Why Not Multi-Agent?

**Decision:** One generalist agent with delegation capabilities, not separate specialized agents.

The question of multi-agent (email agent, calendar agent, research agent with a router) vs. generalist was resolved by examining how OpenClaw's ecosystem handles this in practice and by analyzing Steward's target use cases.

**OpenClaw's three levels of multi-agent support:**

- **Level 1 — Channel-level routing** (`agents.list[]` + `bindings[]`): Multiple isolated "brains" each with own workspace, memory, session store, personality. Routes WhatsApp to agent A, Telegram to agent B. These aren't specialized agents collaborating — they're isolated personas for different contexts (personal vs. work, or multi-user server). Bindings match on channel/accountId/peer/guildId with precedence rules.
- **Level 2 — Sub-agents for parallelism**: Background agent runs spawned from existing agent, running in their own session (`agent:<agentId>:subagent:<uuid>`). Main agent delegates long-running tasks without blocking the main conversation. Sub-agents cannot spawn sub-agents (no recursive fan-out). This is task parallelism, not specialization.
- **Level 3 — Claude Code Agent Teams** (community-built, experimental): OpenClaw agent spawns Claude Code session which itself forms teams of parallel workers. Bleeding edge, powerful for coding but coordination gaps emerge when the lead starts coding instead of delegating.

**OpenClaw's own recommendation:** Single-agent mode is default and recommended. Most use cases don't require multiple agents. A well-configured single agent with good memory and proper tool access handles most requirements. The community is still figuring out coordination overhead for orchestrator patterns — people actively report issues with infinite loops and inter-agent communication debugging.

**Why generalist wins for Steward's use cases:**

The target tasks — updating a Google Sheet, ordering groceries, submitting health insurance reimbursements — don't need different "brains." They need the same brain with access to different tools. The intelligence required to understand "submit this receipt to Aetna for reimbursement" is the same intelligence required for "add this to my grocery list" — it's the tool execution that differs, not the reasoning capability.

Cross-domain tasks like "check my calendar and email the grocery list to Kristen for tonight's dinner" require unified context from calendar, email, and groceries simultaneously. A router would add latency and lose context. A generalist handles it naturally because it already has the full picture.

### 6.2 Sub-Agent Pool

The generalist agent can delegate work to sub-agents for parallelism and isolated execution. Sub-agents are background agent runs, not specialized agents — they use the same LLM, just in a separate session.

**Sub-agent types:**
- **Research worker** — Spawned for long-running web research, document analysis, or data gathering that would block the main conversation
- **Claude Code session** — Spawned for building new tools, writing integration code, or complex programming tasks (see Self-Expansion Pipeline, Tier 3)
- **Long-running task worker** — Spawned for any operation that takes minutes rather than seconds (batch processing, multi-step workflows)

**Constraints:**
- Sub-agents cannot spawn sub-agents (prevents recursive fan-out / infinite loops)
- Maximum concurrent sub-agents configurable per deployment (`agents.defaults.subagents.maxConcurrent`)
- Sub-agents auto-archive after configurable timeout (default: 60 minutes)
- Each sub-agent runs in its own session with scoped context — it receives the relevant task context from the main agent, not the full conversation history
- Sub-agent results are announced back to the main conversation when complete
- Sub-agents go through the same Guardian LLM + Permission Engine pipeline as the main agent — delegation does not bypass security

**Sub-agent session management:**
```
Session ID format: agent:<agentId>:subagent:<uuid>
Lifecycle:         SPAWNED → RUNNING → COMPLETED | FAILED | TIMED_OUT
Storage:           Separate session store, relevant results merged into main memory on completion
```

---

## 7. Self-Expansion Pipeline

The agent can augment its own capabilities through a three-tier pipeline with human approval at each stage. This addresses the core requirement that the agent should be able to take new actions without the developer building new integrations.

### 7.1 Tier 1 — Skill Files (Prompt-Level, Zero Friction)

**What it is:** The agent creates and modifies SKILL.md documents — markdown files with YAML frontmatter — that get injected into its system prompt. Skills alter how the agent approaches tasks by providing routing logic, step-by-step procedures, and domain-specific knowledge.

**Example:** The agent encounters "submit this receipt to Aetna" for the first time. It figures out the workflow (log into Aetna portal, navigate to claims, upload receipt, fill form fields), then writes a `health-insurance-claims.skill.md` documenting the procedure. Next time, it loads the skill and follows the established process.

**Security model:**
- Skills go through the config-as-code review process — agent drafts, user approves via chat
- Skills cannot grant new tool access — they only help with tasks existing tools can already handle
- Skills are stored in the git-backed config repository and version-controlled
- Skill format follows the Anthropic Agent Skill convention (portable, compatible with Claude Code/Cursor)
- 3,000+ community skills exist on ClawHub that can be evaluated and adopted

**Limitation:** Skills are routing/prompt logic, not new capability. If the agent needs a tool that doesn't exist, it escalates to Tier 2 or 3.

### 7.2 Tier 2 — MCP Discovery and Connection

**What it is:** The agent discovers and connects to MCP (Model Context Protocol) servers that provide new tool capabilities. This taps into the existing ecosystem — MCP servers already exist for Gmail, Google Calendar, Google Sheets, Spotify, Home Assistant, and hundreds of other services.

**Discovery flow:**
1. User mentions a service ("can you check my Spotify") or agent identifies a gap ("I need Google Sheets access to do this")
2. Agent searches known MCP server registries or proposes a specific server
3. MCP proxy generates a conservative default capability manifest (read-only where possible)
4. User reviews the manifest — sees exactly which tools the server exposes and which the agent will be allowed to call
5. On approval, server connects through the MCP proxy with those constraints

**Security model:**
- All MCP connections are proxied (see Section 8: MCP Proxy)
- Per-server capability manifests enforce least-privilege
- Egress filtering on all data flowing through MCP connections
- Full audit logging of every MCP tool call
- User can revoke MCP server access at any time

### 7.3 Tier 3 — Code Generation via Sandboxed Sub-Agent

**What it is:** When no existing tool or MCP server handles a task, the agent delegates to a coding sub-agent (Claude Code session or sandboxed Codex) that builds a new WASM tool or MCP server from scratch.

**Build flow:**
1. Agent identifies capability gap that Tier 1 (skills) and Tier 2 (existing MCP) can't solve
2. Agent spawns Claude Code sub-agent with a scoped task: "build a WASM tool that does X"
3. Sub-agent writes code, tests it, produces a capability manifest declaring its permissions
4. Output goes through staged review:
   - User sees the source code
   - User sees the capability manifest (what the tool can access)
   - User sees the permissions it requests (network endpoints, file access, etc.)
5. On approval, tool is deployed to the WASM sandbox in the tool registry

**Security model:**
- Coding sub-agent runs in isolated session (sub-agent pool constraints apply)
- Generated code must compile to WASM and run sandboxed — no native code execution
- Capability manifest is enforced at runtime regardless of what the code tries to do
- Staged review is mandatory — no auto-deployment of generated tools
- All generated tools are stored in the git-backed config repository

### 7.4 Self-Expansion Rollout Timeline

| Tier | Capability | Available |
|------|-----------|-----------|
| Tier 1 | Skill authoring | Phase 1 (Week 1) |
| Tier 2 | MCP discovery & connection | Phase 3 (Weeks 6-7) |
| Tier 3 | Claude Code delegation / tool generation | Phase 5 (Weeks 11-13) |

---

## 8. MCP Proxy: Security Gateway for External Tools

### 8.1 The Problem

MCP is the primary extensibility mechanism for Steward and the broader agent ecosystem. However, MCP servers run with full system access and represent the biggest security hole in the architecture. IronClaw's own documentation acknowledges this gap — MCP servers bypass the WASM sandbox model entirely, and the framework "can't prevent leaks" through that path.

Every other tool in Steward runs through controlled chokepoints: WASM tools are sandboxed with capability manifests, built-in tools are trusted and audited. But MCP servers are arbitrary external processes that could exfiltrate data, make unauthorized API calls, or behave maliciously.

### 8.2 The Solution: MCP Proxy

MCP servers never connect directly to the agent. A security proxy sits between the agent and all MCP servers, enforcing policy at the protocol level.

```
Agent ──→ MCP Proxy ──→ MCP Server A (Gmail)
                   ├──→ MCP Server B (Google Calendar)
                   ├──→ MCP Server C (Spotify)
                   └──→ MCP Server D (Home Assistant)

Agent sees: unified tool registry (MCP tools indistinguishable from built-in tools)
Agent knows: nothing about the proxy — transparent interception
```

### 8.3 Proxy Functions

**Function 1 — Capability Manifest Enforcement:**

Each MCP server has a YAML capability manifest that declares which tools the agent is allowed to call through that server, with what parameters, at what rate.

```yaml
# mcp-manifests/gmail.yaml
server: gmail-mcp
transport: stdio
allowed_tools:
  - name: gmail.search
    allowed: true
    rate_limit: 30/minute
  - name: gmail.read
    allowed: true
    rate_limit: 60/minute
  - name: gmail.send
    allowed: true
    requires_approval: true  # escalate to human via permission engine
  - name: gmail.delete
    allowed: false           # hard block — never permitted
  - name: gmail.modify_labels
    allowed: true
    rate_limit: 10/minute
blocked_params:
  - pattern: "*.bcc"        # no hidden recipients
  - pattern: "*.forward_to" # no auto-forwarding rules
```

**Function 2 — Bidirectional Egress Filtering:**

All data flowing between agent and MCP server passes through the egress filter stack:
- **Outbound** (agent → MCP server): PII scanner on tool call parameters, secret pattern matcher, recipient/target validation for communication tools
- **Inbound** (MCP server → agent): Response content scanning for injection attempts (MCP server could return poisoned content), content tagging as external data

**Function 3 — Full Audit Logging:**

Every MCP tool call is logged with: timestamp, tool name, parameters (secrets redacted), MCP server identity and manifest version, guardian verdict that approved the call, response summary, latency and error status.

### 8.4 Adding New MCP Servers

```
 ┌────────────┐      ┌───────────────┐      ┌──────────────┐
 │ Agent or   │      │  MCP Proxy    │      │  User        │
 │ User       │      │               │      │  (approval)  │
 └─────┬──────┘      └───────┬───────┘      └──────┬───────┘
       │                     │                      │
       │  1. Propose server  │                      │
       │────────────────────→│                      │
       │                     │                      │
       │                     │  2. Introspect server│
       │                     │     (list tools,     │
       │                     │      capabilities)   │
       │                     │                      │
       │                     │  3. Generate default │
       │                     │     manifest          │
       │                     │     (conservative,    │
       │                     │      read-only first) │
       │                     │                      │
       │                     │  4. Present manifest  │
       │                     │─────────────────────→│
       │                     │                      │
       │                     │  5. User reviews,    │
       │                     │     modifies, approves│
       │                     │←─────────────────────│
       │                     │                      │
       │  6. Server live     │                      │
       │     with constraints│                      │
       │←────────────────────│                      │
```

### 8.5 MCP Proxy Implementation Notes

- **Transport agnostic:** Proxy handles both stdio and SSE transport MCP servers
- **Transparent to agent:** Agent's tool registry shows MCP tools identically to built-in tools — the proxy is invisible
- **Hot-reload manifests:** Capability manifests can be updated without restarting the proxy or agent
- **Circuit breaker:** If an MCP server starts failing or behaving anomalously, the proxy circuit-breaks it (stops routing calls) and alerts the user
- **MCP server isolation:** Each MCP server runs in its own process/container — one compromised server can't affect others
- **Response sanitization:** MCP server responses are treated as external content and tagged accordingly before reaching the agent (same content tagging as the ingress sanitizer)

### 8.6 MCP Proxy vs. Existing Approaches

| Aspect | OpenClaw/IronClaw | Steward MCP Proxy |
|--------|------------------|--------------------|
| MCP server access | Direct — full system access | Proxied — mediated through security gateway |
| Capability control | None — server exposes all tools | Per-server YAML manifests with tool-level allow/block |
| Data filtering | None — "can't prevent leaks" | Bidirectional egress filtering (PII, secrets, injection) |
| Audit trail | Basic logging | Full audit: tool params, guardian verdict, response summary |
| Adding servers | Install and connect | Introspect → generate manifest → user review → connect |
| Runtime protection | None | Circuit breaker, rate limiting, anomaly detection |

### 8.7 Protocol-Level Interception Design

MCP is JSON-RPC 2.0, so every message is a structured object with `method`, `params`, `id`. The proxy intercepts at the JSON-RPC message level, not at the transport level. This is the key design decision — it makes the proxy transport-agnostic. Whether the MCP server uses stdio, SSE, or streamable HTTP, the proxy sees the same JSON-RPC messages.

The critical interception points:

- **`tools/list` response** (server → agent): The proxy filters which tools the agent can see. If `gmail.delete` is blocked in the manifest, it never appears in the tool list. The agent doesn't know the tool exists.
- **`tools/call` request** (agent → server): The proxy enforces permissions, rate limits, parameter validation, and egress filtering before the call reaches the MCP server.
- **`tools/call` response** (server → agent): The proxy scans the response for injection attempts (a malicious MCP server could return poisoned content) and tags it as external data before it reaches the agent.
- **`initialize` handshake**: The proxy intercepts the capability negotiation to ensure the agent and server agree on a capability set compatible with manifest constraints.

### 8.8 Transport Abstraction Layer

The proxy needs to handle two fundamentally different transport modes while presenting a unified message-level API to the interceptor logic:

```
┌──────────────────────────────────────────────────────────┐
│                   MCP PROXY CORE                          │
│                                                           │
│   ┌─────────────────────────────────────────────────┐    │
│   │          MESSAGE INTERCEPTOR                     │    │
│   │                                                   │    │
│   │  Operates on JSON-RPC messages regardless of     │    │
│   │  how they arrived. All policy logic lives here.  │    │
│   │                                                   │    │
│   │  • Manifest enforcement                           │    │
│   │  • Egress filtering (PII/secrets)                │    │
│   │  • Rate limiting                                  │    │
│   │  • Parameter validation                           │    │
│   │  • Audit logging                                  │    │
│   │  • Content tagging on responses                   │    │
│   └──────────┬───────────────────────┬───────────────┘    │
│              │                       │                    │
│   ┌──────────▼──────────┐  ┌────────▼─────────────┐     │
│   │  STDIO TRANSPORT    │  │  HTTP/SSE TRANSPORT   │     │
│   │                     │  │                       │     │
│   │  Spawns MCP server  │  │  Reverse proxy to     │     │
│   │  as child process.  │  │  remote MCP server.   │     │
│   │  Intercepts on      │  │  HTTP POST → request  │     │
│   │  stdin/stdout pipe. │  │  SSE stream → response│     │
│   └─────────────────────┘  └───────────────────────┘     │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

**stdio MCP servers:** The proxy spawns the MCP server as a child process, owns its stdin/stdout, and intercepts all JSON-RPC messages flowing through the pipe. This is clean — the proxy is a man-in-the-middle on the pipe. The proxy is responsible for process lifecycle: spawning, health checking, and termination.

**SSE/HTTP MCP servers:** The proxy acts as an HTTP reverse proxy. The agent thinks it's talking to the MCP server directly, but the proxy sits in between, intercepting HTTP POST requests (agent → server) and SSE event streams (server → agent). For the 2025-11-25 spec's streamable HTTP transport, the proxy handles bidirectional HTTP with proper session management and `Last-Event-ID` support for reconnection.

### 8.9 Tool List Filtering and Schema Rewriting

When the agent sends `tools/list`, the proxy forwards it to the MCP server, gets the full tool list back, then rewrites the response:

```
Server responds with:  [gmail.search, gmail.read, gmail.send, gmail.delete, gmail.modify_labels]
Manifest says:         allowed: [gmail.search, gmail.read, gmail.send]
                       blocked: [gmail.delete, gmail.modify_labels]
Proxy returns to agent: [gmail.search, gmail.read, gmail.send]
```

The proxy also rewrites tool **input schemas**. If `gmail.send` has a `bcc` parameter that the manifest's `blocked_params` list includes, the proxy strips that parameter from the tool's JSON Schema `inputSchema` before the agent ever sees it. The agent literally cannot construct a tool call with a blocked parameter because the schema doesn't include it. This is proactive defense — rather than rejecting bad calls after the fact, the agent never knows the capability exists.

Schema rewriting rules from the manifest:

```yaml
# Per-tool schema overrides
schema_rewrites:
  gmail.send:
    strip_params: ["bcc", "forward_to"]
    constrain_params:
      to:
        max_recipients: 5        # Prevent mass-mailing
      attachments:
        max_size_bytes: 10485760 # 10MB limit
  gmail.search:
    constrain_params:
      max_results:
        maximum: 50              # Prevent context flooding
```

### 8.10 Tool Call Enforcement Pipeline

When the agent calls a tool, the request goes through a multi-stage pipeline within the proxy:

```
Agent sends: tools/call { name: "gmail.send", arguments: { to: "kristen@...", subject: "...", body: "..." } }

Stage 1 — Manifest Check
  Is gmail.send in the allowed_tools list? → YES, continue
  Are all parameters in the allowed schema? → Check for blocked params (bcc, forward_to)
  If blocked tool or param → Return JSON-RPC error, log attempt

Stage 2 — Permission Tier Override
  Does the manifest specify a permission_tier for this tool?
  gmail.send → human_approval → Escalate to Permission Engine
  (Agent's tool call is held until user approves via WhatsApp/chat)

Stage 3 — Rate Limit Check
  gmail.send rate_limit: 5/minute → Token bucket check
  Under limit? → Continue
  Over limit? → Return JSON-RPC error with retry-after hint

Stage 4 — Egress Filter (outbound)
  Scan all arguments through the shared egress filter stack:
  - PII patterns (SSN, credit card, health info)
  - Secret patterns (API keys, tokens, passwords, private keys)
  - Recipient validation (for communication tools)
  Body contains SSN? → BLOCK, log, alert user
  Body contains API key pattern? → BLOCK, log, alert user

Stage 5 — Credential Injection
  Secret Broker injects auth credentials at the transport boundary
  Agent never sees raw OAuth token — broker adds it to the outbound request

Stage 6 — Forward to MCP Server
  Proxy strips any internal metadata, forwards clean JSON-RPC to server

Stage 7 — Response Scan (inbound)
  Server returns result → Scan for injection patterns
  Tag response as [EXTERNAL_CONTENT source="mcp:gmail" tool="gmail.send"]
  Scan for unexpected content types (e.g., HTML that looks like prompt injection)
  Check response size against configurable limits (prevent context flooding)

Stage 8 — Audit Log
  Log: timestamp, tool, params (secrets redacted), guardian verdict,
  response summary, latency, manifest version, server identity
  All logs append-only to PostgreSQL audit table

Stage 9 — Return to Agent
  Filtered, tagged response delivered to agent context
```

Note that Stages 1-4 happen within the proxy. The Guardian LLM and Permission Engine operate *before* the call reaches the proxy — the proxy enforces capability constraints, while the guardian evaluates intent. This separation means the proxy can be fast (no LLM calls in the hot path for auto-execute tier tools) while the guardian handles the reasoning-heavy security decisions upstream.

### 8.11 Connection Lifecycle and Circuit Breaker

Each MCP server connection goes through a state machine:

```
REGISTERED → CONNECTING → INTROSPECTING → ACTIVE → (CIRCUIT_BROKEN) → DISCONNECTED

REGISTERED:      Manifest approved by user, server config stored in config-as-code
CONNECTING:      Proxy establishing transport (spawning process or HTTP handshake)
INTROSPECTING:   Proxy sends initialize + tools/list to verify server matches manifest
                 If server exposes tools not in manifest → log warning, filter silently
                 If server is missing tools from manifest → log warning, mark unavailable
ACTIVE:          Normal operation — tool calls flowing through enforcement pipeline
CIRCUIT_BROKEN:  Server failing — proxy stops routing calls, returns clean errors
DISCONNECTED:    Clean shutdown, user revocation, or unrecoverable failure
```

**Circuit breaker logic:**

```yaml
# Per-server circuit breaker config (in manifest)
circuit_breaker:
  error_threshold: 5          # Consecutive errors before tripping
  error_window: 60s           # Time window for error counting
  latency_threshold: 30s      # Max response time before counting as error
  recovery_timeout: 120s      # How long to wait before retry
  recovery_probes: 3          # Successful probes needed to close circuit
  max_recovery_backoff: 15m   # Maximum backoff between retry attempts
```

When a circuit trips: all pending tool calls get a clean JSON-RPC error response, the agent gets a notification ("Gmail MCP server is temporarily unavailable"), and the user gets an alert via their primary channel. The proxy retries on an exponential backoff schedule with jitter and auto-recovers when the server returns healthy probes.

**Hot-reload manifests:** Capability manifests are file-watched. When a manifest YAML changes on disk (e.g., user approved a config-as-code PR), the proxy reloads it without restarting. Active connections are preserved — the new manifest takes effect on the next `tools/list` request and all subsequent `tools/call` validations.

### 8.12 Integration with the Full Security Stack

This is what differentiates Steward's proxy from enterprise MCP gateways (Kong, Envoy, Traefik, etc.). Those gateways focus on multi-tenant RBAC, OAuth, and enterprise governance. Steward's proxy is purpose-built for a single-agent deployment with deep integration into the full security pipeline:

```
Agent proposes action: tools/call gmail.send(...)
       │
       ▼
Guardian LLM reviews the proposed action
  (Does this match user intent? Is this injection-driven?)
  [INTENT LAYER — catches reasoning-level attacks]
       │
       ▼
Permission Engine checks tier
  (gmail.send → human_approval → ask user)
  [POLICY LAYER — enforces declarative rules]
       │
       ▼
MCP Proxy enforces manifest + egress filter
  (Allowed tool? Clean params? Rate limit OK? No PII leaking?)
  [CAPABILITY LAYER — enforces technical constraints]
       │
       ▼
Secret Broker injects credentials
  (OAuth token for Gmail injected at transport boundary)
  [CREDENTIAL LAYER — agent never sees raw secrets]
       │
       ▼
MCP Server receives authenticated, validated, filtered call
```

Each layer catches different failure modes:
- **Guardian** catches injection-driven intent ("the agent was tricked into sending this email by a malicious calendar invite")
- **Permission Engine** catches policy violations ("email.send requires human approval regardless of guardian verdict")
- **MCP Proxy** catches capability violations ("this tool call includes a blocked parameter" or "this call contains PII in the body")
- **Secret Broker** prevents credential exposure ("OAuth token is injected at the boundary, never visible to the agent or the proxy's audit logs")

No single layer is trusted to be sufficient — this is defense in depth applied to every MCP tool call.

---

## 9. Day-One Capability Stack

To be genuinely useful from day one, Steward ships with a practical baseline of tools and integrations.

### 9.1 Built-in Tools (Direct, No MCP)

| Tool | Description | Permission Tier |
|------|-------------|----------------|
| Shell exec | Sandboxed command execution | human_approval |
| Filesystem | Staged file reads/writes with diff preview | auto (read) / human_approval (write) |
| Web browser | Headless browsing with content extraction | log_and_execute |
| Web search | Search engine queries | auto_execute |

### 9.2 MCP Integrations (Proxied, First Wave)

| MCP Server | Use Cases | Default Manifest |
|------------|-----------|-----------------|
| Gmail | Read, search, draft, send email | Read: auto. Send: human_approval. Delete: blocked |
| Google Calendar | Read, create, modify events | Read: auto. Create/modify: human_approval |
| Google Sheets/Docs | Read and edit documents | Read: auto. Edit: log_and_execute |
| Spotify | Playback control, playlists | All: auto_execute |
| Home Assistant | Smart home control | Read: auto. Control: log_and_execute |

### 9.3 Self-Expansion Availability

- **Skill authoring (Tier 1):** Available from Week 1 — agent can immediately start learning new task patterns
- **MCP discovery (Tier 2):** Available from Phase 3 — agent can propose connecting to new services
- **Code generation (Tier 3):** Available from Phase 5 — agent can build entirely new tools when nothing else exists


---

## 10. Communication Layer

### Supported Channels (Priority Order)

1. **WhatsApp** — Primary channel (via WhatsApp Business API / Baileys)
2. **Telegram** — Secondary channel (via grammY)
3. **Web Chat** — Dashboard/admin interface
4. **Slack** — For work contexts
5. **Signal** — For privacy-sensitive users
6. **Discord** — Community/social contexts

### Channel Security

- **Webhook signature verification** — Validate inbound messages are authentic (not spoofed)
- **Rate limiting** — Circuit breaker if the agent tries >N actions per minute
- **Confirmation UX** — For high-risk actions, the confirmation flow shows the full action details (draft email with recipient, calendar event details, etc.) — not just "OK to proceed? Y/N"
- **Channel-specific policies** — Different permission tiers per channel (e.g., WhatsApp gets full access, public Discord gets read-only)

---

## 11. Model Support

Provider-agnostic with failover chains:

### Primary Agent

| Provider | Models | Notes |
|----------|--------|-------|
| Anthropic | Claude Opus 4.6, Sonnet 4.5 | Recommended for prompt injection resistance |
| Meta | Llama 4 | Self-hosted option, no API dependency |
| OpenAI | GPT-5.3, o3 | Strong tool use capabilities |
| Google | Gemini 2.5 Pro | Long context window |
| Local | Ollama, vLLM | Fully offline operation |

### Guardian LLM

Deliberately smaller and cheaper than the primary agent. The guardian processes far more requests (every proposed action) so cost efficiency matters. Candidates: Claude Haiku 4.5, Llama 3.3 70B (local), GPT-4.1-mini.

---

## 12. Project Structure

```
steward/
├── core/
│   ├── agent.rs              # Main agent loop + LLM interaction
│   ├── guardian.rs            # Guardian LLM — action review before execution
│   ├── permissions.rs         # Permission engine — YAML manifest enforcement
│   ├── router.rs              # Intent classification and job routing
│   ├── scheduler.rs           # Parallel job execution with priorities
│   └── worker.rs              # Job execution with LLM reasoning + tool calls
│
├── security/
│   ├── ingress_sanitizer.rs   # Prompt injection preprocessing + content tagging
│   ├── egress_filter.rs       # PII/secret detection on ALL outbound content
│   ├── secret_broker.rs       # Encrypted vault + credential injection at boundary
│   ├── leak_detector.rs       # Bidirectional secret scanning on I/O
│   └── audit_logger.rs        # Append-only action logging + anomaly detection
│
├── memory/
│   ├── workspace.rs           # PostgreSQL-backed persistent memory
│   ├── search.rs              # Hybrid FTS + vector search (RRF)
│   ├── provenance.rs          # Memory origin tracking + trust scoring
│   └── integrity.rs           # Periodic memory audit + poisoning detection
│
├── tools/
│   ├── registry.rs            # Tool discovery + capability enforcement
│   ├── wasm_sandbox.rs        # WASM tool execution with capability manifests
│   ├── mcp_proxy.rs           # MCP proxy core — message interceptor + transport abstraction
│   ├── mcp_manifest.rs        # Per-server capability manifest parser + enforcer
│   ├── mcp_introspect.rs      # MCP server introspection + manifest generation
│   ├── mcp_schema_rewrite.rs  # Tool list filtering + input schema rewriting
│   ├── mcp_circuit_breaker.rs # Per-server circuit breaker + connection lifecycle
│   ├── mcp_transport_stdio.rs # stdio transport adapter (child process management)
│   ├── mcp_transport_http.rs  # HTTP/SSE transport adapter (reverse proxy)
│   ├── staging.rs             # Staged file writes with diff preview
│   ├── subagent_pool.rs       # Sub-agent lifecycle management + session isolation
│   ├── skill_manager.rs       # Skill file authoring, loading, and review workflow
│   ├── self_expansion.rs      # Three-tier expansion pipeline orchestrator
│   └── built_in/              # Trusted in-process tools
│       ├── shell.rs
│       ├── filesystem.rs
│       ├── browser.rs
│       ├── search.rs
│       └── email.rs
│
├── channels/
│   ├── manager.rs             # Channel multiplexer
│   ├── whatsapp.rs            # WhatsApp Business API adapter
│   ├── telegram.rs            # Telegram via grammY
│   ├── slack.rs               # Slack adapter
│   ├── signal.rs              # Signal adapter
│   ├── web.rs                 # Web chat + admin dashboard
│   └── confirmation.rs        # Human-in-the-loop approval UX
│
├── config/
│   ├── permissions.yaml       # Declarative action tier classifications
│   ├── integrations.yaml      # Connected services + scoped OAuth
│   ├── guardrails.yaml        # Forbidden patterns, rate limits, circuit breakers
│   ├── identity.md            # Agent personality + behavioral boundaries
│   └── mcp-manifests/         # Per-MCP-server capability manifests
│       ├── gmail.yaml
│       ├── gcal.yaml
│       ├── gsheets.yaml
│       └── ...
│
├── skills/                    # Skill files (SKILL.md format)
│   ├── curated/               # Community skills reviewed + approved
│   └── agent-authored/        # Skills the agent wrote (git-tracked)
│
├── dashboard/
│   ├── audit_viewer.rs        # Web UI for reviewing action logs
│   ├── memory_browser.rs      # Inspect + manage persistent memory
│   └── config_editor.rs       # View/propose config changes
│
├── deploy/
│   ├── Dockerfile             # Hardened container with read-only root
│   ├── docker-compose.yml     # Full stack: agent + PostgreSQL + monitoring
│   └── terraform/             # Optional IaC for DigitalOcean/AWS
│
└── tests/
    ├── injection_suite/       # Red-team prompt injection test cases
    ├── permission_tests/      # Permission enforcement verification
    ├── guardian_tests/        # Guardian LLM accuracy benchmarks
    └── integration/           # End-to-end channel tests
```

---

## 13. What We Borrow vs. What We Build

### Borrowed from IronClaw (proven, adopt directly)

- WASM sandbox with capability-based permissions for untrusted tools
- Credential injection at host boundary (agent never sees raw secrets)
- Bidirectional leak detection on tool I/O
- Endpoint allowlisting for HTTP requests
- PostgreSQL + pgvector for persistent memory with hybrid search
- Rust as implementation language (memory safety, single binary, native performance)

### Borrowed from OpenClaw (concepts, reimplemented securely)

- Multi-channel communication architecture (WhatsApp, Telegram, Slack, etc.)
- Identity files (SOUL.md → identity.md) for agent personality
- Heartbeat/cron system for proactive background tasks
- Session management with context window budgeting
- Tool approval workflows (but with our tiered permission system)

### Novel to Steward (our differentiation)

- **Guardian LLM** — Secondary model reviewing every action before execution
- **Memory provenance + integrity** — Origin tracking, trust scoring, poisoning detection
- **Channel-level egress filtering** — PII/secret scanning on ALL outbound messages
- **Staged file writes** — Diff preview + human approval before any file mutation
- **Declarative permission manifests** — Auditable YAML defining action tiers
- **Configuration as code** — Git-backed, version-controlled agent configuration with human-approved evolution
- **Continuous security monitoring** — Real-time anomaly detection over audit logs (not point-in-time CLI)
- **MCP proxy with filtering** — Security gateway wrapping all MCP servers with per-server capability manifests, bidirectional egress filtering, and full audit logging (addressing IronClaw's acknowledged gap)
- **Generalist + delegation model** — Single agent with unified context + sub-agent pool for parallelism, validated against OpenClaw's multi-agent ecosystem
- **Three-tier self-expansion** — Agent can teach itself (skills), connect to new services (MCP discovery), and build new tools (code generation) — all with human approval gates

---

## 14. Build Phases

### Phase 1: Foundation (Weeks 1-3)

- Basic agent loop with single LLM provider (Claude or Llama)
- WhatsApp channel adapter with webhook auth
- ALL actions require manual approval (safe baseline — no autonomy yet)
- PostgreSQL setup with audit logging
- Encrypted secret storage with system keychain
- **Skill file infrastructure** — SKILL.md loading, authoring workflow, review via chat (Tier 1 self-expansion)

### Phase 2: Permission Engine (Weeks 4-5)

- Implement permission YAML manifest parser and enforcer
- Classify initial action set into tiers
- Allow auto-execute for read-only actions
- Build the human approval confirmation UX in WhatsApp

### Phase 3: Ingress + Egress Security (Weeks 6-7)

- Ingress sanitizer with content tagging and pattern detection
- Egress filter with PII scanner and secret pattern matcher
- Leak detector on all tool I/O
- Secret broker with credential injection pattern
- **MCP proxy foundation** — proxy process, manifest parser, egress filtering on MCP traffic
- **MCP discovery workflow** — server introspection, default manifest generation, user approval flow (Tier 2 self-expansion)

### Phase 4: Guardian LLM (Weeks 8-10)

- Design guardian prompt and evaluation criteria
- Implement guardian as interception layer between agent and execution
- Build test suite of injection scenarios to validate guardian accuracy
- Tune guardian sensitivity (minimize false positives while catching real attacks)

### Phase 5: WASM Sandbox + Tools (Weeks 11-13)

- WASM runtime integration with capability manifest enforcement
- Port initial tools to WASM (or build adapters)
- **Sub-agent pool** — session management, lifecycle, max concurrency, auto-archive
- **Claude Code sub-agent delegation** — spawn coding sessions for tool generation (Tier 3 self-expansion)
- Staged file write workflow
- **First-wave MCP integrations** — Gmail, Google Calendar, Google Sheets through proxy with manifests

### Phase 6: Memory + Persistence (Weeks 14-15)

- Hybrid search (FTS + vector) with RRF scoring
- Memory provenance tagging and trust scoring
- Integrity audit background job
- Immutable core memory tier

### Phase 7: Hardening + Open Source (Weeks 16-18)

- Red-team the entire system with crafted injection attacks
- Continuous security monitoring daemon
- Documentation and contributor guide
- Dashboard for audit review and memory browsing
- Open-source release prep: LICENSE, CONTRIBUTING.md, security policy

---

## 15. Key Design Decisions (Rationale)

| Decision | Rationale |
|----------|-----------|
| **Rust over TypeScript** | Memory safety, single binary distribution, no runtime dependency. OpenClaw's TypeScript codebase has had multiple prototype pollution and injection vulnerabilities that Rust's type system would prevent. |
| **WASM over Docker for tool sandboxing** | Lighter weight (~ms startup vs seconds), capability-based (not all-or-nothing), no daemon dependency. IronClaw proved this works. |
| **PostgreSQL over SQLite/JSONL** | Production-ready, supports pgvector for embeddings, append-only audit logging is natural, concurrent access for monitoring. |
| **Guardian as separate LLM call** | The primary agent's context is contaminated by external content — the guardian operates on a clean, distilled summary and is therefore harder to inject. |
| **YAML permission manifests** | Human-readable, auditable, diffable in git, no code changes needed to adjust policy. |
| **No NEAR AI / vendor auth dependency** | IronClaw's NEAR AI requirement conflicts with self-hosted ethos. Provider-agnostic from day one. |
| **Staged writes over direct file access** | Irreversible actions are the highest-risk category. Staging adds friction that prevents both injection-driven and hallucination-driven damage. |
| **Generalist over multi-agent** | Cross-domain tasks need unified context. Separate specialized agents create coordination overhead worse than the problem they solve. OpenClaw's ecosystem validates: single agent with good tools is the default that works. |
| **Three-tier self-expansion** | Graduated capability: skills (prompt-level, zero friction) → MCP discovery (existing ecosystem) → code generation (build anything). Each tier has its own security model and human approval gate. |
| **MCP proxy over direct connection** | MCP servers run with full system access — IronClaw acknowledges they can't prevent leaks. Proxying adds capability manifests, egress filtering, and audit logging without breaking MCP protocol compatibility. |

---

## 16. Open Questions for Future Design Sessions

- **Guardian LLM detailed architecture**: Prompt design, evaluation criteria, handling of edge cases, latency budget, cost optimization
- ~~**MCP proxy design**~~ → **RESOLVED in v0.2** (Section 8)
- **Memory integrity verification**: What heuristics detect poisoned memories? How to avoid false positives?
- ~~**Multi-agent routing**~~ → **RESOLVED in v0.2**: Generalist + delegation (Section 6)
- **Offline/local-only mode**: Full operation with Ollama/vLLM and no cloud dependencies
- **Mobile companion app**: Lightweight approval interface for on-the-go confirmation of high-risk actions
- **MCP proxy detailed spec** ~~(NEW)~~ → **RESOLVED in v0.3** (Sections 8.7-8.12): Protocol-level interception, transport abstraction (stdio + HTTP/SSE), tool schema rewriting, multi-stage enforcement pipeline, connection lifecycle with circuit breaker, and integration with full security stack
- **Sub-agent security model** (NEW): How the guardian evaluates sub-agent spawning requests, context scoping for sub-agent sessions, preventing privilege escalation through delegation
- **Skill file trust model** (NEW): Should community skills from ClawHub go through a different review process than agent-authored skills? How to handle skill supply chain attacks (OpenClaw found ~20% of ClawHub skills were malicious)
