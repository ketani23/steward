# Steward Memory System — Requirements Document

## Vision
A security-first, personality-aware memory system that gives Steward durable knowledge across sessions and channels, with scoped memory partitions per personality and a shared knowledge base underneath.

## Architecture Overview

```
┌──────────────────────────────────────────┐
│              MEMORY ENGINE               │
│         (PostgreSQL + pgvector)          │
├──────────────────────────────────────────┤
│                                          │
│  ┌─────────────────────────────────┐     │
│  │        SHARED MEMORY            │     │
│  │  (user facts, world knowledge,  │     │
│  │   cross-cutting decisions)      │     │
│  └─────────────────────────────────┘     │
│                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │ dev scope│ │mktg scope│ │admin     │ │
│  │          │ │          │ │scope     │ │
│  └──────────┘ └──────────┘ └──────────┘ │
│                                          │
├──────────────────────────────────────────┤
│  EXTRACTION │ RECALL │ REFLECTION │ AUDIT│
└──────────────────────────────────────────┘
```

## Core Requirements

### R1: Structured Fact Storage (not raw chunks)

**What**: Extract structured, self-contained facts from conversations using an LLM. Store facts, not conversation chunks.

**Why**: Raw text chunks are noisy, context-dependent, and degrade search quality at scale. Structured facts are precise and composable.

**Schema**:
```sql
memories (
  id UUID PRIMARY KEY,
  content TEXT NOT NULL,           -- The fact in natural language
  content_embedding VECTOR(768),   -- For semantic search
  
  -- Scoping
  scope TEXT NOT NULL DEFAULT 'shared',  -- 'shared' | personality_id
  entity_refs TEXT[],              -- Entity IDs this fact relates to
  
  -- Provenance & Trust
  source_type TEXT NOT NULL,       -- 'user_instruction' | 'agent_observation' | 'tool_result' | 'external_content'
  source_session TEXT,             -- Which session produced this
  source_channel TEXT,             -- Which channel (telegram, api, slack)
  trust_score FLOAT NOT NULL DEFAULT 0.5,
  
  -- Temporal
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_accessed_at TIMESTAMPTZ,
  access_count INT DEFAULT 0,
  valid_from TIMESTAMPTZ,          -- When this fact became true (if known)
  valid_until TIMESTAMPTZ,         -- When this fact stopped being true (if known)
  superseded_by UUID REFERENCES memories(id),  -- Points to the replacing fact
  
  -- Metadata
  confidence FLOAT DEFAULT 1.0,    -- How confident the extraction is
  tags TEXT[]                       -- Freeform tags for filtering
)
```

**Acceptance criteria**:
- After a conversation where the user says "I moved to Brooklyn", a fact like "User lives in Brooklyn" is stored with source_type='user_instruction', scope='shared'
- Facts are deduplicated: saying "I live in Brooklyn" twice doesn't create two entries
- Extraction happens automatically after each agent turn (implicit, not tool-dependent)

### R2: Scoped Memory (Personality Partitions)

**What**: Each personality has its own memory scope plus read access to shared memory. Facts are written to the current personality's scope by default.

**Why**: A developer personality shouldn't have marketing campaign details polluting its search results, and vice versa. But both need to know user preferences.

**Implementation**:
- Memory scope is a TEXT field on each fact
- Search query includes `WHERE scope IN ('shared', :current_personality)`
- Write defaults to current personality's scope
- Explicit promotion: a fact can be moved from personality scope to 'shared' by the agent or a reflection job
- Personality ID comes from the agent/persona config, not from the channel

**Acceptance criteria**:
- Developer persona searching "deployment strategy" only sees dev-scoped and shared memories
- Marketing persona searching "brand voice" only sees marketing-scoped and shared memories
- A fact learned in dev scope about user preferences can be promoted to shared

### R3: Implicit Extraction + Explicit Recall

**What**: Two separate paths for memory writes and reads.

**Writes (implicit)**: After each agent response, an extraction pipeline runs asynchronously to identify and store new facts from the conversation. The agent does NOT need to call a tool to remember things.

**Reads (explicit + implicit)**:
- **Implicit injection**: Before each agent turn, search memory for relevant context based on the user's message and inject top results into the system prompt. The agent doesn't need to actively search.
- **Explicit tool**: `memory.search` tool for when the agent wants to actively search for specific information.

**Why**: Implicit extraction solves the biggest weakness in OpenClaw's system — relying on the LLM to decide to remember things. Implicit injection means the agent has context without burning a tool call.

**Extraction pipeline**:
1. After agent responds, send the conversation turn to a lightweight LLM call
2. LLM extracts facts as structured JSON: `[{content, scope_suggestion, entity_refs, confidence}]`
3. Deduplicate against existing memories (semantic similarity > 0.9 = likely duplicate)
4. For near-matches (0.7-0.9 similarity), check if this is an UPDATE (supersede old fact) or genuinely new
5. Store with full provenance

**Acceptance criteria**:
- A conversation about deploying Steward automatically creates memories about deployment without the agent calling any tool
- Before the agent responds to "how do we deploy?", relevant deployment memories are injected into context
- The agent can also explicitly call memory.search for targeted queries

### R4: Update Semantics (Supersede, Don't Append)

**What**: When a new fact contradicts an existing one, the old fact is marked as superseded and the new one takes its place.

**Why**: Append-only memory creates contradictions. "User lives in Tenafly" and "User moved to Brooklyn" shouldn't coexist as equal facts.

**Implementation**:
- During extraction, check for semantic conflicts with existing facts (same entity + similar topic but different value)
- LLM-assisted conflict resolution: present the old and new fact, ask which is current
- Winner gets stored; loser gets `superseded_by = winner.id` and `valid_until = NOW()`
- Superseded facts are excluded from search by default but retained for audit

**Acceptance criteria**:
- Saying "I moved to Brooklyn" after "I live in Tenafly" results in one active fact (Brooklyn) with the old fact (Tenafly) superseded
- Superseded facts can still be found with `include_superseded=true` for auditing
- The conflict resolution prompt is logged for transparency

### R5: Temporal Decay + Access Reinforcement

**What**: Memories that are never accessed gradually lose relevance in search rankings. Memories that are frequently accessed stay strong.

**Why**: Prevents noise accumulation. A conversation from 6 months ago about a one-off debugging session shouldn't rank alongside active project knowledge.

**Implementation**:
- Search score multiplier: `decay_factor = exp(-lambda * days_since_last_access)`
- Each successful retrieval updates `last_accessed_at` and increments `access_count`
- Configurable lambda (default: 0.01, meaning ~50% weight after 69 days of no access)
- Reflection job can periodically prune memories below a threshold (e.g., trust_score * decay_factor < 0.05)

**Acceptance criteria**:
- A memory accessed yesterday ranks higher than an identical-relevance memory last accessed 3 months ago
- Frequently-accessed memories maintain high scores indefinitely
- A periodic job can prune decayed memories (with configurable thresholds)

### R6: Cross-Channel Identity

**What**: Memory is channel-agnostic. Facts learned via Telegram are available when querying via Slack, API, or any other channel.

**Why**: The user is one person. An agent that "forgets" when you switch channels is broken.

**Implementation**:
- Memory storage has no channel dependency — `source_channel` is metadata, not a filter
- Session management tracks which channel a conversation is on, but memory queries don't filter by channel
- Personality (not channel) determines memory scope

**Acceptance criteria**:
- Tell Steward something via Telegram, ask about it via the HTTP API — it remembers
- `source_channel` is recorded for provenance but never used to filter search results

### R7: Provenance + Trust Scoring

**What**: Every memory tracks where it came from and how trustworthy it is.

**Why**: Security differentiator. A fact from a trusted sender should outweigh a fact extracted from an untrusted web page. Enables memory poisoning detection.

**Trust scoring rules**:
- `user_instruction` from trusted sender: trust = 1.0
- `user_instruction` from allowed (non-trusted) sender: trust = 0.7
- `agent_observation` (agent's own reasoning): trust = 0.6
- `tool_result` (from a tool execution): trust = 0.5
- `external_content` (web fetch, email, etc.): trust = 0.3

**Search ranking**: `final_score = relevance_score * trust_score * decay_factor`

**Acceptance criteria**:
- A memory from the owner saying "deploy to prod" has higher trust than a memory from a web search saying "best practice is to deploy to staging first"
- Trust scores are visible in search results
- Memory poisoning detection: alert if a batch of low-trust memories contradict high-trust ones

### R8: Memory Tools (Agent-Facing)

**What**: Tools the agent can use to interact with memory explicitly.

**Tools**:
- `memory.search(query, scope?, limit?, include_superseded?)` — Search memories. Returns facts with scores, provenance, timestamps.
- `memory.store(content, scope?, entity_refs?, tags?)` — Explicitly store a fact (for when the agent wants to remember something specific beyond auto-extraction).
- `memory.forget(memory_id, reason)` — Soft-delete a memory with audit trail.

**Permission tiers**:
- `memory.search` → `log_and_execute` (safe, read-only)
- `memory.store` → `log_and_execute` (low risk, audited)
- `memory.forget` → `human_approval` (destructive)

**Acceptance criteria**:
- Agent can search memories and gets structured results with scores
- Agent can explicitly store a fact when auto-extraction might miss nuance
- Agent can forget a memory (with approval) and it's soft-deleted with reason logged

### R9: Reflection Jobs

**What**: Periodic background jobs that maintain memory quality.

**Jobs**:
1. **Consolidation**: Merge related facts into summaries when a topic has many small facts
2. **Conflict detection**: Find contradictory active facts and flag for resolution
3. **Scope promotion**: Identify personality-scoped facts that should be shared
4. **Decay pruning**: Remove memories below relevance threshold
5. **Entity page generation**: Create/update entity summary pages (markdown export)

**Frequency**: Configurable. Default: daily.

**Acceptance criteria**:
- After running consolidation, 15 facts about the same topic become 3-5 consolidated facts
- Conflicting facts are flagged with a log/notification
- Entity pages are human-readable Markdown exports

### R10: Security & Audit

**What**: Memory-specific security measures consistent with Steward's security-first design.

**Requirements**:
- All memory writes go through ingress sanitization (existing pipeline)
- Memory poisoning detection: statistical anomaly detection on trust scores, bulk write patterns
- Audit trail: every write, update, supersede, and delete is logged with timestamp and actor
- No PII in embeddings (embed sanitized content only)
- Memory export requires human approval
- Rate limiting on memory writes (prevent flooding)

**Acceptance criteria**:
- An attempt to inject false memories via untrusted content triggers an alert
- Every memory mutation has an audit log entry
- Memory export is gated behind human_approval permission

## Implementation Phases

### Phase 1: Foundation (wire up what exists + basic extraction)
- Fix `memories` table creation at startup
- Wire up PgMemoryStore + HybridMemorySearch to the agent
- Add `scope` column and basic filtering
- Implement extraction pipeline (post-turn LLM call)
- Add `memory.search` and `memory.store` tools
- Add implicit injection (pre-turn memory lookup)

### Phase 2: Intelligence (updates, decay, provenance)
- Implement conflict detection + supersede semantics
- Add temporal decay to search scoring
- Add access-count reinforcement
- Implement trust scoring based on source type
- Add `memory.forget` tool with audit

### Phase 3: Multi-Personality
- Add personality config to agent definition
- Scope-aware extraction (auto-assign personality scope)
- Scope-aware search (personality + shared)
- Scope promotion mechanics

### Phase 4: Reflection + Export
- Consolidation job
- Conflict detection job
- Entity page generation (Markdown export)
- Memory health dashboard
- Poisoning detection

## Non-Goals (for now)
- Knowledge graph / entity-relationship storage (phase 5+ if needed)
- Full-text Markdown file management (OpenClaw's approach — we're going DB-first)
- Real-time streaming memory updates
- Multi-user memory sharing (single-owner for now)

## Resolved Design Decisions
1. **Embedding model**: Use the Anthropic API (already configured) via the Voyager-3 embedding model, with a trait-based EmbeddingProvider so we can swap to local GGUF later. For Phase 1, OpenAI text-embedding-3-small is fine since we already have an API key in the repo.
2. **Extraction aggressiveness**: Extract every turn but use a lightweight LLM call (Haiku-class) to keep costs low. The extraction prompt should return empty array if no new facts are present, so no-op turns are cheap.
3. **Reflection jobs**: Run inside Steward as a configurable periodic task (like a heartbeat). No separate process.
4. **Phase 1 scope**: Fix memories table, wire up search + extraction pipeline, add memory.search + memory.store tools, add implicit pre-turn injection. Skip update semantics and personality scoping for Phase 1.
