//! Steward server binary.
//!
//! Wires all subsystems together and runs the Steward agent:
//! - CLI args via `clap`
//! - Config loading from disk
//! - Database connection + migrations
//! - Component initialization (security, LLM, guardian, permissions, tools, memory, channels)
//! - Webhook/HTTP server for inbound messages
//! - Message processing loop (inbound → agent → outbound)
//! - Graceful shutdown on SIGTERM/SIGINT

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use clap::Parser;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use steward_channels::manager::ChannelManager;
use steward_channels::telegram::{TelegramAdapter, TelegramConfig};
use steward_channels::whatsapp::{WhatsAppAdapter, WhatsAppConfig};
use steward_core::agent::{Agent, AgentConfig, AgentDeps};
use steward_core::conversation::ConversationStore;
use steward_core::guardian::{GuardianConfig, GuardianLlm};
use steward_core::llm::anthropic::AnthropicProvider;
use steward_core::permissions::YamlPermissionEngine;
use steward_security::audit::{self, InMemoryAuditLogger, PostgresAuditLogger};
use steward_security::egress::{EgressFilterConfig, EgressFilterImpl};
use steward_security::ingress::{DefaultIngressSanitizer, IngressSanitizerConfig};
use steward_security::leak_detector::PatternLeakDetector;
use steward_tools::built_in::file_edit::FileEditTool;
use steward_tools::built_in::file_list::FileListTool;
use steward_tools::built_in::file_read::FileReadTool;
use steward_tools::built_in::file_write::FileWriteTool;
use steward_tools::built_in::shell::{ShellConfig, ShellTool};
use steward_tools::built_in::workspace::workspace_root;
use steward_tools::registry::ToolRegistryImpl;
use steward_types::actions::{ChannelType, InboundMessage, OutboundMessage};
use steward_types::config::IdentityConfig;
use steward_types::config_loader::ConfigLoader;
use steward_types::traits::{AuditLogger, ChannelAdapter};
use uuid::Uuid;

/// Steward — security-hardened autonomous AI agent.
#[derive(Parser, Debug)]
#[command(name = "steward", version, about)]
struct Cli {
    /// Path to the config directory (contains permissions.yaml, guardrails.yaml, identity.md).
    #[arg(long, default_value = "config", env = "STEWARD_CONFIG_DIR")]
    config_dir: PathBuf,

    /// PostgreSQL connection URL.
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// Anthropic API key for the primary LLM.
    #[arg(long, env = "ANTHROPIC_API_KEY")]
    anthropic_api_key: String,

    /// Model to use for the primary agent LLM.
    #[arg(
        long,
        default_value = "claude-sonnet-4-5-20250929",
        env = "STEWARD_MODEL"
    )]
    model: String,

    /// Model to use for the guardian LLM.
    #[arg(
        long,
        default_value = "claude-haiku-4-5-20251001",
        env = "STEWARD_GUARDIAN_MODEL"
    )]
    guardian_model: String,

    /// Host to bind the HTTP server to.
    #[arg(long, default_value = "0.0.0.0", env = "STEWARD_HOST")]
    host: String,

    /// Port to bind the HTTP server to.
    #[arg(long, default_value = "8080", env = "STEWARD_PORT")]
    port: u16,

    /// WhatsApp Business API access token.
    #[arg(long, env = "WHATSAPP_ACCESS_TOKEN")]
    whatsapp_access_token: Option<String>,

    /// WhatsApp phone number ID.
    #[arg(long, env = "WHATSAPP_PHONE_NUMBER_ID")]
    whatsapp_phone_number_id: Option<String>,

    /// WhatsApp app secret for webhook signature verification.
    #[arg(long, env = "WHATSAPP_APP_SECRET")]
    whatsapp_app_secret: Option<String>,

    /// WhatsApp webhook verification token.
    #[arg(long, env = "WHATSAPP_VERIFY_TOKEN")]
    whatsapp_verify_token: Option<String>,

    /// Telegram Bot API token (from BotFather).
    #[arg(long, env = "TELEGRAM_BOT_TOKEN")]
    telegram_bot_token: Option<String>,

    /// Comma-delimited list of allowed Telegram user IDs.
    #[arg(long, env = "TELEGRAM_ALLOWED_USER_IDS", value_delimiter = ',')]
    telegram_allowed_user_ids: Option<Vec<i64>>,

    /// Telegram Bot API base URL.
    #[arg(
        long,
        default_value = "https://api.telegram.org",
        env = "TELEGRAM_API_BASE_URL"
    )]
    telegram_api_base_url: String,

    /// Log format: "json" for structured JSON, "pretty" for human-readable.
    #[arg(long, default_value = "pretty", env = "STEWARD_LOG_FORMAT")]
    log_format: String,

    /// Comma-separated list of trusted sender IDs that bypass `[EXTERNAL_CONTENT]` tagging.
    ///
    /// Merged with any `trusted_senders` entries already present in `guardrails.yaml`.
    /// Whitespace around each ID is ignored. If unset, no additional senders are trusted.
    #[arg(long, env = "STEWARD_TRUSTED_SENDERS")]
    trusted_senders: Option<String>,

    /// Named API keys for `POST /chat`. Format: `principal1:key1,principal2:key2`.
    ///
    /// When set, takes precedence over `STEWARD_API_KEY`. Each key maps to a
    /// principal name that namespaces its conversation sessions.
    #[arg(long, env = "STEWARD_API_KEYS")]
    api_keys: Option<String>,

    /// Bearer token that callers must supply in `Authorization: Bearer <key>`
    /// when calling `POST /chat`. Legacy single-key form — use `STEWARD_API_KEYS`
    /// for named principals. If `STEWARD_API_KEYS` is set this is ignored.
    #[arg(long, env = "STEWARD_API_KEY")]
    api_key: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    init_tracing(&cli.log_format);

    info!("Starting Steward agent server");

    if let Err(e) = run(cli).await {
        error!(error = %e, "Steward server failed");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // ── 0. Load config (identity, guardrails, permissions) ──────
    let steward_config = ConfigLoader::load_all(&cli.config_dir).map_err(|e| {
        format!(
            "Failed to load config from {}: {e}",
            cli.config_dir.display()
        )
    })?;
    let system_prompt = build_system_prompt(&steward_config.identity);
    // Build the trusted-senders list from two sources:
    //   1. guardrails.yaml `trusted_senders`
    //   2. STEWARD_TRUSTED_SENDERS env var (additional senders; whitespace trimmed)
    let mut trusted_senders = steward_config.guardrails.trusted_senders.clone();

    if let Some(ref raw) = cli.trusted_senders {
        for s in parse_trusted_senders(raw) {
            if !trusted_senders.contains(&s) {
                trusted_senders.push(s);
            }
        }
    }

    info!(
        identity = %steward_config.identity.name,
        trusted_sender_count = trusted_senders.len(),
        "Loaded agent identity and config"
    );

    // ── 1. Database (optional) ──────────────────────────────────
    let db_pool = if let Some(ref url) = cli.database_url {
        info!("Connecting to PostgreSQL...");
        let pool = PgPool::connect(url).await?;
        info!("Running database migrations...");
        audit::run_migrations(&pool).await?;
        Some(pool)
    } else {
        warn!("No DATABASE_URL provided — using in-memory audit logger (data will not persist)");
        None
    };

    // ── 2. Security components ──────────────────────────────────
    let leak_detector = Arc::new(PatternLeakDetector::new());

    let ingress = Arc::new(DefaultIngressSanitizer::new(IngressSanitizerConfig {
        trusted_senders,
        ..IngressSanitizerConfig::default()
    }));

    let egress = Arc::new(
        EgressFilterImpl::new(leak_detector.clone(), EgressFilterConfig::default())
            .map_err(|e| format!("Failed to create egress filter: {e}"))?,
    );

    let audit: Arc<dyn AuditLogger> = if let Some(ref pool) = db_pool {
        Arc::new(PostgresAuditLogger::new(
            pool.clone(),
            leak_detector.clone(),
        ))
    } else {
        Arc::new(InMemoryAuditLogger::with_leak_detector(
            leak_detector.clone(),
        ))
    };

    // ── 3. Permission engine ────────────────────────────────────
    let permissions_path = cli.config_dir.join("permissions.yaml");
    if !permissions_path.exists() {
        return Err(format!(
            "Permissions manifest not found at {}",
            permissions_path.display()
        )
        .into());
    }
    let permissions = Arc::new(
        YamlPermissionEngine::new(&permissions_path)
            .map_err(|e| format!("Failed to load permissions: {e}"))?,
    );

    // ── 4. LLM providers ───────────────────────────────────────
    let primary_llm = Arc::new(AnthropicProvider::new(cli.anthropic_api_key.clone()));
    let guardian_llm_provider = Arc::new(AnthropicProvider::new(cli.anthropic_api_key.clone()));

    // ── 5. Guardian ─────────────────────────────────────────────
    let guardian = Arc::new(GuardianLlm::new(
        guardian_llm_provider,
        GuardianConfig {
            model: cli.guardian_model.clone(),
            ..GuardianConfig::default()
        },
    ));

    // ── 6. Tool registry + built-in tools ───────────────────────
    let tools = Arc::new(ToolRegistryImpl::new());
    tools
        .register_built_in(
            ShellTool::tool_definition(),
            Arc::new(ShellTool::new(ShellConfig::default())),
        )
        .await?;

    // File tools — workspace path from STEWARD_WORKSPACE env var or current dir.
    let workspace = workspace_root();
    tools
        .register_built_in(
            FileReadTool::tool_definition(),
            Arc::new(FileReadTool::new(workspace.clone())),
        )
        .await?;
    tools
        .register_built_in(
            FileWriteTool::tool_definition(),
            Arc::new(FileWriteTool::new(workspace.clone())),
        )
        .await?;
    tools
        .register_built_in(
            FileListTool::tool_definition(),
            Arc::new(FileListTool::new(workspace.clone())),
        )
        .await?;
    tools
        .register_built_in(
            FileEditTool::tool_definition(),
            Arc::new(FileEditTool::new(workspace)),
        )
        .await?;

    // ── 7. Memory (requires DB) ─────────────────────────────────
    let memory: Arc<dyn steward_types::traits::MemorySearch> = if let Some(ref pool) = db_pool {
        let search = steward_memory::search::HybridMemorySearch::new(
            pool.clone(),
            steward_memory::search::SearchConfig::default(),
            None, // No embedding provider yet — FTS only
        );
        search
            .run_migrations()
            .await
            .map_err(|e| format!("Memory migration failed: {e}"))?;
        info!("Memory table and indexes ready");
        Arc::new(search)
    } else {
        Arc::new(NullMemorySearch)
    };

    // ── 8. Channel manager ──────────────────────────────────────
    // Create manager → register adapters → start_listening() → THEN wrap in Arc.
    let mut channel_manager = ChannelManager::new(256);

    let has_whatsapp = cli.whatsapp_access_token.is_some();
    let has_telegram = cli.telegram_bot_token.is_some();

    if has_whatsapp {
        info!("Configuring WhatsApp channel adapter");
        let wa_config = WhatsAppConfig {
            access_token: cli.whatsapp_access_token.clone().unwrap_or_default(),
            phone_number_id: cli.whatsapp_phone_number_id.clone().unwrap_or_default(),
            app_secret: cli.whatsapp_app_secret.clone().unwrap_or_default(),
            verify_token: cli.whatsapp_verify_token.clone().unwrap_or_default(),
            ..WhatsAppConfig::default()
        };
        channel_manager
            .register_channel(
                ChannelType::WhatsApp,
                Arc::new(WhatsAppAdapter::new(wa_config)),
            )
            .await;
    }

    if has_telegram {
        info!("Configuring Telegram channel adapter");
        let tg_config = TelegramConfig {
            bot_token: cli.telegram_bot_token.clone().unwrap_or_default(),
            allowed_user_ids: cli.telegram_allowed_user_ids.clone().unwrap_or_default(),
            api_base_url: cli.telegram_api_base_url.clone(),
            ..TelegramConfig::default()
        };
        channel_manager
            .register_channel(
                ChannelType::Telegram,
                Arc::new(TelegramAdapter::new(tg_config)),
            )
            .await;
    }

    if !has_whatsapp && !has_telegram {
        info!("No channel configured — using console channel for testing");
        channel_manager
            .register_channel(ChannelType::WebChat, Arc::new(ConsoleChannel))
            .await;
    }

    // Start listening on all registered channels BEFORE wrapping in Arc.
    let inbound_rx = channel_manager.start_listening().await?;

    // Now wrap the manager in Arc for shared ownership.
    let channel: Arc<dyn ChannelAdapter> = Arc::new(channel_manager);

    // ── 9. Agent ────────────────────────────────────────────────
    let agent_config = AgentConfig {
        model: cli.model.clone(),
        system_prompt,
        owner: steward_config.identity.owner.clone(),
        known_agents: steward_config.identity.known_agents.clone(),
        ..AgentConfig::default()
    };

    let deps = AgentDeps {
        llm: primary_llm,
        guardian,
        permissions,
        tools,
        egress,
        ingress,
        audit: audit.clone(),
        memory,
        channel: channel.clone(),
        conversation_store: Arc::new(ConversationStore::new()),
    };

    let agent = Arc::new(Agent::new(deps, agent_config));

    // ── 10. Message processing loop ─────────────────────────────
    let agent_loop = Arc::clone(&agent);
    let channel_loop = channel.clone();
    let msg_loop_handle = tokio::spawn(async move {
        let mut rx = inbound_rx;
        while let Some(msg) = rx.recv().await {
            let sender = msg.sender.clone();
            let ch = msg.channel;
            match agent_loop.handle_message(msg).await {
                Ok(text) => {
                    let out = OutboundMessage {
                        recipient: sender.clone(),
                        text,
                        channel: ch,
                        metadata: serde_json::json!({}),
                    };
                    if let Err(e) = channel_loop.send_message(out).await {
                        error!(sender = %sender, error = %e, "failed to send response");
                    }
                }
                Err(e) => {
                    error!(sender = %sender, error = %e, "agent handle_message failed");
                    let out = OutboundMessage {
                        recipient: sender.clone(),
                        text: "Sorry, I'm having trouble processing that right now. Please try again in a moment.".to_string(),
                        channel: ch,
                        metadata: serde_json::json!({}),
                    };
                    let _ = channel_loop.send_message(out).await;
                }
            }
        }
        info!("Message processing loop exited — inbound channel closed");
    });

    // ── 11. HTTP server (webhook endpoints) ─────────────────────
    let app = build_router(AppState {
        agent: Arc::clone(&agent),
        api_keys: build_api_keys_map(cli.api_keys.as_deref(), cli.api_key.as_deref()),
    });

    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port).parse()?;
    info!(%addr, "Starting HTTP server");

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // ── 12. Run server + message loop with graceful shutdown ────
    info!("Steward is ready. Send messages via the configured channel.");

    tokio::select! {
        result = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()) => {
            if let Err(e) = result {
                error!(error = %e, "HTTP server error");
            }
        }
        _ = msg_loop_handle => {
            info!("Message processing loop finished");
        }
    }

    info!("Steward server shut down gracefully");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// HTTP API types and handlers
// ═══════════════════════════════════════════════════════════════

/// Shared state injected into axum route handlers.
#[derive(Clone)]
struct AppState {
    agent: Arc<Agent>,
    /// Map from bearer token → principal name for `POST /chat` auth.
    ///
    /// An empty map means no keys are configured and every request is rejected
    /// with `401 Unauthorized` (fail-closed).
    api_keys: HashMap<String, String>,
}

/// Request body for `POST /chat`.
#[derive(Debug, Deserialize)]
struct ChatRequest {
    /// The message text (required).
    text: String,
    /// Caller-supplied sender identifier. Defaults to `"api"`.
    #[serde(default)]
    sender_id: Option<String>,
    /// Human-readable sender name. Stored in message metadata if provided.
    #[serde(default)]
    sender_name: Option<String>,
    /// Additional caller metadata merged into the inbound message.
    #[serde(default)]
    metadata: serde_json::Value,
    /// Optional: resume a previous session by its server-issued session ID.
    ///
    /// If absent, the server generates a new UUID for this session. Pass the
    /// `session_id` from a prior response to continue that conversation.
    #[serde(default)]
    session_id: Option<String>,
}

/// Response body for `POST /chat`.
#[derive(Debug, Serialize)]
struct ChatResponse {
    /// The agent's reply text.
    response: String,
    /// UUID of the inbound message that was processed.
    message_id: String,
    /// ISO-8601 timestamp of when the response was produced.
    timestamp: String,
    /// Stable session handle. Pass this back in subsequent requests as
    /// `session_id` to continue the same conversation.
    session_id: String,
}

/// Handle `POST /chat` — synchronous HTTP interface to the agent.
///
/// Accepts a JSON body with at least `"text"`, constructs an `InboundMessage`,
/// runs it through the full agent pipeline, and returns the reply.
///
/// # Auth
/// `STEWARD_API_KEYS` (or legacy `STEWARD_API_KEY`) must be set. The caller
/// must include: `Authorization: Bearer <key>`. Requests with a missing,
/// incorrect, or unconfigured key receive `401 Unauthorized`.
///
/// # Sessions
/// Each response includes a `session_id`. Pass it back in subsequent requests
/// to continue the same conversation. If omitted, the server generates a new
/// UUID. Sessions are namespaced per-principal so keys from different callers
/// can never access each other's history.
async fn chat_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ChatRequest>,
) -> impl IntoResponse {
    // ── Auth check (fail-closed) ─────────────────────────────
    if state.api_keys.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "API keys not configured"})),
        )
            .into_response();
    }

    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let principal = match token.and_then(|t| state.api_keys.get(t)) {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Unauthorized"})),
            )
                .into_response();
        }
    };

    // ── Build InboundMessage ─────────────────────────────────
    let msg_id = Uuid::new_v4();

    // Validate metadata: must be a JSON object (or absent).
    let mut meta = req.metadata;
    if meta.is_null() {
        meta = serde_json::json!({});
    } else if !meta.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "metadata must be a JSON object"})),
        )
            .into_response();
    }

    if let Some(name) = req.sender_name {
        meta["sender_name"] = serde_json::Value::String(name);
    }

    // Stamp server-controlled fields that the agent uses for session keying.
    // These override any caller-supplied values to prevent session hijacking.
    //
    // Validate any caller-supplied session_id: must be a valid UUID (≤ 36 chars).
    // This prevents oversized keys from bloating the in-memory session HashMap.
    let session_id = match req.session_id {
        Some(sid) => {
            if sid.len() > 36 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "session_id too long"})),
                )
                    .into_response();
            }
            if uuid::Uuid::parse_str(&sid).is_err() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "session_id must be a valid UUID"})),
                )
                    .into_response();
            }
            sid
        }
        None => Uuid::new_v4().to_string(),
    };
    meta["api_principal"] = serde_json::Value::String(principal.clone());
    meta["api_session_id"] = serde_json::Value::String(session_id.clone());

    let msg = InboundMessage {
        id: msg_id,
        text: req.text,
        channel: ChannelType::WebChat,
        sender: req.sender_id.unwrap_or_else(|| "api".to_string()),
        timestamp: chrono::Utc::now(),
        metadata: meta,
    };

    // ── Call agent ──────────────────────────────────────────
    match state.agent.handle_message(msg).await {
        Ok(response) => (
            StatusCode::OK,
            Json(ChatResponse {
                response,
                message_id: msg_id.to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                session_id,
            }),
        )
            .into_response(),
        Err(e) => {
            error!(error = %e, "chat handler: agent.handle_message failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal server error"})),
            )
                .into_response()
        }
    }
}

/// Build the axum router with health, webhook, and chat endpoints.
fn build_router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/health", axum::routing::get(health_handler))
        .route("/webhook/whatsapp", axum::routing::get(webhook_verify))
        .route("/webhook/whatsapp", axum::routing::post(webhook_receive))
        .route("/chat", axum::routing::post(chat_handler))
        .with_state(state)
}

async fn health_handler() -> &'static str {
    "ok"
}

async fn webhook_verify() -> &'static str {
    // WhatsApp webhook verification is handled by the WhatsApp adapter's axum routes.
    // This is a placeholder — in production, mount the adapter's router directly.
    "webhook verify placeholder"
}

async fn webhook_receive() -> &'static str {
    // WhatsApp webhook receive is handled by the WhatsApp adapter's axum routes.
    "webhook receive placeholder"
}

/// Wait for SIGTERM or SIGINT for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, shutting down..."),
        _ = terminate => info!("Received SIGTERM, shutting down..."),
    }
}

/// Initialize tracing subscriber based on log format.
fn init_tracing(format: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("steward=info,tower_http=info"));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }
}

/// Build the system prompt from the agent's identity config.
///
/// Combines the raw identity markdown with brief tool-use guidance.
/// Falls back gracefully if the identity markdown is empty.
fn build_system_prompt(identity: &IdentityConfig) -> String {
    let identity_md = identity.raw_markdown.trim();
    if identity_md.is_empty() {
        return AgentConfig::default().system_prompt;
    }
    format!(
        "{identity_md}\n\n---\n\nWhen using tools, briefly describe what you're about to do. \
         Work through multi-step tasks one step at a time."
    )
}

/// Build the API keys map from CLI/env inputs.
///
/// If `api_keys_raw` (from `STEWARD_API_KEYS`) is provided it takes precedence.
/// Otherwise, if the legacy `api_key` (from `STEWARD_API_KEY`) is provided, it
/// is treated as a single key with principal `"default"`. Returns an empty map
/// if neither is set (every `/chat` request will be rejected with `401`).
fn build_api_keys_map(
    api_keys_raw: Option<&str>,
    api_key_legacy: Option<&str>,
) -> HashMap<String, String> {
    if let Some(raw) = api_keys_raw {
        parse_api_keys(raw)
    } else if let Some(key) = api_key_legacy {
        let mut map = HashMap::new();
        map.insert(key.to_string(), "default".to_string());
        map
    } else {
        HashMap::new()
    }
}

/// Parse a `STEWARD_API_KEYS` value (`"name1:key1,name2:key2"`) into a
/// token → principal map.
///
/// Entries with a missing colon, empty name, or empty key are silently skipped.
fn parse_api_keys(raw: &str) -> HashMap<String, String> {
    raw.split(',')
        .filter_map(|entry| {
            let (name, key) = entry.trim().split_once(':')?;
            let name = name.trim();
            let key = key.trim();
            if name.is_empty() || key.is_empty() {
                return None;
            }
            Some((key.to_string(), name.to_string()))
        })
        .collect()
}

/// Parse a comma-separated `STEWARD_TRUSTED_SENDERS` value into individual IDs.
///
/// Splits on commas and trims whitespace from each token. Empty tokens are discarded.
///
/// ```
/// # use steward_server::parse_trusted_senders; // hypothetical import
/// let ids = parse_trusted_senders(" 123 , 456 ");
/// assert_eq!(ids, vec!["123", "456"]);
/// ```
fn parse_trusted_senders(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ═══════════════════════════════════════════════════════════════
// Fallback implementations for when no real channel/memory is
// configured.
// ═══════════════════════════════════════════════════════════════

/// No-op memory search that always returns empty results.
struct NullMemorySearch;

#[async_trait]
impl steward_types::traits::MemorySearch for NullMemorySearch {
    async fn search(
        &self,
        _query: &str,
        _limit: usize,
        _scope: Option<&str>,
    ) -> Result<Vec<steward_types::actions::MemorySearchResult>, steward_types::errors::StewardError>
    {
        Ok(vec![])
    }
}

/// Console-based channel adapter for local testing.
///
/// Prints responses to stdout and auto-approves actions.
/// Useful for development without configuring WhatsApp/Telegram.
struct ConsoleChannel;

#[async_trait]
impl steward_types::traits::ChannelAdapter for ConsoleChannel {
    async fn send_message(
        &self,
        message: steward_types::actions::OutboundMessage,
    ) -> Result<(), steward_types::errors::StewardError> {
        println!("[Steward] {}", message.text);
        Ok(())
    }

    async fn start_listening(
        &mut self,
    ) -> Result<mpsc::Receiver<InboundMessage>, steward_types::errors::StewardError> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(rx)
    }

    async fn request_approval(
        &self,
        request: steward_types::actions::ApprovalRequest,
    ) -> Result<steward_types::actions::ApprovalResponse, steward_types::errors::StewardError> {
        info!(
            tool = %request.proposal.tool_name,
            "Console channel: auto-approving action"
        );
        Ok(steward_types::actions::ApprovalResponse {
            approved: true,
            message: Some("Auto-approved in console mode".to_string()),
            timestamp: chrono::Utc::now(),
        })
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use steward_types::actions::*;
    use steward_types::errors::{RateLimitExceeded, StewardError};
    use steward_types::traits::*;
    use tower::ServiceExt;

    // ── Minimal mock implementations ────────────────────────────

    struct MockLlm;
    struct MockGuardian;
    struct MockPermissions;
    struct MockTools;
    struct MockEgress;
    struct MockIngress;
    struct MockAudit;
    struct MockMemory;
    struct MockChannel;

    #[async_trait]
    impl LlmProvider for MockLlm {
        async fn complete(
            &self,
            _req: CompletionRequest,
        ) -> Result<CompletionResponse, StewardError> {
            Ok(CompletionResponse {
                content: "mock response".to_string(),
                tool_calls: vec![],
                model: "mock".to_string(),
                usage: TokenUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                },
            })
        }
        async fn complete_with_tools(
            &self,
            req: CompletionRequest,
            _tools: &[ToolDefinition],
        ) -> Result<CompletionResponse, StewardError> {
            self.complete(req).await
        }
    }

    #[async_trait]
    impl Guardian for MockGuardian {
        async fn review(
            &self,
            _req: &GuardianReviewRequest,
        ) -> Result<GuardianVerdict, StewardError> {
            Ok(GuardianVerdict {
                decision: GuardianDecision::Allow,
                reasoning: "mock".to_string(),
                confidence: 1.0,
                injection_indicators: vec![],
                timestamp: chrono::Utc::now(),
            })
        }
    }

    #[async_trait]
    impl PermissionEngine for MockPermissions {
        fn classify(&self, _action: &ActionProposal) -> PermissionTier {
            PermissionTier::AutoExecute
        }
        async fn check_rate_limit(
            &self,
            _action: &ActionProposal,
        ) -> Result<(), RateLimitExceeded> {
            Ok(())
        }
        async fn reload_manifest(&mut self) -> Result<(), StewardError> {
            Ok(())
        }
    }

    #[async_trait]
    impl ToolRegistry for MockTools {
        async fn list_tools(&self) -> Result<Vec<ToolDefinition>, StewardError> {
            Ok(vec![])
        }
        async fn execute(&self, _call: ToolCall) -> Result<ToolResult, StewardError> {
            Ok(ToolResult {
                success: true,
                output: serde_json::json!({}),
                error: None,
            })
        }
        async fn register(&mut self, _tool: ToolDefinition) -> Result<(), StewardError> {
            Ok(())
        }
    }

    #[async_trait]
    impl EgressFilter for MockEgress {
        async fn filter(&self, _content: &OutboundContent) -> Result<EgressDecision, StewardError> {
            Ok(EgressDecision::Pass)
        }
        fn register_pattern(&mut self, _pattern: SensitivePattern) {}
    }

    #[async_trait]
    impl IngressSanitizer for MockIngress {
        async fn sanitize(&self, input: RawContent) -> Result<SanitizedContent, StewardError> {
            Ok(SanitizedContent {
                text: input.text,
                detections: vec![],
                truncated: false,
                source: input.source,
            })
        }
        async fn detect_injection(
            &self,
            _input: &str,
        ) -> Result<Vec<InjectionDetection>, StewardError> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl AuditLogger for MockAudit {
        async fn log(&self, _event: AuditEvent) -> Result<(), StewardError> {
            Ok(())
        }
        async fn query(&self, _filter: AuditFilter) -> Result<Vec<AuditEvent>, StewardError> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl MemorySearch for MockMemory {
        async fn search(
            &self,
            _query: &str,
            _limit: usize,
            _scope: Option<&str>,
        ) -> Result<Vec<MemorySearchResult>, StewardError> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl ChannelAdapter for MockChannel {
        async fn send_message(&self, _msg: OutboundMessage) -> Result<(), StewardError> {
            Ok(())
        }
        async fn start_listening(
            &mut self,
        ) -> Result<mpsc::Receiver<InboundMessage>, StewardError> {
            let (_tx, rx) = mpsc::channel(1);
            Ok(rx)
        }
        async fn request_approval(
            &self,
            _req: ApprovalRequest,
        ) -> Result<ApprovalResponse, StewardError> {
            Ok(ApprovalResponse {
                approved: true,
                message: None,
                timestamp: chrono::Utc::now(),
            })
        }
    }

    fn make_agent() -> Arc<Agent> {
        Arc::new(Agent::new(
            AgentDeps {
                llm: Arc::new(MockLlm),
                guardian: Arc::new(MockGuardian),
                permissions: Arc::new(MockPermissions),
                tools: Arc::new(MockTools),
                egress: Arc::new(MockEgress),
                ingress: Arc::new(MockIngress),
                audit: Arc::new(MockAudit),
                memory: Arc::new(MockMemory),
                channel: Arc::new(MockChannel),
                conversation_store: Arc::new(ConversationStore::new()),
            },
            AgentConfig::default(),
        ))
    }

    /// Build test state using the legacy single-key path (backward compat helper).
    fn make_test_state(api_key: Option<String>) -> AppState {
        AppState {
            agent: make_agent(),
            api_keys: build_api_keys_map(None, api_key.as_deref()),
        }
    }

    /// Build test state with an explicit multi-key map.
    fn make_test_state_multi(keys: HashMap<String, String>) -> AppState {
        AppState {
            agent: make_agent(),
            api_keys: keys,
        }
    }

    fn chat_post(body: &'static str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/chat")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    fn chat_post_with_token(body: &'static str, token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/chat")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .unwrap()
    }

    fn chat_post_with_token_owned(body: String, token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/chat")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .unwrap()
    }

    async fn parse_response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_chat_401_when_auth_required_and_no_header() {
        let app = build_router(make_test_state(Some("secret".to_string())));
        let resp = app.oneshot(chat_post(r#"{"text":"hello"}"#)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_chat_401_when_wrong_token_supplied() {
        let app = build_router(make_test_state(Some("secret".to_string())));
        let resp = app
            .oneshot(chat_post_with_token(r#"{"text":"hello"}"#, "wrong"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_chat_200_with_correct_token() {
        let app = build_router(make_test_state(Some("secret".to_string())));
        let resp = app
            .oneshot(chat_post_with_token(r#"{"text":"hello"}"#, "secret"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_chat_401_when_no_api_key_configured() {
        // Endpoint is fail-closed: no key configured → every request is rejected.
        let app = build_router(make_test_state(None));
        let resp = app.oneshot(chat_post(r#"{"text":"hello"}"#)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_chat_400_on_missing_text_field() {
        let app = build_router(make_test_state(Some("secret".to_string())));
        let resp = app
            .oneshot(chat_post_with_token(r#"{"sender_id":"rook"}"#, "secret"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_chat_400_on_non_object_metadata_string() {
        let app = build_router(make_test_state(Some("secret".to_string())));
        let resp = app
            .oneshot(chat_post_with_token(
                r#"{"text":"hello","metadata":"bad"}"#,
                "secret",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_chat_400_on_non_object_metadata_array() {
        let app = build_router(make_test_state(Some("secret".to_string())));
        let resp = app
            .oneshot(chat_post_with_token(
                r#"{"text":"hello","metadata":[1,2,3]}"#,
                "secret",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_parse_trusted_senders_trims_whitespace() {
        let result = parse_trusted_senders(" 123 , 456 ");
        assert_eq!(result, vec!["123", "456"]);
    }

    #[test]
    fn test_parse_trusted_senders_no_whitespace() {
        let result = parse_trusted_senders("abc,def");
        assert_eq!(result, vec!["abc", "def"]);
    }

    #[test]
    fn test_parse_trusted_senders_empty_string() {
        let result = parse_trusted_senders("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_trusted_senders_skips_empty_tokens() {
        let result = parse_trusted_senders("123,,456");
        assert_eq!(result, vec!["123", "456"]);
    }

    // ── parse_api_keys tests ────────────────────────────────────

    #[test]
    fn test_parse_api_keys_valid_entries() {
        let map = parse_api_keys("rook:abc123,aniket:def456");
        assert_eq!(map.get("abc123").map(String::as_str), Some("rook"));
        assert_eq!(map.get("def456").map(String::as_str), Some("aniket"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_parse_api_keys_trims_whitespace() {
        let map = parse_api_keys(" rook : abc123 , aniket : def456 ");
        assert_eq!(map.get("abc123").map(String::as_str), Some("rook"));
        assert_eq!(map.get("def456").map(String::as_str), Some("aniket"));
    }

    #[test]
    fn test_parse_api_keys_skips_entries_without_colon() {
        let map = parse_api_keys("nocolon,rook:goodkey");
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("goodkey").map(String::as_str), Some("rook"));
    }

    #[test]
    fn test_parse_api_keys_skips_empty_name_or_key() {
        let map = parse_api_keys(":emptyname,:,validname:validkey");
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("validkey").map(String::as_str), Some("validname"));
    }

    #[test]
    fn test_parse_api_keys_empty_string() {
        let map = parse_api_keys("");
        assert!(map.is_empty());
    }

    // ── build_api_keys_map tests ────────────────────────────────

    #[test]
    fn test_build_api_keys_map_legacy_single_key_uses_default_principal() {
        let map = build_api_keys_map(None, Some("mylegacykey"));
        assert_eq!(map.get("mylegacykey").map(String::as_str), Some("default"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_build_api_keys_map_multi_key_takes_precedence_over_legacy() {
        // STEWARD_API_KEYS overrides STEWARD_API_KEY entirely.
        let map = build_api_keys_map(Some("rook:newkey"), Some("oldlegacykey"));
        assert_eq!(map.get("newkey").map(String::as_str), Some("rook"));
        assert!(
            !map.contains_key("oldlegacykey"),
            "legacy key must be ignored"
        );
    }

    #[test]
    fn test_build_api_keys_map_neither_set_returns_empty() {
        let map = build_api_keys_map(None, None);
        assert!(map.is_empty());
    }

    // ── session_id tests ────────────────────────────────────────

    #[tokio::test]
    async fn test_chat_response_includes_session_id() {
        let app = build_router(make_test_state(Some("secret".to_string())));
        let resp = app
            .oneshot(chat_post_with_token(r#"{"text":"hello"}"#, "secret"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = parse_response_json(resp).await;
        let session_id = json["session_id"]
            .as_str()
            .expect("session_id must be present");
        // Must be a valid UUID
        uuid::Uuid::parse_str(session_id).expect("session_id must be a valid UUID");
    }

    #[tokio::test]
    async fn test_session_id_roundtrip() {
        // Caller passes back the session_id from a previous response;
        // the server echoes the same session_id in the next response.
        let state = make_test_state(Some("secret".to_string()));
        let app1 = build_router(state.clone());
        let app2 = build_router(state);

        // First request: server generates a session_id.
        let resp1 = app1
            .oneshot(chat_post_with_token(r#"{"text":"hello"}"#, "secret"))
            .await
            .unwrap();
        let json1 = parse_response_json(resp1).await;
        let session_id = json1["session_id"].as_str().unwrap().to_string();

        // Second request: caller supplies the session_id.
        let body2 =
            serde_json::json!({"text": "hello again", "session_id": session_id}).to_string();
        let resp2 = app2
            .oneshot(chat_post_with_token_owned(body2, "secret"))
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let json2 = parse_response_json(resp2).await;
        assert_eq!(
            json2["session_id"].as_str().unwrap(),
            session_id,
            "server must echo back the caller-supplied session_id"
        );
    }

    // ── principal / session isolation tests ─────────────────────

    #[tokio::test]
    async fn test_two_api_keys_same_sender_id_get_different_principals() {
        // Two callers sharing the same sender_id but different API keys must
        // get separate sessions because their principals differ.
        let mut keys = HashMap::new();
        keys.insert("key-rook".to_string(), "rook".to_string());
        keys.insert("key-aniket".to_string(), "aniket".to_string());
        let state = make_test_state_multi(keys);

        let app1 = build_router(state.clone());
        let app2 = build_router(state);

        let body = r#"{"text":"hello","sender_id":"shared-sender"}"#;
        let resp1 = app1
            .oneshot(chat_post_with_token(body, "key-rook"))
            .await
            .unwrap();
        let resp2 = app2
            .oneshot(chat_post_with_token(body, "key-aniket"))
            .await
            .unwrap();

        assert_eq!(resp1.status(), StatusCode::OK);
        assert_eq!(resp2.status(), StatusCode::OK);

        let json1 = parse_response_json(resp1).await;
        let json2 = parse_response_json(resp2).await;

        // Both get valid (but different) session UUIDs, confirming isolated namespaces.
        let sid1 = json1["session_id"].as_str().unwrap();
        let sid2 = json2["session_id"].as_str().unwrap();
        uuid::Uuid::parse_str(sid1).unwrap();
        uuid::Uuid::parse_str(sid2).unwrap();
        assert_ne!(
            sid1, sid2,
            "independent new sessions must have different UUIDs"
        );
    }

    #[tokio::test]
    async fn test_caller_cannot_hijack_session_across_principals() {
        // Even if a caller guesses another principal's session_id, the session
        // keys are isolated: api:rook:<sid> ≠ api:aniket:<sid>.
        let mut keys = HashMap::new();
        keys.insert("key-rook".to_string(), "rook".to_string());
        keys.insert("key-aniket".to_string(), "aniket".to_string());
        let state = make_test_state_multi(keys);

        let app1 = build_router(state.clone());
        let app2 = build_router(state);

        // rook creates a session.
        let resp1 = app1
            .oneshot(chat_post_with_token(r#"{"text":"hi"}"#, "key-rook"))
            .await
            .unwrap();
        let json1 = parse_response_json(resp1).await;
        let rook_session_id = json1["session_id"].as_str().unwrap().to_string();

        // aniket attempts to reuse rook's session_id.
        let hijack_body =
            serde_json::json!({"text": "hi", "session_id": rook_session_id}).to_string();
        let resp2 = app2
            .oneshot(chat_post_with_token_owned(hijack_body, "key-aniket"))
            .await
            .unwrap();
        // Request succeeds (auth passes), but aniket's session key is
        // api:aniket:<rook_session_id> — a completely separate history.
        // The server doesn't error because the session_id is just a namespace key.
        assert_eq!(resp2.status(), StatusCode::OK);
        let json2 = parse_response_json(resp2).await;
        // The echoed session_id matches what aniket sent — aniket is working
        // in their own isolated namespace, not rook's.
        assert_eq!(json2["session_id"].as_str().unwrap(), rook_session_id);
    }

    // ── session_id validation tests ──────────────────────────────

    #[tokio::test]
    async fn test_invalid_session_id_returns_400() {
        let app = build_router(make_test_state(Some("secret".to_string())));
        let body = serde_json::json!({"text": "hello", "session_id": "not-a-uuid"}).to_string();
        let resp = app
            .oneshot(chat_post_with_token_owned(body, "secret"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "non-UUID session_id must return 400"
        );
        let json = parse_response_json(resp).await;
        assert!(
            json["error"].as_str().unwrap_or("").contains("UUID"),
            "error must mention UUID: {json:?}"
        );
    }

    #[tokio::test]
    async fn test_oversized_session_id_returns_400() {
        let app = build_router(make_test_state(Some("secret".to_string())));
        // 37+ character string (even if it looks UUID-like) must be rejected
        let oversized = "a".repeat(37);
        let body = serde_json::json!({"text": "hello", "session_id": oversized}).to_string();
        let resp = app
            .oneshot(chat_post_with_token_owned(body, "secret"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "oversized session_id must return 400"
        );
        let json = parse_response_json(resp).await;
        assert!(
            json["error"].as_str().unwrap_or("").contains("too long"),
            "error must mention too long: {json:?}"
        );
    }

    #[tokio::test]
    async fn test_valid_uuid_session_id_accepted() {
        let app = build_router(make_test_state(Some("secret".to_string())));
        let valid_uuid = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({"text": "hello", "session_id": valid_uuid}).to_string();
        let resp = app
            .oneshot(chat_post_with_token_owned(body, "secret"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "valid UUID session_id must be accepted"
        );
    }
}
