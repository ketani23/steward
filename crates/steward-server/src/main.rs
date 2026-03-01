//! Steward server binary.
//!
//! Wires all subsystems together and runs the Steward agent:
//! - CLI args via `clap`
//! - Config loading from disk
//! - Database connection + migrations
//! - Component initialization (security, LLM, guardian, permissions, tools, memory, channels)
//! - Webhook/HTTP server for inbound messages
//! - Graceful shutdown on SIGTERM/SIGINT

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;
use sqlx::PgPool;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use steward_channels::whatsapp::{WhatsAppAdapter, WhatsAppConfig};
use steward_core::agent::{Agent, AgentConfig, AgentDeps};
use steward_core::guardian::{GuardianConfig, GuardianLlm};
use steward_core::llm::anthropic::AnthropicProvider;
use steward_core::permissions::YamlPermissionEngine;
use steward_security::audit::{self, InMemoryAuditLogger, PostgresAuditLogger};
use steward_security::egress::{EgressFilterConfig, EgressFilterImpl};
use steward_security::ingress::{DefaultIngressSanitizer, IngressSanitizerConfig};
use steward_security::leak_detector::PatternLeakDetector;
use steward_tools::registry::ToolRegistryImpl;
use steward_types::actions::InboundMessage;
use steward_types::traits::AuditLogger;

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

    /// Log format: "json" for structured JSON, "pretty" for human-readable.
    #[arg(long, default_value = "pretty", env = "STEWARD_LOG_FORMAT")]
    log_format: String,
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

    let ingress = Arc::new(DefaultIngressSanitizer::new(
        IngressSanitizerConfig::default(),
    ));

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

    // ── 6. Tool registry ────────────────────────────────────────
    let tools = Arc::new(ToolRegistryImpl::new());

    // ── 7. Memory (requires DB) ─────────────────────────────────
    let memory: Arc<dyn steward_types::traits::MemorySearch> = if let Some(ref pool) = db_pool {
        Arc::new(steward_memory::search::HybridMemorySearch::new(
            pool.clone(),
            steward_memory::search::SearchConfig::default(),
            None, // No embedding provider yet — FTS only
        ))
    } else {
        Arc::new(NullMemorySearch)
    };

    // ── 8. Channel adapter ──────────────────────────────────────
    let channel: Arc<dyn steward_types::traits::ChannelAdapter> =
        if cli.whatsapp_access_token.is_some() {
            info!("Configuring WhatsApp channel adapter");
            let wa_config = WhatsAppConfig {
                access_token: cli.whatsapp_access_token.clone().unwrap_or_default(),
                phone_number_id: cli.whatsapp_phone_number_id.clone().unwrap_or_default(),
                app_secret: cli.whatsapp_app_secret.clone().unwrap_or_default(),
                verify_token: cli.whatsapp_verify_token.clone().unwrap_or_default(),
                ..WhatsAppConfig::default()
            };
            Arc::new(WhatsAppAdapter::new(wa_config))
        } else {
            info!("No channel configured — using console channel for testing");
            Arc::new(ConsoleChannel)
        };

    // ── 9. Agent ────────────────────────────────────────────────
    let agent_config = AgentConfig {
        model: cli.model.clone(),
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
    };

    let _agent = Arc::new(Agent::new(deps, agent_config));

    // ── 10. HTTP server (webhook endpoints) ─────────────────────
    let app = build_router();

    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port).parse()?;
    info!(%addr, "Starting HTTP server");

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // ── 11. Run server with graceful shutdown ───────────────────
    info!("Steward is ready. Send messages via the configured channel.");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Steward server shut down gracefully");
    Ok(())
}

/// Build the axum router with health and webhook endpoints.
fn build_router() -> axum::Router {
    axum::Router::new()
        .route("/health", axum::routing::get(health_handler))
        .route("/webhook/whatsapp", axum::routing::get(webhook_verify))
        .route("/webhook/whatsapp", axum::routing::post(webhook_receive))
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
