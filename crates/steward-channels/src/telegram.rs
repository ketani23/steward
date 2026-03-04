//! Telegram Bot API channel adapter.
//!
//! Handles Telegram communication using the Bot API directly via `reqwest`:
//! - Long-polling via `getUpdates` for inbound messages
//! - Outbound message sending via `sendMessage`
//! - Inline keyboard buttons for human-in-the-loop approval flows
//! - Callback query handling and acknowledgement (`answerCallbackQuery`)
//! - User allowlist filtering — messages from unauthorized users are ignored
//! - Sliding-window rate limiting on outbound messages
//!
//! See `docs/architecture.md` section 10 for channel requirements.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex, RwLock};
use uuid::Uuid;

use steward_types::actions::*;
use steward_types::errors::StewardError;
use steward_types::traits::ChannelAdapter;

// ============================================================
// Configuration
// ============================================================

/// Configuration for the Telegram Bot API adapter.
#[derive(Debug, Clone)]
pub struct TelegramConfig {
    /// Bot token from BotFather (e.g., `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`).
    pub bot_token: String,
    /// Allowlist of Telegram user IDs that may interact with the bot.
    /// Messages from users not in this list are silently dropped.
    /// An empty list means *no users* are allowed (deny-all by default).
    pub allowed_user_ids: Vec<i64>,
    /// Base URL for the Telegram Bot API (default: `https://api.telegram.org`).
    pub api_base_url: String,
    /// Timeout in seconds for the `getUpdates` long-poll request.
    pub polling_timeout_secs: u64,
    /// Default timeout in seconds when waiting for an approval response.
    pub approval_timeout_secs: u64,
    /// Maximum outbound messages per minute (rate limiting).
    pub rate_limit_per_minute: u32,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            bot_token: String::new(),
            allowed_user_ids: Vec::new(),
            api_base_url: "https://api.telegram.org".to_string(),
            polling_timeout_secs: 30,
            approval_timeout_secs: 300,
            rate_limit_per_minute: 30,
        }
    }
}

impl TelegramConfig {
    /// Build the full Bot API URL for a given method.
    fn api_url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.api_base_url, self.bot_token, method)
    }
}

// ============================================================
// Telegram API Types (subset used by this adapter)
// ============================================================

/// Wrapper returned by every Telegram Bot API method.
#[derive(Debug, Deserialize)]
struct TelegramResponse<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
}

/// A Telegram Update object (subset of fields we care about).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Update {
    /// Unique update identifier.
    pub update_id: i64,
    /// New incoming message, if any.
    pub message: Option<TgMessage>,
    /// New incoming callback query (inline keyboard button press), if any.
    pub callback_query: Option<CallbackQuery>,
}

/// A Telegram Message object (subset).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TgMessage {
    /// Unique message identifier within this chat.
    pub message_id: i64,
    /// Sender of the message (empty for messages sent to channels).
    pub from: Option<TgUser>,
    /// Chat the message belongs to.
    pub chat: TgChat,
    /// Date the message was sent (Unix timestamp).
    pub date: i64,
    /// The text of the message, if it is a text message.
    pub text: Option<String>,
}

/// A Telegram User object (subset).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TgUser {
    /// Unique Telegram user identifier.
    pub id: i64,
    /// User's first name.
    pub first_name: String,
    /// User's last name.
    pub last_name: Option<String>,
    /// User's username (without leading `@`).
    pub username: Option<String>,
}

impl TgUser {
    /// Produce a human-readable display name.
    pub fn display_name(&self) -> String {
        match (&self.username, &self.last_name) {
            (Some(username), _) => format!("@{username}"),
            (None, Some(last)) => format!("{} {last}", self.first_name),
            (None, None) => self.first_name.clone(),
        }
    }
}

/// A Telegram Chat object (subset).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TgChat {
    /// Unique chat identifier.
    pub id: i64,
    /// Type of chat: `"private"`, `"group"`, `"supergroup"`, or `"channel"`.
    #[serde(rename = "type")]
    pub chat_type: String,
}

/// A Telegram CallbackQuery (inline keyboard button press).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CallbackQuery {
    /// Unique identifier for this query.
    pub id: String,
    /// Sender of the callback query.
    pub from: TgUser,
    /// Data associated with the callback button (set via `callback_data`).
    pub data: Option<String>,
    /// Message that originated the query (the message with the inline keyboard).
    pub message: Option<TgMessage>,
}

// ============================================================
// Rate Limiter
// ============================================================

/// Simple sliding-window rate limiter for outbound messages.
struct RateLimiter {
    /// Timestamps of recent sends (within the window).
    timestamps: Vec<std::time::Instant>,
    /// Maximum messages allowed per minute.
    max_per_minute: u32,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            timestamps: Vec::new(),
            max_per_minute,
        }
    }

    /// Check if a send is allowed. If so, record it. If not, return an error.
    fn check_and_record(&mut self) -> Result<(), StewardError> {
        let now = std::time::Instant::now();
        let window = Duration::from_secs(60);
        self.timestamps.retain(|t| now.duration_since(*t) < window);

        if self.timestamps.len() >= self.max_per_minute as usize {
            return Err(StewardError::RateLimitExceeded(format!(
                "Telegram rate limit exceeded: {} messages/minute",
                self.max_per_minute
            )));
        }
        self.timestamps.push(now);
        Ok(())
    }
}

// ============================================================
// Telegram Adapter
// ============================================================

/// Telegram Bot API adapter.
///
/// Implements the [`ChannelAdapter`] trait, providing:
/// - Inbound message reception via `getUpdates` long-polling
/// - Outbound message sending via `sendMessage`
/// - Human-in-the-loop approval flows via inline keyboard buttons
pub struct TelegramAdapter {
    /// HTTP client for Bot API calls.
    client: reqwest::Client,
    /// Configuration.
    config: Arc<TelegramConfig>,
    /// Receiver end — taken once by `start_listening()`.
    inbound_rx: Mutex<Option<mpsc::Receiver<InboundMessage>>>,
    /// Sender for inbound messages (shared with the polling task).
    inbound_tx: Arc<mpsc::Sender<InboundMessage>>,
    /// Pending approval callbacks keyed by approval ID.
    /// When a callback query with matching data arrives, the pending future is resolved.
    pending_approvals: Arc<RwLock<HashMap<String, mpsc::Sender<bool>>>>,
    /// Rate limiter for outbound messages.
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

#[allow(dead_code)]
impl TelegramAdapter {
    /// Create a new Telegram adapter with the given configuration.
    pub fn new(config: TelegramConfig) -> Self {
        let (tx, rx) = mpsc::channel(256);
        let rate_limiter = RateLimiter::new(config.rate_limit_per_minute);

        Self {
            client: reqwest::Client::new(),
            config: Arc::new(config),
            inbound_rx: Mutex::new(Some(rx)),
            inbound_tx: Arc::new(tx),
            pending_approvals: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
        }
    }

    /// Create a new Telegram adapter with a custom `reqwest::Client`.
    ///
    /// Useful for testing (e.g., pointing at a mock server).
    pub fn with_client(config: TelegramConfig, client: reqwest::Client) -> Self {
        let (tx, rx) = mpsc::channel(256);
        let rate_limiter = RateLimiter::new(config.rate_limit_per_minute);

        Self {
            client,
            config: Arc::new(config),
            inbound_rx: Mutex::new(Some(rx)),
            inbound_tx: Arc::new(tx),
            pending_approvals: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
        }
    }

    /// Check whether a user ID is in the allowlist.
    fn is_user_allowed(&self, user_id: i64) -> bool {
        self.config.allowed_user_ids.contains(&user_id)
    }

    /// Call `sendMessage` on the Telegram Bot API.
    async fn send_text(&self, chat_id: &str, text: &str) -> Result<(), StewardError> {
        self.rate_limiter.lock().await.check_and_record()?;

        let body = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
        });

        let resp = self
            .client
            .post(self.config.api_url("sendMessage"))
            .json(&body)
            .send()
            .await
            .map_err(|e| StewardError::Channel(format!("Telegram sendMessage failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(StewardError::Channel(format!(
                "Telegram API error {status}: {body}"
            )));
        }

        Ok(())
    }

    /// Send a message with an inline keyboard (Approve / Reject buttons).
    async fn send_inline_keyboard(
        &self,
        chat_id: &str,
        text: &str,
        approve_data: &str,
        reject_data: &str,
    ) -> Result<(), StewardError> {
        self.rate_limiter.lock().await.check_and_record()?;

        let body = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "reply_markup": {
                "inline_keyboard": [[
                    { "text": "Approve", "callback_data": approve_data },
                    { "text": "Reject", "callback_data": reject_data },
                ]]
            }
        });

        let resp = self
            .client
            .post(self.config.api_url("sendMessage"))
            .json(&body)
            .send()
            .await
            .map_err(|e| StewardError::Channel(format!("Telegram sendMessage failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(StewardError::Channel(format!(
                "Telegram API error {status}: {body}"
            )));
        }

        Ok(())
    }

    /// Spawn a background task to acknowledge a button press via `answerCallbackQuery`.
    ///
    /// Fire-and-forget with a 5-second timeout so the approval decision path is
    /// never blocked waiting for Telegram's ack endpoint.
    fn spawn_answer_callback_query(&self, callback_query_id: String) {
        let client = self.client.clone();
        let url = self.config.api_url("answerCallbackQuery");
        tokio::spawn(async move {
            let body = serde_json::json!({
                "callback_query_id": callback_query_id,
            });

            let result =
                tokio::time::timeout(Duration::from_secs(5), client.post(url).json(&body).send())
                    .await;

            match result {
                Err(_elapsed) => {
                    tracing::warn!(
                        callback_query_id = %callback_query_id,
                        "answerCallbackQuery timed out after 5s"
                    );
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        callback_query_id = %callback_query_id,
                        "answerCallbackQuery request failed: {e}"
                    );
                }
                Ok(Ok(resp)) if !resp.status().is_success() => {
                    let status = resp.status();
                    tracing::warn!(
                        callback_query_id = %callback_query_id,
                        "answerCallbackQuery returned non-success status {status}"
                    );
                }
                Ok(Ok(_)) => {}
            }
        });
    }

    /// Process a single update: dispatch to the inbound channel or resolve a pending approval.
    async fn process_update(&self, update: &Update) {
        // Handle callback queries (approval button presses).
        if let Some(ref cq) = update.callback_query {
            self.handle_callback_query(cq).await;
            return;
        }

        // Handle regular messages.
        if let Some(ref msg) = update.message {
            self.handle_message(msg).await;
        }
    }

    /// Handle a regular text message from a user.
    async fn handle_message(&self, msg: &TgMessage) {
        // Check user allowlist.
        let user = match &msg.from {
            Some(u) => u,
            None => {
                tracing::debug!("Ignoring message without a sender");
                return;
            }
        };

        if !self.is_user_allowed(user.id) {
            tracing::debug!(user_id = user.id, "Ignoring message from unauthorized user");
            return;
        }

        let text = match &msg.text {
            Some(t) => t.clone(),
            None => {
                tracing::debug!("Ignoring non-text message from user {}", user.id);
                return;
            }
        };

        let inbound = InboundMessage {
            id: Uuid::new_v4(),
            text,
            channel: ChannelType::Telegram,
            sender: user.display_name(),
            timestamp: Utc::now(),
            metadata: serde_json::json!({
                "telegram_message_id": msg.message_id,
                "telegram_user_id": user.id,
                "telegram_chat_id": msg.chat.id,
                "chat_type": msg.chat.chat_type,
            }),
        };

        if let Err(e) = self.inbound_tx.send(inbound).await {
            tracing::error!("Failed to forward inbound Telegram message: {e}");
        }
    }

    /// Handle a callback query (inline keyboard button press).
    async fn handle_callback_query(&self, cq: &CallbackQuery) {
        // Check user allowlist.
        if !self.is_user_allowed(cq.from.id) {
            tracing::debug!(
                user_id = cq.from.id,
                "Ignoring callback query from unauthorized user"
            );
            return;
        }

        // Acknowledge the callback query in a background task so the loading
        // spinner is dismissed without blocking the approval decision path.
        self.spawn_answer_callback_query(cq.id.clone());

        let data = match &cq.data {
            Some(d) => d.as_str(),
            None => return,
        };

        // Extract approval ID from callback data: "approve_{id}" or "reject_{id}".
        let (approved, approval_id) = if let Some(id) = data.strip_prefix("approve_") {
            (true, id)
        } else if let Some(id) = data.strip_prefix("reject_") {
            (false, id)
        } else {
            tracing::debug!("Ignoring callback query with unrecognized data: {data}");
            return;
        };

        let approvals = self.pending_approvals.read().await;
        if let Some(tx) = approvals.get(approval_id) {
            if let Err(e) = tx.send(approved).await {
                tracing::error!("Failed to send approval response: {e}");
            }
        } else {
            tracing::debug!("No pending approval found for ID: {approval_id}");
        }
    }
}

#[async_trait]
impl ChannelAdapter for TelegramAdapter {
    /// Send a message through Telegram.
    ///
    /// The `recipient` field of [`OutboundMessage`] is interpreted as the Telegram chat ID.
    async fn send_message(&self, message: OutboundMessage) -> Result<(), StewardError> {
        self.send_text(&message.recipient, &message.text).await
    }

    /// Start listening for inbound messages via long-polling.
    ///
    /// Spawns a background tokio task that repeatedly calls `getUpdates`.
    /// Returns an [`mpsc::Receiver`] that yields parsed [`InboundMessage`]s.
    /// Can only be called once — subsequent calls return an error.
    async fn start_listening(&mut self) -> Result<mpsc::Receiver<InboundMessage>, StewardError> {
        let rx =
            self.inbound_rx.lock().await.take().ok_or_else(|| {
                StewardError::Channel("start_listening already called".to_string())
            })?;

        // Clone the values the polling task needs.
        let client = self.client.clone();
        let config = Arc::clone(&self.config);
        let inbound_tx = Arc::clone(&self.inbound_tx);
        let pending_approvals = Arc::clone(&self.pending_approvals);
        let allowed_user_ids = config.allowed_user_ids.clone();

        // Spawn the long-polling loop.
        tokio::spawn(async move {
            let adapter_for_processing = TelegramPollingWorker {
                client,
                config,
                inbound_tx,
                pending_approvals,
                allowed_user_ids,
            };
            adapter_for_processing.poll_loop().await;
        });

        Ok(rx)
    }

    /// Request human approval for an action.
    ///
    /// Sends a message with Approve/Reject inline buttons and waits for the
    /// user's callback query response with a configurable timeout.
    async fn request_approval(
        &self,
        request: ApprovalRequest,
    ) -> Result<ApprovalResponse, StewardError> {
        let approval_id = Uuid::new_v4().to_string();
        let approve_data = format!("approve_{approval_id}");
        let reject_data = format!("reject_{approval_id}");

        // Format the approval message.
        let body_text = crate::confirmation::format_approval_message(&request);

        // Register a channel for the callback response.
        let (tx, mut rx) = mpsc::channel(1);
        self.pending_approvals
            .write()
            .await
            .insert(approval_id.clone(), tx);

        // Determine the chat ID to send to. We look in the proposal metadata or
        // fall back to the first allowed user ID.
        let chat_id = request
            .proposal
            .parameters
            .get("telegram_chat_id")
            .and_then(|v| v.as_i64())
            .or_else(|| self.config.allowed_user_ids.first().copied())
            .map(|id| id.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Send the inline keyboard.
        self.send_inline_keyboard(&chat_id, &body_text, &approve_data, &reject_data)
            .await?;

        // Wait for the callback with timeout.
        let timeout_secs = if request.timeout_secs > 0 {
            request.timeout_secs
        } else {
            self.config.approval_timeout_secs
        };

        let result = tokio::time::timeout(Duration::from_secs(timeout_secs), rx.recv()).await;

        // Clean up the pending approval entry.
        self.pending_approvals.write().await.remove(&approval_id);

        match result {
            Ok(Some(approved)) => Ok(ApprovalResponse {
                approved,
                message: if approved {
                    Some("User approved via Telegram".to_string())
                } else {
                    Some("User rejected via Telegram".to_string())
                },
                timestamp: Utc::now(),
            }),
            Ok(None) => Err(StewardError::Channel(
                "Approval channel closed unexpectedly".to_string(),
            )),
            Err(_) => Err(StewardError::Timeout(format!(
                "Approval timed out after {timeout_secs}s"
            ))),
        }
    }
}

// ============================================================
// Polling Worker
// ============================================================

/// Internal worker that runs the `getUpdates` long-polling loop in a spawned task.
///
/// This is separate from `TelegramAdapter` because the adapter itself cannot be
/// moved into the spawned task (it is borrowed by the caller). The worker holds
/// only the cloned/shared fields it needs.
struct TelegramPollingWorker {
    client: reqwest::Client,
    config: Arc<TelegramConfig>,
    inbound_tx: Arc<mpsc::Sender<InboundMessage>>,
    pending_approvals: Arc<RwLock<HashMap<String, mpsc::Sender<bool>>>>,
    allowed_user_ids: Vec<i64>,
}

impl TelegramPollingWorker {
    /// Run the long-polling loop until the inbound channel is closed.
    async fn poll_loop(&self) {
        let mut offset: i64 = 0;

        loop {
            // If the receiver has been dropped, stop polling.
            if self.inbound_tx.is_closed() {
                tracing::info!("Inbound channel closed, stopping Telegram polling");
                break;
            }

            match self.get_updates(offset).await {
                Ok(updates) => {
                    for update in &updates {
                        // Advance the offset past this update so we don't receive it again.
                        if update.update_id >= offset {
                            offset = update.update_id + 1;
                        }
                        self.process_update(update).await;
                    }
                }
                Err(e) => {
                    tracing::error!("getUpdates error: {e}");
                    // Back off before retrying to avoid a tight error loop.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Call `getUpdates` on the Telegram Bot API.
    async fn get_updates(&self, offset: i64) -> Result<Vec<Update>, StewardError> {
        let body = serde_json::json!({
            "offset": offset,
            "timeout": self.config.polling_timeout_secs,
            "allowed_updates": ["message", "callback_query"],
        });

        let resp = self
            .client
            .post(self.config.api_url("getUpdates"))
            .json(&body)
            .timeout(Duration::from_secs(self.config.polling_timeout_secs + 10))
            .send()
            .await
            .map_err(|e| StewardError::Channel(format!("Telegram getUpdates failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(StewardError::Channel(format!(
                "Telegram getUpdates error {status}: {body}"
            )));
        }

        let api_resp: TelegramResponse<Vec<Update>> = resp.json().await.map_err(|e| {
            StewardError::Channel(format!("Failed to parse getUpdates response: {e}"))
        })?;

        if !api_resp.ok {
            return Err(StewardError::Channel(format!(
                "Telegram API returned ok=false: {}",
                api_resp.description.unwrap_or_default()
            )));
        }

        Ok(api_resp.result.unwrap_or_default())
    }

    /// Process a single update.
    async fn process_update(&self, update: &Update) {
        if let Some(ref cq) = update.callback_query {
            self.handle_callback_query(cq).await;
            return;
        }

        if let Some(ref msg) = update.message {
            self.handle_message(msg).await;
        }
    }

    /// Handle a regular text message.
    async fn handle_message(&self, msg: &TgMessage) {
        let user = match &msg.from {
            Some(u) => u,
            None => return,
        };

        if !self.allowed_user_ids.contains(&user.id) {
            tracing::debug!(user_id = user.id, "Ignoring message from unauthorized user");
            return;
        }

        let text = match &msg.text {
            Some(t) => t.clone(),
            None => return,
        };

        let inbound = InboundMessage {
            id: Uuid::new_v4(),
            text,
            channel: ChannelType::Telegram,
            sender: user.display_name(),
            timestamp: Utc::now(),
            metadata: serde_json::json!({
                "telegram_message_id": msg.message_id,
                "telegram_user_id": user.id,
                "telegram_chat_id": msg.chat.id,
                "chat_type": msg.chat.chat_type,
            }),
        };

        if let Err(e) = self.inbound_tx.send(inbound).await {
            tracing::error!("Failed to forward inbound Telegram message: {e}");
        }
    }

    /// Acknowledge a callback query to dismiss the loading spinner in Telegram.
    ///
    /// Spawned as a background task so the approval decision is delivered
    /// immediately regardless of whether the ack HTTP call succeeds.
    /// A 5-second timeout prevents the task from hanging indefinitely.
    fn spawn_answer_callback_query(&self, callback_query_id: String) {
        let client = self.client.clone();
        let url = self.config.api_url("answerCallbackQuery");
        tokio::spawn(async move {
            let body = serde_json::json!({
                "callback_query_id": callback_query_id,
            });

            let result =
                tokio::time::timeout(Duration::from_secs(5), client.post(url).json(&body).send())
                    .await;

            match result {
                Err(_elapsed) => {
                    tracing::warn!(
                        callback_query_id = %callback_query_id,
                        "answerCallbackQuery timed out after 5s"
                    );
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        callback_query_id = %callback_query_id,
                        "answerCallbackQuery request failed: {e}"
                    );
                }
                Ok(Ok(resp)) if !resp.status().is_success() => {
                    let status = resp.status();
                    tracing::warn!(
                        callback_query_id = %callback_query_id,
                        "answerCallbackQuery returned non-success status {status}"
                    );
                }
                Ok(Ok(_)) => {}
            }
        });
    }

    /// Handle a callback query (inline keyboard button press).
    async fn handle_callback_query(&self, cq: &CallbackQuery) {
        if !self.allowed_user_ids.contains(&cq.from.id) {
            tracing::debug!(
                user_id = cq.from.id,
                "Ignoring callback from unauthorized user"
            );
            return;
        }

        // Acknowledge the callback query in a background task so the loading
        // spinner is dismissed without blocking the approval decision path.
        self.spawn_answer_callback_query(cq.id.clone());

        let data = match &cq.data {
            Some(d) => d.as_str(),
            None => {
                tracing::debug!(callback_id = %cq.id, "Callback query has no data");
                return;
            }
        };

        let (approved, approval_id) = if let Some(id) = data.strip_prefix("approve_") {
            (true, id)
        } else if let Some(id) = data.strip_prefix("reject_") {
            (false, id)
        } else {
            tracing::debug!(data = %data, "Ignoring callback query with unrecognized data format");
            return;
        };

        tracing::info!(
            approval_id = %approval_id,
            approved = %approved,
            user_id = %cq.from.id,
            "Received approval callback"
        );

        let approvals = self.pending_approvals.read().await;
        if let Some(tx) = approvals.get(approval_id) {
            if let Err(e) = tx.send(approved).await {
                tracing::error!(approval_id = %approval_id, "Failed to deliver approval response: {e}");
            }
        } else {
            tracing::warn!(
                approval_id = %approval_id,
                "No pending approval found — it may have already timed out or been resolved"
            );
        }
    }
}

// ============================================================
// Public helpers for parsing (used by tests and potentially externally)
// ============================================================

/// Parse a Telegram [`TgMessage`] into an [`InboundMessage`].
///
/// Returns `None` if the message has no sender, no text, or the sender is not
/// in the allowlist.
pub fn parse_telegram_message(msg: &TgMessage, allowed_user_ids: &[i64]) -> Option<InboundMessage> {
    let user = msg.from.as_ref()?;

    if !allowed_user_ids.contains(&user.id) {
        return None;
    }

    let text = msg.text.as_ref()?;

    Some(InboundMessage {
        id: Uuid::new_v4(),
        text: text.clone(),
        channel: ChannelType::Telegram,
        sender: user.display_name(),
        timestamp: Utc::now(),
        metadata: serde_json::json!({
            "telegram_message_id": msg.message_id,
            "telegram_user_id": user.id,
            "telegram_chat_id": msg.chat.id,
            "chat_type": msg.chat.chat_type,
        }),
    })
}

/// Extract the approval decision from a [`CallbackQuery`].
///
/// Returns `Some((approval_id, approved))` if the data matches the
/// `approve_{id}` / `reject_{id}` convention, or `None` otherwise.
pub fn parse_callback_query(cq: &CallbackQuery) -> Option<(String, bool)> {
    let data = cq.data.as_deref()?;

    if let Some(id) = data.strip_prefix("approve_") {
        Some((id.to_string(), true))
    } else {
        data.strip_prefix("reject_")
            .map(|id| (id.to_string(), false))
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Test Helpers ==========

    fn test_config() -> TelegramConfig {
        TelegramConfig {
            bot_token: "123456:ABC-DEF".to_string(),
            allowed_user_ids: vec![100, 200, 300],
            api_base_url: "https://api.telegram.org".to_string(),
            polling_timeout_secs: 5,
            approval_timeout_secs: 10,
            rate_limit_per_minute: 5,
        }
    }

    fn make_tg_user(id: i64, first_name: &str, username: Option<&str>) -> TgUser {
        TgUser {
            id,
            first_name: first_name.to_string(),
            last_name: None,
            username: username.map(|s| s.to_string()),
        }
    }

    fn make_tg_message(
        message_id: i64,
        user: Option<TgUser>,
        chat_id: i64,
        text: Option<&str>,
    ) -> TgMessage {
        TgMessage {
            message_id,
            from: user,
            chat: TgChat {
                id: chat_id,
                chat_type: "private".to_string(),
            },
            date: 1700000000,
            text: text.map(|s| s.to_string()),
        }
    }

    fn make_callback_query(
        id: &str,
        user: TgUser,
        data: Option<&str>,
        message: Option<TgMessage>,
    ) -> CallbackQuery {
        CallbackQuery {
            id: id.to_string(),
            from: user,
            data: data.map(|s| s.to_string()),
            message,
        }
    }

    fn sample_approval_request(chat_id: i64) -> ApprovalRequest {
        ApprovalRequest {
            proposal: ActionProposal {
                id: Uuid::new_v4(),
                tool_name: "email.send".to_string(),
                parameters: serde_json::json!({"telegram_chat_id": chat_id}),
                reasoning: "User asked to send an email".to_string(),
                user_message_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            },
            guardian_verdict: GuardianVerdict {
                decision: GuardianDecision::EscalateToHuman,
                reasoning: "Email send requires approval".to_string(),
                confidence: 0.9,
                injection_indicators: vec![],
                timestamp: Utc::now(),
            },
            permission_tier: PermissionTier::HumanApproval,
            channel: ChannelType::Telegram,
            timeout_secs: 1,
        }
    }

    // ========== TgUser Display Name Tests ==========

    #[test]
    fn test_user_display_name_with_username() {
        let user = make_tg_user(1, "Alice", Some("alice_bot"));
        assert_eq!(user.display_name(), "@alice_bot");
    }

    #[test]
    fn test_user_display_name_with_last_name() {
        let mut user = make_tg_user(1, "Alice", None);
        user.last_name = Some("Smith".to_string());
        assert_eq!(user.display_name(), "Alice Smith");
    }

    #[test]
    fn test_user_display_name_first_only() {
        let user = make_tg_user(1, "Alice", None);
        assert_eq!(user.display_name(), "Alice");
    }

    // ========== Message Parsing Tests ==========

    #[test]
    fn test_parse_text_message_allowed_user() {
        let user = make_tg_user(100, "Alice", Some("alice"));
        let msg = make_tg_message(1, Some(user), 100, Some("Hello, Steward!"));
        let allowed = vec![100, 200];

        let result = parse_telegram_message(&msg, &allowed).unwrap();
        assert_eq!(result.text, "Hello, Steward!");
        assert_eq!(result.sender, "@alice");
        assert_eq!(result.channel, ChannelType::Telegram);
        assert_eq!(result.metadata["telegram_user_id"], 100);
        assert_eq!(result.metadata["telegram_chat_id"], 100);
        assert_eq!(result.metadata["telegram_message_id"], 1);
    }

    #[test]
    fn test_parse_message_unauthorized_user() {
        let user = make_tg_user(999, "Hacker", None);
        let msg = make_tg_message(1, Some(user), 999, Some("I should be filtered"));
        let allowed = vec![100, 200];

        let result = parse_telegram_message(&msg, &allowed);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_message_no_sender() {
        let msg = make_tg_message(1, None, 100, Some("Ghost message"));
        let allowed = vec![100];

        let result = parse_telegram_message(&msg, &allowed);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_message_no_text() {
        let user = make_tg_user(100, "Alice", None);
        let msg = make_tg_message(1, Some(user), 100, None);
        let allowed = vec![100];

        let result = parse_telegram_message(&msg, &allowed);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_message_empty_allowlist() {
        let user = make_tg_user(100, "Alice", None);
        let msg = make_tg_message(1, Some(user), 100, Some("Hello"));
        let allowed: Vec<i64> = vec![];

        let result = parse_telegram_message(&msg, &allowed);
        assert!(result.is_none());
    }

    // ========== Callback Query Parsing Tests ==========

    #[test]
    fn test_parse_callback_query_approve() {
        let user = make_tg_user(100, "Alice", None);
        let cq = make_callback_query("cq1", user, Some("approve_abc123"), None);

        let (id, approved) = parse_callback_query(&cq).unwrap();
        assert_eq!(id, "abc123");
        assert!(approved);
    }

    #[test]
    fn test_parse_callback_query_reject() {
        let user = make_tg_user(100, "Alice", None);
        let cq = make_callback_query("cq2", user, Some("reject_abc123"), None);

        let (id, approved) = parse_callback_query(&cq).unwrap();
        assert_eq!(id, "abc123");
        assert!(!approved);
    }

    #[test]
    fn test_parse_callback_query_unknown_data() {
        let user = make_tg_user(100, "Alice", None);
        let cq = make_callback_query("cq3", user, Some("unknown_data"), None);

        assert!(parse_callback_query(&cq).is_none());
    }

    #[test]
    fn test_parse_callback_query_no_data() {
        let user = make_tg_user(100, "Alice", None);
        let cq = make_callback_query("cq4", user, None, None);

        assert!(parse_callback_query(&cq).is_none());
    }

    // ========== Update Deserialization Tests ==========

    #[test]
    fn test_deserialize_text_message_update() {
        let json = serde_json::json!({
            "update_id": 100001,
            "message": {
                "message_id": 42,
                "from": {
                    "id": 100,
                    "first_name": "Alice",
                    "username": "alice"
                },
                "chat": {
                    "id": 100,
                    "type": "private"
                },
                "date": 1700000000,
                "text": "Hello bot!"
            }
        });

        let update: Update = serde_json::from_value(json).unwrap();
        assert_eq!(update.update_id, 100001);

        let msg = update.message.unwrap();
        assert_eq!(msg.message_id, 42);
        assert_eq!(msg.text.unwrap(), "Hello bot!");
        assert_eq!(msg.from.unwrap().id, 100);
        assert!(update.callback_query.is_none());
    }

    #[test]
    fn test_deserialize_callback_query_update() {
        let json = serde_json::json!({
            "update_id": 100002,
            "callback_query": {
                "id": "cq_12345",
                "from": {
                    "id": 200,
                    "first_name": "Bob"
                },
                "data": "approve_my_approval_id",
                "message": {
                    "message_id": 99,
                    "from": {
                        "id": 111,
                        "first_name": "StewardBot"
                    },
                    "chat": {
                        "id": 200,
                        "type": "private"
                    },
                    "date": 1700000001,
                    "text": "ACTION APPROVAL REQUEST..."
                }
            }
        });

        let update: Update = serde_json::from_value(json).unwrap();
        assert_eq!(update.update_id, 100002);
        assert!(update.message.is_none());

        let cq = update.callback_query.unwrap();
        assert_eq!(cq.id, "cq_12345");
        assert_eq!(cq.from.id, 200);
        assert_eq!(cq.data.unwrap(), "approve_my_approval_id");
    }

    #[test]
    fn test_deserialize_api_response_with_updates() {
        let json = serde_json::json!({
            "ok": true,
            "result": [
                {
                    "update_id": 1,
                    "message": {
                        "message_id": 1,
                        "from": { "id": 100, "first_name": "Alice" },
                        "chat": { "id": 100, "type": "private" },
                        "date": 1700000000,
                        "text": "Hello"
                    }
                },
                {
                    "update_id": 2,
                    "message": {
                        "message_id": 2,
                        "from": { "id": 200, "first_name": "Bob" },
                        "chat": { "id": 200, "type": "private" },
                        "date": 1700000001,
                        "text": "World"
                    }
                }
            ]
        });

        let resp: TelegramResponse<Vec<Update>> = serde_json::from_value(json).unwrap();
        assert!(resp.ok);
        let updates = resp.result.unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].update_id, 1);
        assert_eq!(updates[1].update_id, 2);
    }

    #[test]
    fn test_deserialize_api_response_error() {
        let json = serde_json::json!({
            "ok": false,
            "description": "Unauthorized"
        });

        let resp: TelegramResponse<Vec<Update>> = serde_json::from_value(json).unwrap();
        assert!(!resp.ok);
        assert!(resp.result.is_none());
        assert_eq!(resp.description.unwrap(), "Unauthorized");
    }

    // ========== Rate Limiter Tests ==========

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new(3);
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_ok());
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_ok());

        let result = limiter.check_and_record();
        assert!(result.is_err());
        match result {
            Err(StewardError::RateLimitExceeded(msg)) => {
                assert!(msg.contains("Telegram"));
                assert!(msg.contains("2"));
            }
            other => panic!("Expected RateLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_rate_limiter_recovers_after_window() {
        let mut limiter = RateLimiter::new(1);
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_err());

        // Manually expire the timestamps by replacing them with old ones.
        limiter.timestamps = vec![std::time::Instant::now() - Duration::from_secs(61)];
        assert!(limiter.check_and_record().is_ok());
    }

    #[test]
    fn test_rate_limiter_zero_limit() {
        let mut limiter = RateLimiter::new(0);
        let result = limiter.check_and_record();
        assert!(result.is_err());
    }

    // ========== TelegramConfig Tests ==========

    #[test]
    fn test_config_api_url() {
        let config = TelegramConfig {
            bot_token: "123456:ABC".to_string(),
            api_base_url: "https://api.telegram.org".to_string(),
            ..TelegramConfig::default()
        };
        assert_eq!(
            config.api_url("sendMessage"),
            "https://api.telegram.org/bot123456:ABC/sendMessage"
        );
        assert_eq!(
            config.api_url("getUpdates"),
            "https://api.telegram.org/bot123456:ABC/getUpdates"
        );
    }

    #[test]
    fn test_config_defaults() {
        let config = TelegramConfig::default();
        assert_eq!(config.api_base_url, "https://api.telegram.org");
        assert_eq!(config.polling_timeout_secs, 30);
        assert_eq!(config.approval_timeout_secs, 300);
        assert_eq!(config.rate_limit_per_minute, 30);
        assert!(config.allowed_user_ids.is_empty());
        assert!(config.bot_token.is_empty());
    }

    // ========== Adapter Construction Tests ==========

    #[test]
    fn test_is_user_allowed() {
        let adapter = TelegramAdapter::new(test_config());
        assert!(adapter.is_user_allowed(100));
        assert!(adapter.is_user_allowed(200));
        assert!(adapter.is_user_allowed(300));
        assert!(!adapter.is_user_allowed(999));
        assert!(!adapter.is_user_allowed(0));
    }

    // ========== Start Listening Tests ==========

    #[tokio::test]
    async fn test_start_listening_once() {
        let mut adapter = TelegramAdapter::new(test_config());
        let result = adapter.start_listening().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_listening_twice_fails() {
        let mut adapter = TelegramAdapter::new(test_config());
        let _ = adapter.start_listening().await.unwrap();
        let result = adapter.start_listening().await;
        assert!(result.is_err());
        match result {
            Err(StewardError::Channel(msg)) => {
                assert!(msg.contains("already called"));
            }
            other => panic!("Expected Channel error, got {other:?}"),
        }
    }

    // ========== Approval Flow Tests ==========

    #[tokio::test]
    async fn test_approval_callback_approved() {
        let adapter = TelegramAdapter::new(test_config());

        let approval_id = "test_approval_123";
        let (tx, mut rx) = mpsc::channel(1);

        // Register a pending approval.
        adapter
            .pending_approvals
            .write()
            .await
            .insert(approval_id.to_string(), tx);

        // Simulate receiving an approve callback query.
        let user = make_tg_user(100, "Alice", None);
        let cq = make_callback_query(
            "cq_test",
            user,
            Some(&format!("approve_{approval_id}")),
            None,
        );

        // Directly invoke the handler (not through the Bot API).
        adapter.handle_callback_query(&cq).await;

        let result = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_approval_callback_rejected() {
        let adapter = TelegramAdapter::new(test_config());

        let approval_id = "test_approval_456";
        let (tx, mut rx) = mpsc::channel(1);

        adapter
            .pending_approvals
            .write()
            .await
            .insert(approval_id.to_string(), tx);

        let user = make_tg_user(200, "Bob", None);
        let cq = make_callback_query(
            "cq_test2",
            user,
            Some(&format!("reject_{approval_id}")),
            None,
        );

        adapter.handle_callback_query(&cq).await;

        let result = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_approval_callback_unknown_id() {
        let adapter = TelegramAdapter::new(test_config());

        // No pending approvals registered.
        let user = make_tg_user(100, "Alice", None);
        let cq = make_callback_query("cq_test3", user, Some("approve_nonexistent"), None);

        // Should not panic — gracefully ignores unknown approval IDs.
        adapter.handle_callback_query(&cq).await;
    }

    #[tokio::test]
    async fn test_approval_callback_unauthorized_user() {
        let adapter = TelegramAdapter::new(test_config());

        let approval_id = "test_approval_789";
        let (tx, mut rx) = mpsc::channel(1);

        adapter
            .pending_approvals
            .write()
            .await
            .insert(approval_id.to_string(), tx);

        // User 999 is NOT in the allowlist.
        let user = make_tg_user(999, "Hacker", None);
        let cq = make_callback_query(
            "cq_test4",
            user,
            Some(&format!("approve_{approval_id}")),
            None,
        );

        adapter.handle_callback_query(&cq).await;

        // The approval should NOT have been resolved.
        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_err(), "Should have timed out — unauthorized user");
    }

    #[tokio::test]
    async fn test_approval_timeout() {
        let adapter = TelegramAdapter::new(test_config());

        // Create an approval request — it will fail at the HTTP call since there is
        // no real Telegram server, or it will time out.
        let request = sample_approval_request(100);

        let result = adapter.request_approval(request).await;
        assert!(result.is_err());

        // The error should be Channel (HTTP call fails) or Timeout.
        match result {
            Err(StewardError::Channel(_)) => {}
            Err(StewardError::Timeout(_)) => {}
            Err(other) => panic!("Unexpected error type: {other:?}"),
            Ok(_) => panic!("Expected error"),
        }
    }

    // ========== Handle Message (on adapter) Tests ==========

    #[tokio::test]
    async fn test_handle_message_allowed_user() {
        let adapter = TelegramAdapter::new(test_config());

        let user = make_tg_user(100, "Alice", Some("alice"));
        let msg = make_tg_message(1, Some(user), 100, Some("Hello!"));

        // Create a second receiver to verify the message is forwarded.
        // The adapter already has a receiver, but we can verify via the sender.
        adapter.handle_message(&msg).await;

        // Pull from the channel stored in the adapter.
        let mut rx_guard = adapter.inbound_rx.lock().await;
        let rx = rx_guard.as_mut().unwrap();

        let inbound = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inbound.text, "Hello!");
        assert_eq!(inbound.sender, "@alice");
        assert_eq!(inbound.channel, ChannelType::Telegram);
    }

    #[tokio::test]
    async fn test_handle_message_unauthorized_user() {
        let adapter = TelegramAdapter::new(test_config());

        let user = make_tg_user(999, "Hacker", None);
        let msg = make_tg_message(1, Some(user), 999, Some("Trying to get in"));

        adapter.handle_message(&msg).await;

        // Verify nothing was sent to the channel.
        let mut rx_guard = adapter.inbound_rx.lock().await;
        let rx = rx_guard.as_mut().unwrap();

        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_err(), "Should have timed out — no message sent");
    }

    #[tokio::test]
    async fn test_handle_message_no_sender() {
        let adapter = TelegramAdapter::new(test_config());

        let msg = make_tg_message(1, None, 100, Some("Ghost message"));

        adapter.handle_message(&msg).await;

        let mut rx_guard = adapter.inbound_rx.lock().await;
        let rx = rx_guard.as_mut().unwrap();

        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_err(), "Should have timed out — no sender");
    }

    #[tokio::test]
    async fn test_handle_message_no_text() {
        let adapter = TelegramAdapter::new(test_config());

        let user = make_tg_user(100, "Alice", None);
        let msg = make_tg_message(1, Some(user), 100, None);

        adapter.handle_message(&msg).await;

        let mut rx_guard = adapter.inbound_rx.lock().await;
        let rx = rx_guard.as_mut().unwrap();

        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_err(), "Should have timed out — no text");
    }

    // ========== Process Update Tests ==========

    #[tokio::test]
    async fn test_process_update_with_message() {
        let adapter = TelegramAdapter::new(test_config());

        let user = make_tg_user(100, "Alice", None);
        let msg = make_tg_message(42, Some(user), 100, Some("Via update"));

        let update = Update {
            update_id: 1,
            message: Some(msg),
            callback_query: None,
        };

        adapter.process_update(&update).await;

        let mut rx_guard = adapter.inbound_rx.lock().await;
        let rx = rx_guard.as_mut().unwrap();

        let inbound = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inbound.text, "Via update");
    }

    #[tokio::test]
    async fn test_process_update_with_callback_query() {
        let adapter = TelegramAdapter::new(test_config());

        let approval_id = "update_test_id";
        let (tx, mut rx) = mpsc::channel(1);
        adapter
            .pending_approvals
            .write()
            .await
            .insert(approval_id.to_string(), tx);

        let user = make_tg_user(100, "Alice", None);
        let cq = make_callback_query(
            "cq_update",
            user,
            Some(&format!("approve_{approval_id}")),
            None,
        );

        let update = Update {
            update_id: 2,
            message: None,
            callback_query: Some(cq),
        };

        adapter.process_update(&update).await;

        let approved = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(approved);
    }

    #[tokio::test]
    async fn test_process_update_callback_takes_priority() {
        // When an update has both a message AND a callback_query,
        // the callback_query should be handled and the message ignored.
        let adapter = TelegramAdapter::new(test_config());

        let approval_id = "priority_test";
        let (tx, mut approval_rx) = mpsc::channel(1);
        adapter
            .pending_approvals
            .write()
            .await
            .insert(approval_id.to_string(), tx);

        let user = make_tg_user(100, "Alice", None);
        let msg = make_tg_message(1, Some(user.clone()), 100, Some("Should be ignored"));
        let cq = make_callback_query(
            "cq_prio",
            user,
            Some(&format!("reject_{approval_id}")),
            None,
        );

        let update = Update {
            update_id: 3,
            message: Some(msg),
            callback_query: Some(cq),
        };

        adapter.process_update(&update).await;

        // The callback should have been resolved.
        let approved = tokio::time::timeout(Duration::from_secs(1), approval_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!approved);

        // The message should NOT have been forwarded.
        let mut rx_guard = adapter.inbound_rx.lock().await;
        let rx = rx_guard.as_mut().unwrap();
        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(
            result.is_err(),
            "Message should not have been forwarded when callback_query is present"
        );
    }

    // ========== Send Message (with mock server) Tests ==========

    #[tokio::test]
    async fn test_send_message_rate_limited() {
        let mut config = test_config();
        config.rate_limit_per_minute = 2;
        let adapter = TelegramAdapter::new(config);

        // Exhaust the rate limiter by directly recording sends.
        {
            let mut limiter = adapter.rate_limiter.lock().await;
            limiter.check_and_record().unwrap();
            limiter.check_and_record().unwrap();
        }

        // Now send_message should be rate-limited.
        let message = OutboundMessage {
            recipient: "12345".to_string(),
            text: "Should fail".to_string(),
            channel: ChannelType::Telegram,
            metadata: serde_json::json!({}),
        };

        let result = adapter.send_message(message).await;
        assert!(result.is_err());
        match result {
            Err(StewardError::RateLimitExceeded(msg)) => {
                assert!(msg.contains("Telegram"));
            }
            other => panic!("Expected RateLimitExceeded, got {other:?}"),
        }
    }

    // ========== Polling Worker Tests ==========

    #[tokio::test]
    async fn test_polling_worker_handle_message_allowed() {
        let (tx, mut rx) = mpsc::channel(256);
        let worker = TelegramPollingWorker {
            client: reqwest::Client::new(),
            config: Arc::new(test_config()),
            inbound_tx: Arc::new(tx),
            pending_approvals: Arc::new(RwLock::new(HashMap::new())),
            allowed_user_ids: vec![100, 200],
        };

        let user = make_tg_user(100, "Alice", Some("alice"));
        let msg = make_tg_message(1, Some(user), 100, Some("Worker test"));

        worker.handle_message(&msg).await;

        let inbound = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inbound.text, "Worker test");
    }

    #[tokio::test]
    async fn test_polling_worker_handle_message_unauthorized() {
        let (tx, mut rx) = mpsc::channel(256);
        let worker = TelegramPollingWorker {
            client: reqwest::Client::new(),
            config: Arc::new(test_config()),
            inbound_tx: Arc::new(tx),
            pending_approvals: Arc::new(RwLock::new(HashMap::new())),
            allowed_user_ids: vec![100],
        };

        let user = make_tg_user(999, "Hacker", None);
        let msg = make_tg_message(1, Some(user), 999, Some("Blocked"));

        worker.handle_message(&msg).await;

        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_polling_worker_handle_callback_approved() {
        let (tx, _rx) = mpsc::channel(256);
        let pending = Arc::new(RwLock::new(HashMap::new()));

        let approval_id = "worker_approval";
        let (approval_tx, mut approval_rx) = mpsc::channel(1);
        pending
            .write()
            .await
            .insert(approval_id.to_string(), approval_tx);

        let worker = TelegramPollingWorker {
            client: reqwest::Client::new(),
            config: Arc::new(test_config()),
            inbound_tx: Arc::new(tx),
            pending_approvals: pending,
            allowed_user_ids: vec![100],
        };

        let user = make_tg_user(100, "Alice", None);
        let cq = make_callback_query(
            "cq_worker",
            user,
            Some(&format!("approve_{approval_id}")),
            None,
        );

        worker.handle_callback_query(&cq).await;

        let approved = tokio::time::timeout(Duration::from_secs(1), approval_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(approved);
    }

    #[tokio::test]
    async fn test_polling_worker_handle_callback_unauthorized() {
        let (tx, _rx) = mpsc::channel(256);
        let pending = Arc::new(RwLock::new(HashMap::new()));

        let approval_id = "worker_approval_unauth";
        let (approval_tx, mut approval_rx) = mpsc::channel(1);
        pending
            .write()
            .await
            .insert(approval_id.to_string(), approval_tx);

        let worker = TelegramPollingWorker {
            client: reqwest::Client::new(),
            config: Arc::new(test_config()),
            inbound_tx: Arc::new(tx),
            pending_approvals: pending,
            allowed_user_ids: vec![100],
        };

        // User 999 is not allowed.
        let user = make_tg_user(999, "Hacker", None);
        let cq = make_callback_query(
            "cq_unauth",
            user,
            Some(&format!("approve_{approval_id}")),
            None,
        );

        worker.handle_callback_query(&cq).await;

        // Approval should NOT have been resolved.
        let result = tokio::time::timeout(Duration::from_millis(100), approval_rx.recv()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_polling_worker_process_update_message() {
        let (tx, mut rx) = mpsc::channel(256);
        let worker = TelegramPollingWorker {
            client: reqwest::Client::new(),
            config: Arc::new(test_config()),
            inbound_tx: Arc::new(tx),
            pending_approvals: Arc::new(RwLock::new(HashMap::new())),
            allowed_user_ids: vec![100],
        };

        let user = make_tg_user(100, "Alice", None);
        let msg = make_tg_message(1, Some(user), 100, Some("Process update test"));

        let update = Update {
            update_id: 10,
            message: Some(msg),
            callback_query: None,
        };

        worker.process_update(&update).await;

        let inbound = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inbound.text, "Process update test");
    }

    #[tokio::test]
    async fn test_polling_worker_process_update_callback() {
        let (tx, _rx) = mpsc::channel(256);
        let pending = Arc::new(RwLock::new(HashMap::new()));

        let approval_id = "process_cb";
        let (approval_tx, mut approval_rx) = mpsc::channel(1);
        pending
            .write()
            .await
            .insert(approval_id.to_string(), approval_tx);

        let worker = TelegramPollingWorker {
            client: reqwest::Client::new(),
            config: Arc::new(test_config()),
            inbound_tx: Arc::new(tx),
            pending_approvals: pending,
            allowed_user_ids: vec![100],
        };

        let user = make_tg_user(100, "Alice", None);
        let cq = make_callback_query(
            "cq_proc",
            user,
            Some(&format!("reject_{approval_id}")),
            None,
        );

        let update = Update {
            update_id: 11,
            message: None,
            callback_query: Some(cq),
        };

        worker.process_update(&update).await;

        let approved = tokio::time::timeout(Duration::from_secs(1), approval_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!approved);
    }
}
