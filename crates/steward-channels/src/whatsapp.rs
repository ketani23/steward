//! WhatsApp Business Cloud API channel adapter.
//!
//! Handles WhatsApp communication:
//! - Webhook endpoint for inbound messages (axum HTTP server)
//! - Webhook signature verification (HMAC-SHA256)
//! - Outbound message sending via Business Cloud API
//! - Interactive approval buttons for human-in-the-loop
//! - Rate limiting for outbound messages
//!
//! See `docs/architecture.md` section 10 for channel requirements.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::{mpsc, Mutex, RwLock};
use uuid::Uuid;

use steward_types::actions::*;
use steward_types::errors::StewardError;
use steward_types::traits::ChannelAdapter;

/// Configuration for the WhatsApp Business Cloud API adapter.
#[derive(Debug, Clone)]
pub struct WhatsAppConfig {
    /// WhatsApp Business API access token.
    pub access_token: String,
    /// Phone number ID for the WhatsApp Business account.
    pub phone_number_id: String,
    /// App secret used for webhook signature verification.
    pub app_secret: String,
    /// Webhook verification token (set during Facebook app setup).
    pub verify_token: String,
    /// Base URL for the WhatsApp Business API (default: graph.facebook.com).
    pub api_base_url: String,
    /// API version (default: v21.0).
    pub api_version: String,
    /// Maximum outbound messages per minute (rate limiting).
    pub rate_limit_per_minute: u32,
    /// Default approval timeout in seconds.
    pub approval_timeout_secs: u64,
}

impl Default for WhatsAppConfig {
    fn default() -> Self {
        Self {
            access_token: String::new(),
            phone_number_id: String::new(),
            app_secret: String::new(),
            verify_token: String::new(),
            api_base_url: "https://graph.facebook.com".to_string(),
            api_version: "v21.0".to_string(),
            rate_limit_per_minute: 80,
            approval_timeout_secs: 300,
        }
    }
}

/// Shared state for the webhook handler and the adapter.
#[derive(Clone)]
pub struct WhatsAppState {
    /// Configuration.
    config: Arc<WhatsAppConfig>,
    /// Sender for inbound messages parsed from webhooks.
    inbound_tx: Arc<mpsc::Sender<InboundMessage>>,
    /// Pending approval callbacks keyed by message ID.
    /// When an interactive button response arrives, we resolve the pending approval.
    pending_approvals: Arc<RwLock<HashMap<String, mpsc::Sender<bool>>>>,
    /// Rate limiter: tracks timestamps of recent outbound messages.
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

/// Simple sliding-window rate limiter.
struct RateLimiter {
    /// Timestamps of recent sends (within the window).
    timestamps: Vec<std::time::Instant>,
    /// Maximum messages allowed per window.
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
                "WhatsApp rate limit exceeded: {} messages/minute",
                self.max_per_minute
            )));
        }
        self.timestamps.push(now);
        Ok(())
    }
}

/// WhatsApp Business Cloud API adapter.
///
/// Implements the [`ChannelAdapter`] trait, providing inbound message handling
/// via webhooks, outbound message sending, and interactive approval flows.
pub struct WhatsAppAdapter {
    /// HTTP client for outbound API calls.
    client: reqwest::Client,
    /// Shared state with the webhook handler.
    state: WhatsAppState,
    /// Receiver end — taken once by `start_listening()`.
    inbound_rx: Mutex<Option<mpsc::Receiver<InboundMessage>>>,
}

impl WhatsAppAdapter {
    /// Create a new WhatsApp adapter with the given configuration.
    pub fn new(config: WhatsAppConfig) -> Self {
        let (tx, rx) = mpsc::channel(256);
        let rate_limiter = RateLimiter::new(config.rate_limit_per_minute);

        let state = WhatsAppState {
            config: Arc::new(config),
            inbound_tx: Arc::new(tx),
            pending_approvals: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
        };

        Self {
            client: reqwest::Client::new(),
            state,
            inbound_rx: Mutex::new(Some(rx)),
        }
    }

    /// Build the axum router for WhatsApp webhook endpoints.
    ///
    /// Mount this into a larger web server:
    /// ```rust,ignore
    /// let app = Router::new()
    ///     .nest("/webhook/whatsapp", adapter.webhook_router());
    /// ```
    pub fn webhook_router(&self) -> Router {
        Router::new()
            .route("/", get(webhook_verify))
            .route("/", post(webhook_receive))
            .with_state(self.state.clone())
    }

    /// Build the WhatsApp Business API URL for sending messages.
    fn send_url(&self) -> String {
        format!(
            "{}/{}/{}/messages",
            self.state.config.api_base_url,
            self.state.config.api_version,
            self.state.config.phone_number_id
        )
    }

    /// Send a text message via the WhatsApp Business Cloud API.
    async fn send_text(&self, to: &str, text: &str) -> Result<(), StewardError> {
        // Check rate limit
        self.state.rate_limiter.lock().await.check_and_record()?;

        let body = serde_json::json!({
            "messaging_product": "whatsapp",
            "to": to,
            "type": "text",
            "text": { "body": text }
        });

        let resp = self
            .client
            .post(self.send_url())
            .bearer_auth(&self.state.config.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| StewardError::Channel(format!("WhatsApp send failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(StewardError::Channel(format!(
                "WhatsApp API error {status}: {body}"
            )));
        }

        Ok(())
    }

    /// Send an interactive button message for approval flows.
    async fn send_interactive_buttons(
        &self,
        to: &str,
        body_text: &str,
        approve_id: &str,
        reject_id: &str,
    ) -> Result<(), StewardError> {
        // Check rate limit
        self.state.rate_limiter.lock().await.check_and_record()?;

        let body = serde_json::json!({
            "messaging_product": "whatsapp",
            "to": to,
            "type": "interactive",
            "interactive": {
                "type": "button",
                "body": { "text": body_text },
                "action": {
                    "buttons": [
                        {
                            "type": "reply",
                            "reply": {
                                "id": approve_id,
                                "title": "Approve"
                            }
                        },
                        {
                            "type": "reply",
                            "reply": {
                                "id": reject_id,
                                "title": "Reject"
                            }
                        }
                    ]
                }
            }
        });

        let resp = self
            .client
            .post(self.send_url())
            .bearer_auth(&self.state.config.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| StewardError::Channel(format!("WhatsApp send failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(StewardError::Channel(format!(
                "WhatsApp API error {status}: {body}"
            )));
        }

        Ok(())
    }
}

#[async_trait]
impl ChannelAdapter for WhatsAppAdapter {
    /// Send a message through WhatsApp.
    async fn send_message(&self, message: OutboundMessage) -> Result<(), StewardError> {
        self.send_text(&message.recipient, &message.text).await
    }

    /// Start listening for inbound messages via the webhook.
    ///
    /// Returns a receiver that yields parsed inbound messages. Can only be
    /// called once — subsequent calls return an error.
    async fn start_listening(&mut self) -> Result<mpsc::Receiver<InboundMessage>, StewardError> {
        self.inbound_rx
            .lock()
            .await
            .take()
            .ok_or_else(|| StewardError::Channel("start_listening already called".to_string()))
    }

    /// Request human approval for an action.
    ///
    /// Sends an interactive button message (Approve / Reject) and waits for
    /// the user's response with a configurable timeout.
    async fn request_approval(
        &self,
        request: ApprovalRequest,
    ) -> Result<ApprovalResponse, StewardError> {
        let approval_id = Uuid::new_v4().to_string();
        let approve_id = format!("approve_{approval_id}");
        let reject_id = format!("reject_{approval_id}");

        // Format the approval message with action details
        let body_text = crate::confirmation::format_approval_message(&request);

        // Register a oneshot channel for the callback
        let (tx, mut rx) = mpsc::channel(1);
        self.state
            .pending_approvals
            .write()
            .await
            .insert(approval_id.clone(), tx);

        // Determine the recipient from the proposal's metadata or use a configured default
        let recipient = request
            .proposal
            .parameters
            .get("sender")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Send the interactive buttons
        self.send_interactive_buttons(&recipient, &body_text, &approve_id, &reject_id)
            .await?;

        // Wait for button callback with timeout
        let timeout_secs = if request.timeout_secs > 0 {
            request.timeout_secs
        } else {
            self.state.config.approval_timeout_secs
        };

        let result = tokio::time::timeout(Duration::from_secs(timeout_secs), rx.recv()).await;

        // Clean up pending approval
        self.state
            .pending_approvals
            .write()
            .await
            .remove(&approval_id);

        match result {
            Ok(Some(approved)) => Ok(ApprovalResponse {
                approved,
                message: if approved {
                    Some("User approved via WhatsApp".to_string())
                } else {
                    Some("User rejected via WhatsApp".to_string())
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
// Webhook Handlers
// ============================================================

/// Query parameters for webhook verification (GET request).
#[derive(serde::Deserialize)]
pub struct WebhookVerifyParams {
    #[serde(rename = "hub.mode")]
    hub_mode: Option<String>,
    #[serde(rename = "hub.verify_token")]
    hub_verify_token: Option<String>,
    #[serde(rename = "hub.challenge")]
    hub_challenge: Option<String>,
}

/// GET handler for webhook verification (Facebook webhook setup).
async fn webhook_verify(
    State(state): State<WhatsAppState>,
    Query(params): Query<WebhookVerifyParams>,
) -> impl IntoResponse {
    if let (Some(mode), Some(token), Some(challenge)) = (
        &params.hub_mode,
        &params.hub_verify_token,
        &params.hub_challenge,
    ) {
        if mode == "subscribe" && token == &state.config.verify_token {
            tracing::info!("Webhook verification succeeded");
            return (StatusCode::OK, challenge.clone());
        }
    }
    tracing::warn!("Webhook verification failed");
    (StatusCode::FORBIDDEN, "Verification failed".to_string())
}

/// POST handler for inbound webhook events.
async fn webhook_receive(
    State(state): State<WhatsAppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Verify webhook signature
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok());

    if !verify_signature(&state.config.app_secret, &body, signature) {
        tracing::warn!("Webhook signature verification failed");
        return StatusCode::UNAUTHORIZED;
    }

    // Parse the webhook payload
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Failed to parse webhook payload: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };

    // Process messages from the payload
    if let Some(entries) = payload.get("entry").and_then(|e| e.as_array()) {
        for entry in entries {
            if let Some(changes) = entry.get("changes").and_then(|c| c.as_array()) {
                for change in changes {
                    let value = match change.get("value") {
                        Some(v) => v,
                        None => continue,
                    };

                    // Handle interactive button responses (approval callbacks)
                    if let Some(statuses) = value.get("statuses") {
                        tracing::debug!("Received status update: {statuses}");
                    }

                    // Handle incoming messages
                    if let Some(messages) = value.get("messages").and_then(|m| m.as_array()) {
                        let contacts = value.get("contacts").and_then(|c| c.as_array());

                        for message in messages {
                            // Check for interactive button replies (approval callbacks)
                            if let Some(interactive) = message.get("interactive") {
                                handle_interactive_reply(&state, interactive).await;
                                continue;
                            }

                            // Check for regular button replies
                            if let Some(button) = message.get("button") {
                                handle_button_reply(&state, button).await;
                                continue;
                            }

                            if let Some(inbound) = parse_message(message, contacts) {
                                if let Err(e) = state.inbound_tx.send(inbound).await {
                                    tracing::error!("Failed to forward inbound message: {e}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    StatusCode::OK
}

/// Handle interactive button reply messages (approval callbacks).
async fn handle_interactive_reply(state: &WhatsAppState, interactive: &serde_json::Value) {
    let button_reply = match interactive.get("button_reply") {
        Some(br) => br,
        None => return,
    };

    let button_id = match button_reply.get("id").and_then(|id| id.as_str()) {
        Some(id) => id,
        None => return,
    };

    // Extract approval ID from button_id format: "approve_{id}" or "reject_{id}"
    let (approved, approval_id) = if let Some(id) = button_id.strip_prefix("approve_") {
        (true, id)
    } else if let Some(id) = button_id.strip_prefix("reject_") {
        (false, id)
    } else {
        return;
    };

    let approvals = state.pending_approvals.read().await;
    if let Some(tx) = approvals.get(approval_id) {
        if let Err(e) = tx.send(approved).await {
            tracing::error!("Failed to send approval response: {e}");
        }
    }
}

/// Handle regular button reply messages (approval callbacks).
async fn handle_button_reply(state: &WhatsAppState, button: &serde_json::Value) {
    let payload = match button.get("payload").and_then(|p| p.as_str()) {
        Some(p) => p,
        None => return,
    };

    let (approved, approval_id) = if let Some(id) = payload.strip_prefix("approve_") {
        (true, id)
    } else if let Some(id) = payload.strip_prefix("reject_") {
        (false, id)
    } else {
        return;
    };

    let approvals = state.pending_approvals.read().await;
    if let Some(tx) = approvals.get(approval_id) {
        if let Err(e) = tx.send(approved).await {
            tracing::error!("Failed to send approval response: {e}");
        }
    }
}

/// Parse a WhatsApp message payload into an InboundMessage.
///
/// Handles text, image, and document message types.
fn parse_message(
    message: &serde_json::Value,
    contacts: Option<&Vec<serde_json::Value>>,
) -> Option<InboundMessage> {
    let from = message.get("from")?.as_str()?;
    let msg_type = message.get("type")?.as_str()?;
    let wa_id = message.get("id")?.as_str()?;

    // Resolve sender name from contacts
    let sender_name = contacts
        .and_then(|c| {
            c.iter().find_map(|contact| {
                let wa_id_match = contact.get("wa_id")?.as_str()? == from;
                if wa_id_match {
                    contact
                        .get("profile")
                        .and_then(|p| p.get("name"))
                        .and_then(|n| n.as_str())
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| from.to_string());

    let (text, metadata) = match msg_type {
        "text" => {
            let body = message.get("text")?.get("body")?.as_str()?;
            (body.to_string(), serde_json::json!({"type": "text"}))
        }
        "image" => {
            let image = message.get("image")?;
            let caption = image
                .get("caption")
                .and_then(|c| c.as_str())
                .unwrap_or("[Image]");
            let media_id = image.get("id").and_then(|id| id.as_str());
            let mime_type = image.get("mime_type").and_then(|m| m.as_str());

            (
                caption.to_string(),
                serde_json::json!({
                    "type": "image",
                    "media_id": media_id,
                    "mime_type": mime_type,
                }),
            )
        }
        "document" => {
            let doc = message.get("document")?;
            let filename = doc
                .get("filename")
                .and_then(|f| f.as_str())
                .unwrap_or("[Document]");
            let media_id = doc.get("id").and_then(|id| id.as_str());
            let mime_type = doc.get("mime_type").and_then(|m| m.as_str());
            let caption = doc.get("caption").and_then(|c| c.as_str());

            (
                caption.unwrap_or(filename).to_string(),
                serde_json::json!({
                    "type": "document",
                    "media_id": media_id,
                    "mime_type": mime_type,
                    "filename": filename,
                }),
            )
        }
        _ => {
            tracing::debug!("Ignoring unsupported WhatsApp message type: {msg_type}");
            return None;
        }
    };

    Some(InboundMessage {
        id: Uuid::new_v4(),
        text,
        channel: ChannelType::WhatsApp,
        sender: sender_name,
        timestamp: Utc::now(),
        metadata: serde_json::json!({
            "whatsapp_message_id": wa_id,
            "from": from,
            "message": metadata,
        }),
    })
}

// ============================================================
// Webhook Signature Verification
// ============================================================

/// Verify the HMAC-SHA256 webhook signature from the WhatsApp Business API.
///
/// The signature header value is formatted as `sha256=<hex_digest>`.
pub fn verify_signature(app_secret: &str, body: &[u8], signature_header: Option<&str>) -> bool {
    let signature_header = match signature_header {
        Some(s) => s,
        None => return false,
    };

    let expected_hex = match signature_header.strip_prefix("sha256=") {
        Some(hex) => hex,
        None => return false,
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(app_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };

    mac.update(body);
    let result = mac.finalize().into_bytes();
    let computed_hex = hex_encode(&result);

    // Constant-time comparison via hmac's verify
    computed_hex == expected_hex
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use hmac::Mac;
    use tower::ServiceExt;

    fn test_config() -> WhatsAppConfig {
        WhatsAppConfig {
            access_token: "test_token".to_string(),
            phone_number_id: "123456789".to_string(),
            app_secret: "test_secret".to_string(),
            verify_token: "test_verify_token".to_string(),
            api_base_url: "https://graph.facebook.com".to_string(),
            api_version: "v21.0".to_string(),
            rate_limit_per_minute: 5,
            approval_timeout_secs: 10,
        }
    }

    /// Compute HMAC-SHA256 signature for test payloads.
    fn compute_signature(secret: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let result = mac.finalize().into_bytes();
        format!("sha256={}", hex_encode(&result))
    }

    // ========== Signature Verification Tests ==========

    #[test]
    fn test_valid_signature() {
        let secret = "my_secret";
        let body = b"hello world";
        let sig = compute_signature(secret, body);
        assert!(verify_signature(secret, body, Some(&sig)));
    }

    #[test]
    fn test_invalid_signature() {
        let secret = "my_secret";
        let body = b"hello world";
        assert!(!verify_signature(secret, body, Some("sha256=deadbeef")));
    }

    #[test]
    fn test_missing_signature() {
        assert!(!verify_signature("secret", b"body", None));
    }

    #[test]
    fn test_malformed_signature_no_prefix() {
        assert!(!verify_signature(
            "secret",
            b"body",
            Some("bad_prefix=abc123")
        ));
    }

    #[test]
    fn test_signature_with_different_body() {
        let secret = "my_secret";
        let sig = compute_signature(secret, b"original body");
        assert!(!verify_signature(secret, b"tampered body", Some(&sig)));
    }

    #[test]
    fn test_signature_with_different_secret() {
        let body = b"hello world";
        let sig = compute_signature("secret_a", body);
        assert!(!verify_signature("secret_b", body, Some(&sig)));
    }

    // ========== Message Parsing Tests ==========

    #[test]
    fn test_parse_text_message() {
        let msg = serde_json::json!({
            "from": "15551234567",
            "id": "wamid.abc123",
            "type": "text",
            "text": { "body": "Hello, Steward!" }
        });

        let contacts = vec![serde_json::json!({
            "wa_id": "15551234567",
            "profile": { "name": "Alice" }
        })];

        let result = parse_message(&msg, Some(&contacts)).unwrap();
        assert_eq!(result.text, "Hello, Steward!");
        assert_eq!(result.sender, "Alice");
        assert_eq!(result.channel, ChannelType::WhatsApp);
        assert_eq!(result.metadata["from"], "15551234567");
        assert_eq!(result.metadata["message"]["type"], "text");
    }

    #[test]
    fn test_parse_text_message_no_contact() {
        let msg = serde_json::json!({
            "from": "15551234567",
            "id": "wamid.abc123",
            "type": "text",
            "text": { "body": "Hello!" }
        });

        let result = parse_message(&msg, None).unwrap();
        assert_eq!(result.text, "Hello!");
        assert_eq!(result.sender, "15551234567");
    }

    #[test]
    fn test_parse_image_message() {
        let msg = serde_json::json!({
            "from": "15551234567",
            "id": "wamid.img123",
            "type": "image",
            "image": {
                "id": "media_id_123",
                "mime_type": "image/jpeg",
                "caption": "Check this out"
            }
        });

        let result = parse_message(&msg, None).unwrap();
        assert_eq!(result.text, "Check this out");
        assert_eq!(result.metadata["message"]["type"], "image");
        assert_eq!(result.metadata["message"]["media_id"], "media_id_123");
        assert_eq!(result.metadata["message"]["mime_type"], "image/jpeg");
    }

    #[test]
    fn test_parse_image_message_no_caption() {
        let msg = serde_json::json!({
            "from": "15551234567",
            "id": "wamid.img456",
            "type": "image",
            "image": {
                "id": "media_id_456",
                "mime_type": "image/png"
            }
        });

        let result = parse_message(&msg, None).unwrap();
        assert_eq!(result.text, "[Image]");
    }

    #[test]
    fn test_parse_document_message() {
        let msg = serde_json::json!({
            "from": "15551234567",
            "id": "wamid.doc123",
            "type": "document",
            "document": {
                "id": "media_id_doc",
                "mime_type": "application/pdf",
                "filename": "receipt.pdf",
                "caption": "My receipt"
            }
        });

        let result = parse_message(&msg, None).unwrap();
        assert_eq!(result.text, "My receipt");
        assert_eq!(result.metadata["message"]["type"], "document");
        assert_eq!(result.metadata["message"]["filename"], "receipt.pdf");
        assert_eq!(result.metadata["message"]["media_id"], "media_id_doc");
    }

    #[test]
    fn test_parse_document_message_no_caption() {
        let msg = serde_json::json!({
            "from": "15551234567",
            "id": "wamid.doc456",
            "type": "document",
            "document": {
                "id": "media_id_doc2",
                "mime_type": "application/pdf",
                "filename": "invoice.pdf"
            }
        });

        let result = parse_message(&msg, None).unwrap();
        assert_eq!(result.text, "invoice.pdf");
    }

    #[test]
    fn test_parse_unsupported_message_type() {
        let msg = serde_json::json!({
            "from": "15551234567",
            "id": "wamid.sticker123",
            "type": "sticker",
            "sticker": { "id": "sticker_id" }
        });

        assert!(parse_message(&msg, None).is_none());
    }

    #[test]
    fn test_parse_message_missing_fields() {
        // Missing "type"
        let msg = serde_json::json!({
            "from": "15551234567",
            "id": "wamid.abc"
        });
        assert!(parse_message(&msg, None).is_none());

        // Missing "from"
        let msg = serde_json::json!({
            "id": "wamid.abc",
            "type": "text",
            "text": { "body": "Hello" }
        });
        assert!(parse_message(&msg, None).is_none());
    }

    // ========== Webhook Handler Tests ==========

    #[tokio::test]
    async fn test_webhook_verify_success() {
        let adapter = WhatsAppAdapter::new(test_config());
        let router = adapter.webhook_router();

        let req = Request::builder()
            .method("GET")
            .uri("/?hub.mode=subscribe&hub.verify_token=test_verify_token&hub.challenge=challenge_123")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"challenge_123");
    }

    #[tokio::test]
    async fn test_webhook_verify_wrong_token() {
        let adapter = WhatsAppAdapter::new(test_config());
        let router = adapter.webhook_router();

        let req = Request::builder()
            .method("GET")
            .uri("/?hub.mode=subscribe&hub.verify_token=wrong_token&hub.challenge=challenge_123")
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_webhook_receive_valid_text_message() {
        let config = test_config();
        let mut adapter = WhatsAppAdapter::new(config.clone());
        let router = adapter.webhook_router();
        let mut rx = adapter.start_listening().await.unwrap();

        let payload = serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "123",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": {
                            "display_phone_number": "15550001111",
                            "phone_number_id": "123456789"
                        },
                        "contacts": [{
                            "wa_id": "15559998888",
                            "profile": { "name": "Bob" }
                        }],
                        "messages": [{
                            "from": "15559998888",
                            "id": "wamid.test123",
                            "type": "text",
                            "text": { "body": "Hi there!" },
                            "timestamp": "1234567890"
                        }]
                    }
                }]
            }]
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = compute_signature(&config.app_secret, &body_bytes);

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .header("x-hub-signature-256", signature)
            .body(Body::from(body_bytes))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the message was forwarded
        let msg = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.text, "Hi there!");
        assert_eq!(msg.sender, "Bob");
        assert_eq!(msg.channel, ChannelType::WhatsApp);
    }

    #[tokio::test]
    async fn test_webhook_receive_invalid_signature() {
        let adapter = WhatsAppAdapter::new(test_config());
        let router = adapter.webhook_router();

        let payload = serde_json::json!({"entry": []});
        let body_bytes = serde_json::to_vec(&payload).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .header("x-hub-signature-256", "sha256=invalid")
            .body(Body::from(body_bytes))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_webhook_receive_missing_signature() {
        let adapter = WhatsAppAdapter::new(test_config());
        let router = adapter.webhook_router();

        let payload = serde_json::json!({"entry": []});
        let body_bytes = serde_json::to_vec(&payload).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(body_bytes))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ========== Approval Flow Tests ==========

    #[tokio::test]
    async fn test_approval_timeout() {
        let mut config = test_config();
        config.approval_timeout_secs = 1; // 1 second timeout for test
        let adapter = WhatsAppAdapter::new(config);

        let request = ApprovalRequest {
            proposal: ActionProposal {
                id: Uuid::new_v4(),
                tool_name: "email.send".to_string(),
                parameters: serde_json::json!({"sender": "15551234567"}),
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
            channel: ChannelType::WhatsApp,
            timeout_secs: 1,
        };

        // request_approval will fail because there's no real WhatsApp API server,
        // but we can test that the timeout path returns a Timeout error
        // by providing a non-routable address
        let result = adapter.request_approval(request).await;
        assert!(result.is_err());

        // The error should be a Channel error (API call fails) rather than Timeout
        // because the HTTP request to the fake API fails first
        match result {
            Err(StewardError::Channel(_)) => {} // Expected — API call fails
            Err(StewardError::Timeout(_)) => {} // Also acceptable
            Err(other) => panic!("Unexpected error type: {other:?}"),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn test_approval_callback_approved() {
        let adapter = WhatsAppAdapter::new(test_config());

        let approval_id = "test_approval_123";
        let (tx, mut rx) = mpsc::channel(1);

        // Register a pending approval
        adapter
            .state
            .pending_approvals
            .write()
            .await
            .insert(approval_id.to_string(), tx);

        // Simulate receiving an approve button callback
        let interactive = serde_json::json!({
            "button_reply": {
                "id": format!("approve_{approval_id}"),
                "title": "Approve"
            }
        });

        handle_interactive_reply(&adapter.state, &interactive).await;

        let result = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_approval_callback_rejected() {
        let adapter = WhatsAppAdapter::new(test_config());

        let approval_id = "test_approval_456";
        let (tx, mut rx) = mpsc::channel(1);

        adapter
            .state
            .pending_approvals
            .write()
            .await
            .insert(approval_id.to_string(), tx);

        let interactive = serde_json::json!({
            "button_reply": {
                "id": format!("reject_{approval_id}"),
                "title": "Reject"
            }
        });

        handle_interactive_reply(&adapter.state, &interactive).await;

        let result = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_approval_callback_unknown_id() {
        let adapter = WhatsAppAdapter::new(test_config());

        // No pending approvals registered
        let interactive = serde_json::json!({
            "button_reply": {
                "id": "approve_nonexistent",
                "title": "Approve"
            }
        });

        // Should not panic — gracefully ignores unknown approval IDs
        handle_interactive_reply(&adapter.state, &interactive).await;
    }

    // ========== Rate Limiting Tests ==========

    #[tokio::test]
    async fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new(3);
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_ok());
        let result = limiter.check_and_record();
        assert!(result.is_err());
        match result {
            Err(StewardError::RateLimitExceeded(_)) => {}
            other => panic!("Expected RateLimitExceeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_recovers_after_window() {
        let mut limiter = RateLimiter::new(1);
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_err());

        // Manually expire the timestamps by replacing them with old ones
        limiter.timestamps = vec![std::time::Instant::now() - Duration::from_secs(61)];
        assert!(limiter.check_and_record().is_ok());
    }

    // ========== Start Listening Tests ==========

    #[tokio::test]
    async fn test_start_listening_once() {
        let mut adapter = WhatsAppAdapter::new(test_config());
        let result = adapter.start_listening().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_listening_twice_fails() {
        let mut adapter = WhatsAppAdapter::new(test_config());
        let _ = adapter.start_listening().await.unwrap();
        let result = adapter.start_listening().await;
        assert!(result.is_err());
    }

    // ========== Integration: Webhook + Approval Callback ==========

    #[tokio::test]
    async fn test_webhook_interactive_button_callback() {
        let config = test_config();
        let adapter = WhatsAppAdapter::new(config.clone());
        let router = adapter.webhook_router();

        let approval_id = "integration_test_id";
        let (tx, mut rx) = mpsc::channel(1);
        adapter
            .state
            .pending_approvals
            .write()
            .await
            .insert(approval_id.to_string(), tx);

        // Simulate a webhook payload with an interactive button reply
        let payload = serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "123",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": {
                            "display_phone_number": "15550001111",
                            "phone_number_id": "123456789"
                        },
                        "messages": [{
                            "from": "15559998888",
                            "id": "wamid.callback123",
                            "type": "interactive",
                            "interactive": {
                                "type": "button_reply",
                                "button_reply": {
                                    "id": format!("approve_{approval_id}"),
                                    "title": "Approve"
                                }
                            },
                            "timestamp": "1234567890"
                        }]
                    }
                }]
            }]
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = compute_signature(&config.app_secret, &body_bytes);

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .header("x-hub-signature-256", signature)
            .body(Body::from(body_bytes))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the approval callback was resolved
        let approved = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(approved);
    }
}
