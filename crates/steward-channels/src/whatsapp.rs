//! WhatsApp Business API channel adapter.
//!
//! Handles WhatsApp communication:
//! - Webhook endpoint for inbound messages (axum HTTP server)
//! - Webhook signature verification (HMAC-SHA256)
//! - Outbound message sending via Business Cloud API
//! - Interactive approval buttons for human-in-the-loop
//!
//! See `docs/architecture.md` section 10 for channel requirements.

// TODO: Implement ChannelAdapter trait for WhatsApp
