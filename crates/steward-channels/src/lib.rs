/// Communication channel adapters for the Steward agent framework.
///
/// Each adapter implements the ChannelAdapter trait for a specific platform:
/// - **Manager**: Channel multiplexer that routes messages to/from adapters
/// - **WhatsApp**: WhatsApp Business API adapter
/// - **Telegram**: Telegram Bot API adapter
/// - **Confirmation**: Human-in-the-loop approval UX
pub mod confirmation;
pub mod manager;
pub mod telegram;
pub mod whatsapp;
