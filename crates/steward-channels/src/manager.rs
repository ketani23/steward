//! Channel manager -- multiplexes messages across communication channels.
//!
//! The [`ChannelManager`] routes inbound messages from any registered channel
//! adapter into a single merged stream, and routes outbound messages to the
//! correct channel based on the message's `channel` field. It also tracks
//! which channel each conversation originated on so that approval requests
//! are routed back to the right place.
//!
//! The manager itself implements [`ChannelAdapter`], so the agent core can
//! treat it as a single channel without knowing about the underlying
//! multiplexing.
//!
//! See `docs/architecture.md` section 10 for channel architecture.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, RwLock};

use steward_types::actions::*;
use steward_types::errors::StewardError;
use steward_types::traits::ChannelAdapter;

/// Channel manager that multiplexes messages across multiple channel adapters.
///
/// Stores registered adapters keyed by [`ChannelType`] and provides:
/// - Unified inbound message stream from all channels
/// - Outbound routing to the correct channel
/// - Conversation-to-channel tracking for approval routing
/// - Default channel fallback for messages without explicit routing
///
/// Thread-safe: channels can be registered while the manager is running.
pub struct ChannelManager {
    /// Registered channel adapters, keyed by channel type.
    adapters: Arc<RwLock<HashMap<ChannelType, Arc<dyn ChannelAdapter>>>>,

    /// Maps conversation sender identifiers to the channel they originated on.
    /// Used to route approval requests back to the correct channel.
    conversation_channels: Arc<RwLock<HashMap<String, ChannelType>>>,

    /// The default channel type used when an outbound message does not specify
    /// a channel or when the originating channel is unknown.
    default_channel: Arc<RwLock<Option<ChannelType>>>,

    /// Sender for the merged inbound message stream. Forwarding tasks
    /// send messages here from individual channel receivers.
    merged_tx: mpsc::Sender<InboundMessage>,

    /// Receiver end of the merged inbound stream. Taken once by
    /// [`start_listening`].
    merged_rx: tokio::sync::Mutex<Option<mpsc::Receiver<InboundMessage>>>,
}

impl ChannelManager {
    /// Create a new channel manager.
    ///
    /// The `buffer_size` parameter controls the capacity of the merged inbound
    /// message channel.
    pub fn new(buffer_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(buffer_size);
        Self {
            adapters: Arc::new(RwLock::new(HashMap::new())),
            conversation_channels: Arc::new(RwLock::new(HashMap::new())),
            default_channel: Arc::new(RwLock::new(None)),
            merged_tx: tx,
            merged_rx: tokio::sync::Mutex::new(Some(rx)),
        }
    }

    /// Register a channel adapter for a given channel type.
    ///
    /// If an adapter for this channel type already exists, it is replaced.
    /// The first registered channel automatically becomes the default unless
    /// one has already been set explicitly.
    pub async fn register_channel(
        &self,
        channel_type: ChannelType,
        adapter: Arc<dyn ChannelAdapter>,
    ) {
        let mut adapters = self.adapters.write().await;
        adapters.insert(channel_type, adapter);

        // Auto-set default channel to the first registered channel.
        let mut default = self.default_channel.write().await;
        if default.is_none() {
            *default = Some(channel_type);
        }
    }

    /// Set the default channel used for outbound messages without explicit routing.
    ///
    /// Returns an error if the specified channel type is not registered.
    pub async fn set_default_channel(&self, channel_type: ChannelType) -> Result<(), StewardError> {
        let adapters = self.adapters.read().await;
        if !adapters.contains_key(&channel_type) {
            return Err(StewardError::Channel(format!(
                "Cannot set default channel to {channel_type:?}: not registered"
            )));
        }
        let mut default = self.default_channel.write().await;
        *default = Some(channel_type);
        Ok(())
    }

    /// Get the current default channel type, if one is set.
    pub async fn default_channel(&self) -> Option<ChannelType> {
        *self.default_channel.read().await
    }

    /// Get the list of registered channel types.
    pub async fn registered_channels(&self) -> Vec<ChannelType> {
        self.adapters.read().await.keys().copied().collect()
    }

    /// Look up which channel a given sender's conversation is on.
    pub async fn channel_for_sender(&self, sender: &str) -> Option<ChannelType> {
        self.conversation_channels.read().await.get(sender).copied()
    }

    /// Record that a sender's conversation is on a specific channel.
    ///
    /// This is called automatically when inbound messages arrive through
    /// the merged stream, but can also be set manually if needed.
    pub async fn track_conversation(&self, sender: &str, channel: ChannelType) {
        self.conversation_channels
            .write()
            .await
            .insert(sender.to_string(), channel);
    }

    /// Resolve which adapter to use for an outbound message.
    ///
    /// Priority:
    /// 1. The channel specified in the outbound message
    /// 2. The channel the sender's conversation is on
    /// 3. The default channel
    async fn resolve_adapter(
        &self,
        channel: ChannelType,
        recipient: &str,
    ) -> Result<Arc<dyn ChannelAdapter>, StewardError> {
        let adapters = self.adapters.read().await;

        // Try the explicitly requested channel first.
        if let Some(adapter) = adapters.get(&channel) {
            return Ok(Arc::clone(adapter));
        }

        // Try the channel the conversation is on.
        if let Some(conv_channel) = self.conversation_channels.read().await.get(recipient) {
            if let Some(adapter) = adapters.get(conv_channel) {
                return Ok(Arc::clone(adapter));
            }
        }

        // Fall back to default channel.
        if let Some(default) = *self.default_channel.read().await {
            if let Some(adapter) = adapters.get(&default) {
                return Ok(Arc::clone(adapter));
            }
        }

        Err(StewardError::Channel(format!(
            "No adapter found for channel {channel:?} and no default channel available"
        )))
    }

    /// Start forwarding inbound messages from a single channel adapter
    /// into the merged stream.
    ///
    /// Spawns a background task that reads from the adapter's receiver and
    /// forwards messages to the merged channel, tracking conversation origins.
    fn spawn_forwarder(
        &self,
        mut rx: mpsc::Receiver<InboundMessage>,
        merged_tx: mpsc::Sender<InboundMessage>,
        conversation_channels: Arc<RwLock<HashMap<String, ChannelType>>>,
    ) {
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                // Track which channel this sender's conversation is on.
                conversation_channels
                    .write()
                    .await
                    .insert(msg.sender.clone(), msg.channel);

                if merged_tx.send(msg).await.is_err() {
                    tracing::warn!("Merged inbound channel closed; stopping forwarder");
                    break;
                }
            }
        });
    }
}

#[async_trait]
impl ChannelAdapter for ChannelManager {
    /// Send a message through the appropriate channel.
    ///
    /// Routes to the channel specified in the message's `channel` field.
    /// Falls back to the conversation's originating channel, then to the
    /// default channel.
    async fn send_message(&self, message: OutboundMessage) -> Result<(), StewardError> {
        let adapter = self
            .resolve_adapter(message.channel, &message.recipient)
            .await?;
        adapter.send_message(message).await
    }

    /// Start listening on ALL registered channels.
    ///
    /// Calls `start_listening()` on every registered adapter and merges their
    /// inbound message streams into a single [`mpsc::Receiver<InboundMessage>`].
    ///
    /// Can only be called once. Subsequent calls return an error.
    async fn start_listening(&mut self) -> Result<mpsc::Receiver<InboundMessage>, StewardError> {
        let rx =
            self.merged_rx.lock().await.take().ok_or_else(|| {
                StewardError::Channel("start_listening already called".to_string())
            })?;

        // Collect all adapters so we can call start_listening on each.
        // We need mutable access to each adapter, so we clone the Arc and
        // use Arc::get_mut or downcast. Since ChannelAdapter requires &mut self
        // for start_listening, we need to work with the adapters directly.
        //
        // We take the adapters out temporarily to get mutable access through Arc.
        let adapters = self.adapters.read().await;
        let channel_types: Vec<ChannelType> = adapters.keys().copied().collect();
        drop(adapters);

        for channel_type in channel_types {
            let mut adapters = self.adapters.write().await;
            if let Some(adapter) = adapters.get_mut(&channel_type) {
                // Get mutable access through Arc::get_mut. This works because
                // during start_listening, no other references should exist.
                if let Some(adapter_mut) = Arc::get_mut(adapter) {
                    match adapter_mut.start_listening().await {
                        Ok(channel_rx) => {
                            self.spawn_forwarder(
                                channel_rx,
                                self.merged_tx.clone(),
                                Arc::clone(&self.conversation_channels),
                            );
                            tracing::info!("Started listening on channel: {channel_type:?}");
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to start listening on channel {channel_type:?}: {e}"
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        "Cannot start listening on {channel_type:?}: adapter has multiple references"
                    );
                }
            }
        }

        Ok(rx)
    }

    /// Request human approval, routing to the channel specified in the request.
    ///
    /// Falls back to the conversation's originating channel if the specified
    /// channel is not available.
    async fn request_approval(
        &self,
        request: ApprovalRequest,
    ) -> Result<ApprovalResponse, StewardError> {
        let adapter = self
            .resolve_adapter(request.channel, &request.proposal.parameters.to_string())
            .await?;
        adapter.request_approval(request).await
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    // ========== Mock Channel Adapter ==========

    /// A mock channel adapter for testing the channel manager.
    ///
    /// Records sent messages and approval requests, and can produce
    /// inbound messages via a sender handle.
    struct MockAdapter {
        /// Which channel type this mock represents.
        channel_type: ChannelType,
        /// Counter of messages sent through this adapter.
        send_count: Arc<AtomicUsize>,
        /// Messages sent through this adapter (for assertion).
        sent_messages: Arc<RwLock<Vec<OutboundMessage>>>,
        /// Approval requests received by this adapter.
        approval_requests: Arc<RwLock<Vec<ApprovalRequest>>>,
        /// Sender for injecting inbound messages in tests.
        inbound_tx: Option<mpsc::Sender<InboundMessage>>,
        /// Receiver that start_listening returns.
        inbound_rx: tokio::sync::Mutex<Option<mpsc::Receiver<InboundMessage>>>,
        /// Whether request_approval should return approved or rejected.
        approval_result: bool,
    }

    impl MockAdapter {
        fn new(channel_type: ChannelType, approval_result: bool) -> Self {
            let (tx, rx) = mpsc::channel(64);
            Self {
                channel_type,
                send_count: Arc::new(AtomicUsize::new(0)),
                sent_messages: Arc::new(RwLock::new(Vec::new())),
                approval_requests: Arc::new(RwLock::new(Vec::new())),
                inbound_tx: Some(tx),
                inbound_rx: tokio::sync::Mutex::new(Some(rx)),
                approval_result,
            }
        }

        /// Get a sender handle to inject inbound messages for testing.
        fn inbound_sender(&self) -> Option<mpsc::Sender<InboundMessage>> {
            self.inbound_tx.clone()
        }

        /// Get the count of messages sent.
        fn send_count(&self) -> usize {
            self.send_count.load(Ordering::SeqCst)
        }

        /// Get a clone of all sent messages.
        async fn sent_messages(&self) -> Vec<OutboundMessage> {
            self.sent_messages.read().await.clone()
        }

        /// Get a clone of all approval requests.
        async fn approval_requests(&self) -> Vec<ApprovalRequest> {
            self.approval_requests.read().await.clone()
        }
    }

    #[async_trait]
    impl ChannelAdapter for MockAdapter {
        async fn send_message(&self, message: OutboundMessage) -> Result<(), StewardError> {
            self.send_count.fetch_add(1, Ordering::SeqCst);
            self.sent_messages.write().await.push(message);
            Ok(())
        }

        async fn start_listening(
            &mut self,
        ) -> Result<mpsc::Receiver<InboundMessage>, StewardError> {
            self.inbound_rx
                .lock()
                .await
                .take()
                .ok_or_else(|| StewardError::Channel("start_listening already called".to_string()))
        }

        async fn request_approval(
            &self,
            request: ApprovalRequest,
        ) -> Result<ApprovalResponse, StewardError> {
            self.approval_requests.write().await.push(request);
            Ok(ApprovalResponse {
                approved: self.approval_result,
                message: Some(format!(
                    "Mock {:?} approval: {}",
                    self.channel_type, self.approval_result
                )),
                timestamp: Utc::now(),
            })
        }
    }

    // ========== Test Helpers ==========

    fn make_outbound(recipient: &str, text: &str, channel: ChannelType) -> OutboundMessage {
        OutboundMessage {
            recipient: recipient.to_string(),
            text: text.to_string(),
            channel,
            metadata: serde_json::json!({}),
        }
    }

    fn make_inbound(sender: &str, text: &str, channel: ChannelType) -> InboundMessage {
        InboundMessage {
            id: Uuid::new_v4(),
            text: text.to_string(),
            channel,
            sender: sender.to_string(),
            timestamp: Utc::now(),
            metadata: serde_json::json!({}),
        }
    }

    fn make_approval_request(channel: ChannelType) -> ApprovalRequest {
        ApprovalRequest {
            proposal: ActionProposal {
                id: Uuid::new_v4(),
                tool_name: "test.action".to_string(),
                parameters: serde_json::json!({"key": "value"}),
                reasoning: "Test reasoning".to_string(),
                user_message_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            },
            guardian_verdict: GuardianVerdict {
                decision: GuardianDecision::EscalateToHuman,
                reasoning: "Needs review".to_string(),
                confidence: 0.8,
                injection_indicators: vec![],
                timestamp: Utc::now(),
            },
            permission_tier: PermissionTier::HumanApproval,
            channel,
            timeout_secs: 30,
        }
    }

    // ========== Registration Tests ==========

    #[tokio::test]
    async fn test_register_single_channel() {
        let manager = ChannelManager::new(64);
        let adapter = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));

        manager
            .register_channel(ChannelType::WhatsApp, adapter)
            .await;

        let channels = manager.registered_channels().await;
        assert_eq!(channels.len(), 1);
        assert!(channels.contains(&ChannelType::WhatsApp));
    }

    #[tokio::test]
    async fn test_register_multiple_channels() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let tg = Arc::new(MockAdapter::new(ChannelType::Telegram, true));
        let sl = Arc::new(MockAdapter::new(ChannelType::Slack, true));

        manager.register_channel(ChannelType::WhatsApp, wa).await;
        manager.register_channel(ChannelType::Telegram, tg).await;
        manager.register_channel(ChannelType::Slack, sl).await;

        let channels = manager.registered_channels().await;
        assert_eq!(channels.len(), 3);
        assert!(channels.contains(&ChannelType::WhatsApp));
        assert!(channels.contains(&ChannelType::Telegram));
        assert!(channels.contains(&ChannelType::Slack));
    }

    #[tokio::test]
    async fn test_first_registered_becomes_default() {
        let manager = ChannelManager::new(64);
        assert!(manager.default_channel().await.is_none());

        let adapter = Arc::new(MockAdapter::new(ChannelType::Telegram, true));
        manager
            .register_channel(ChannelType::Telegram, adapter)
            .await;

        assert_eq!(manager.default_channel().await, Some(ChannelType::Telegram));
    }

    #[tokio::test]
    async fn test_first_registered_stays_default_after_more_registrations() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let tg = Arc::new(MockAdapter::new(ChannelType::Telegram, true));

        manager.register_channel(ChannelType::WhatsApp, wa).await;
        manager.register_channel(ChannelType::Telegram, tg).await;

        // Default should still be WhatsApp (first registered).
        assert_eq!(manager.default_channel().await, Some(ChannelType::WhatsApp));
    }

    #[tokio::test]
    async fn test_set_default_channel() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let tg = Arc::new(MockAdapter::new(ChannelType::Telegram, true));

        manager.register_channel(ChannelType::WhatsApp, wa).await;
        manager.register_channel(ChannelType::Telegram, tg).await;

        manager
            .set_default_channel(ChannelType::Telegram)
            .await
            .unwrap();
        assert_eq!(manager.default_channel().await, Some(ChannelType::Telegram));
    }

    #[tokio::test]
    async fn test_set_default_channel_unregistered_fails() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        manager.register_channel(ChannelType::WhatsApp, wa).await;

        let result = manager.set_default_channel(ChannelType::Slack).await;
        assert!(result.is_err());
    }

    // ========== Message Routing Tests ==========

    #[tokio::test]
    async fn test_send_message_routes_to_correct_channel() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let tg = Arc::new(MockAdapter::new(ChannelType::Telegram, true));

        let wa_clone = Arc::clone(&wa);
        let tg_clone = Arc::clone(&tg);

        manager.register_channel(ChannelType::WhatsApp, wa).await;
        manager.register_channel(ChannelType::Telegram, tg).await;

        // Send to WhatsApp.
        let msg = make_outbound("alice", "Hello WA", ChannelType::WhatsApp);
        manager.send_message(msg).await.unwrap();

        // Send to Telegram.
        let msg = make_outbound("bob", "Hello TG", ChannelType::Telegram);
        manager.send_message(msg).await.unwrap();

        assert_eq!(wa_clone.send_count(), 1);
        assert_eq!(tg_clone.send_count(), 1);

        let wa_msgs = wa_clone.sent_messages().await;
        assert_eq!(wa_msgs[0].text, "Hello WA");
        assert_eq!(wa_msgs[0].recipient, "alice");

        let tg_msgs = tg_clone.sent_messages().await;
        assert_eq!(tg_msgs[0].text, "Hello TG");
        assert_eq!(tg_msgs[0].recipient, "bob");
    }

    #[tokio::test]
    async fn test_send_message_fallback_to_default_channel() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let wa_clone = Arc::clone(&wa);

        manager.register_channel(ChannelType::WhatsApp, wa).await;

        // Try to send to Slack (not registered). The manager should fall back
        // to the default channel (WhatsApp).
        let msg = make_outbound("charlie", "Fallback", ChannelType::Slack);
        manager.send_message(msg).await.unwrap();

        assert_eq!(wa_clone.send_count(), 1);
        let msgs = wa_clone.sent_messages().await;
        assert_eq!(msgs[0].text, "Fallback");
    }

    #[tokio::test]
    async fn test_send_message_no_adapter_no_default_fails() {
        let manager = ChannelManager::new(64);

        // No adapters registered at all.
        let msg = make_outbound("nobody", "Lost", ChannelType::Slack);
        let result = manager.send_message(msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_message_fallback_to_conversation_channel() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let tg = Arc::new(MockAdapter::new(ChannelType::Telegram, true));

        let tg_clone = Arc::clone(&tg);

        manager.register_channel(ChannelType::WhatsApp, wa).await;
        manager.register_channel(ChannelType::Telegram, tg).await;

        // Track that "dave" is on Telegram.
        manager
            .track_conversation("dave", ChannelType::Telegram)
            .await;

        // Send to a channel that is not registered (WebChat), but "dave" is
        // tracked on Telegram, so it should fall back to Telegram.
        let msg = make_outbound("dave", "Conversation fallback", ChannelType::WebChat);
        manager.send_message(msg).await.unwrap();

        assert_eq!(tg_clone.send_count(), 1);
    }

    // ========== Merged Inbound Stream Tests ==========

    #[tokio::test]
    async fn test_merged_inbound_stream_from_multiple_channels() {
        let mut manager = ChannelManager::new(64);

        let wa_adapter = MockAdapter::new(ChannelType::WhatsApp, true);
        let tg_adapter = MockAdapter::new(ChannelType::Telegram, true);

        let wa_tx = wa_adapter.inbound_sender().unwrap();
        let tg_tx = tg_adapter.inbound_sender().unwrap();

        manager
            .register_channel(ChannelType::WhatsApp, Arc::new(wa_adapter))
            .await;
        manager
            .register_channel(ChannelType::Telegram, Arc::new(tg_adapter))
            .await;

        let mut rx = manager.start_listening().await.unwrap();

        // Inject messages into both channels.
        wa_tx
            .send(make_inbound(
                "alice",
                "From WhatsApp",
                ChannelType::WhatsApp,
            ))
            .await
            .unwrap();
        tg_tx
            .send(make_inbound("bob", "From Telegram", ChannelType::Telegram))
            .await
            .unwrap();

        // Collect both messages from the merged stream.
        let mut messages = Vec::new();
        for _ in 0..2 {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            messages.push(msg);
        }

        // Both messages should appear in the merged stream.
        let texts: Vec<&str> = messages.iter().map(|m| m.text.as_str()).collect();
        assert!(texts.contains(&"From WhatsApp"));
        assert!(texts.contains(&"From Telegram"));
    }

    #[tokio::test]
    async fn test_inbound_messages_track_conversation_channel() {
        let mut manager = ChannelManager::new(64);

        let adapter = MockAdapter::new(ChannelType::WhatsApp, true);
        let tx = adapter.inbound_sender().unwrap();

        manager
            .register_channel(ChannelType::WhatsApp, Arc::new(adapter))
            .await;

        let mut rx = manager.start_listening().await.unwrap();

        // Inject an inbound message.
        tx.send(make_inbound("eve", "Hello", ChannelType::WhatsApp))
            .await
            .unwrap();

        let _msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Give the forwarder a moment to update the conversation map.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // The manager should now know that "eve" is on WhatsApp.
        assert_eq!(
            manager.channel_for_sender("eve").await,
            Some(ChannelType::WhatsApp)
        );
    }

    #[tokio::test]
    async fn test_start_listening_twice_fails() {
        let mut manager = ChannelManager::new(64);
        let _ = manager.start_listening().await.unwrap();
        let result = manager.start_listening().await;
        assert!(result.is_err());
    }

    // ========== Approval Routing Tests ==========

    #[tokio::test]
    async fn test_approval_routes_to_correct_channel() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let tg = Arc::new(MockAdapter::new(ChannelType::Telegram, false));

        let wa_clone = Arc::clone(&wa);
        let tg_clone = Arc::clone(&tg);

        manager.register_channel(ChannelType::WhatsApp, wa).await;
        manager.register_channel(ChannelType::Telegram, tg).await;

        // Request approval on WhatsApp -- should be approved (mock returns true).
        let wa_request = make_approval_request(ChannelType::WhatsApp);
        let wa_response = manager.request_approval(wa_request).await.unwrap();
        assert!(wa_response.approved);

        // Request approval on Telegram -- should be rejected (mock returns false).
        let tg_request = make_approval_request(ChannelType::Telegram);
        let tg_response = manager.request_approval(tg_request).await.unwrap();
        assert!(!tg_response.approved);

        // Verify each adapter received exactly one approval request.
        assert_eq!(wa_clone.approval_requests().await.len(), 1);
        assert_eq!(tg_clone.approval_requests().await.len(), 1);
    }

    #[tokio::test]
    async fn test_approval_routes_to_originating_channel() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let tg = Arc::new(MockAdapter::new(ChannelType::Telegram, false));

        let wa_clone = Arc::clone(&wa);
        let tg_clone = Arc::clone(&tg);

        manager.register_channel(ChannelType::WhatsApp, wa).await;
        manager.register_channel(ChannelType::Telegram, tg).await;

        // Request on WhatsApp.
        let request = make_approval_request(ChannelType::WhatsApp);
        let response = manager.request_approval(request).await.unwrap();
        assert!(response.approved);

        // Only WhatsApp should have received the request.
        assert_eq!(wa_clone.approval_requests().await.len(), 1);
        assert_eq!(tg_clone.approval_requests().await.len(), 0);
    }

    #[tokio::test]
    async fn test_approval_fallback_to_default_channel() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let wa_clone = Arc::clone(&wa);

        manager.register_channel(ChannelType::WhatsApp, wa).await;

        // Request on Slack (not registered). Should fall back to WhatsApp.
        let request = make_approval_request(ChannelType::Slack);
        let response = manager.request_approval(request).await.unwrap();
        assert!(response.approved);

        assert_eq!(wa_clone.approval_requests().await.len(), 1);
    }

    // ========== Default Channel Fallback Tests ==========

    #[tokio::test]
    async fn test_default_channel_is_none_initially() {
        let manager = ChannelManager::new(64);
        assert!(manager.default_channel().await.is_none());
    }

    #[tokio::test]
    async fn test_explicit_default_overrides_auto() {
        let manager = ChannelManager::new(64);

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let tg = Arc::new(MockAdapter::new(ChannelType::Telegram, true));

        manager.register_channel(ChannelType::WhatsApp, wa).await;
        manager.register_channel(ChannelType::Telegram, tg).await;

        // Default auto-set to WhatsApp.
        assert_eq!(manager.default_channel().await, Some(ChannelType::WhatsApp));

        // Explicitly set default to Telegram.
        manager
            .set_default_channel(ChannelType::Telegram)
            .await
            .unwrap();
        assert_eq!(manager.default_channel().await, Some(ChannelType::Telegram));
    }

    #[tokio::test]
    async fn test_replace_adapter_for_same_channel_type() {
        let manager = ChannelManager::new(64);

        let wa1 = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let wa2 = Arc::new(MockAdapter::new(ChannelType::WhatsApp, false));
        let wa2_clone = Arc::clone(&wa2);

        manager.register_channel(ChannelType::WhatsApp, wa1).await;
        manager.register_channel(ChannelType::WhatsApp, wa2).await;

        // Only one channel should be registered.
        assert_eq!(manager.registered_channels().await.len(), 1);

        // Sending should use the second adapter.
        let msg = make_outbound("alice", "Hello", ChannelType::WhatsApp);
        manager.send_message(msg).await.unwrap();
        assert_eq!(wa2_clone.send_count(), 1);
    }

    // ========== Concurrency / Thread Safety Tests ==========

    #[tokio::test]
    async fn test_concurrent_sends_to_different_channels() {
        let manager = Arc::new(ChannelManager::new(64));

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let tg = Arc::new(MockAdapter::new(ChannelType::Telegram, true));

        let wa_clone = Arc::clone(&wa);
        let tg_clone = Arc::clone(&tg);

        manager.register_channel(ChannelType::WhatsApp, wa).await;
        manager.register_channel(ChannelType::Telegram, tg).await;

        let manager_wa = Arc::clone(&manager);
        let manager_tg = Arc::clone(&manager);

        let wa_handle = tokio::spawn(async move {
            for i in 0..10 {
                let msg = make_outbound("alice", &format!("WA msg {i}"), ChannelType::WhatsApp);
                manager_wa.send_message(msg).await.unwrap();
            }
        });

        let tg_handle = tokio::spawn(async move {
            for i in 0..10 {
                let msg = make_outbound("bob", &format!("TG msg {i}"), ChannelType::Telegram);
                manager_tg.send_message(msg).await.unwrap();
            }
        });

        wa_handle.await.unwrap();
        tg_handle.await.unwrap();

        assert_eq!(wa_clone.send_count(), 10);
        assert_eq!(tg_clone.send_count(), 10);
    }

    #[tokio::test]
    async fn test_register_channel_while_sending() {
        let manager = Arc::new(ChannelManager::new(64));

        let wa = Arc::new(MockAdapter::new(ChannelType::WhatsApp, true));
        let wa_clone = Arc::clone(&wa);

        manager.register_channel(ChannelType::WhatsApp, wa).await;

        let manager_send = Arc::clone(&manager);
        let manager_reg = Arc::clone(&manager);

        // Concurrently send messages and register a new channel.
        let send_handle = tokio::spawn(async move {
            for i in 0..5 {
                let msg = make_outbound("alice", &format!("msg {i}"), ChannelType::WhatsApp);
                manager_send.send_message(msg).await.unwrap();
            }
        });

        let reg_handle = tokio::spawn(async move {
            let tg = Arc::new(MockAdapter::new(ChannelType::Telegram, true));
            manager_reg
                .register_channel(ChannelType::Telegram, tg)
                .await;
        });

        send_handle.await.unwrap();
        reg_handle.await.unwrap();

        assert_eq!(wa_clone.send_count(), 5);
        assert_eq!(manager.registered_channels().await.len(), 2);
    }
}
