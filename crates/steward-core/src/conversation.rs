//! In-memory conversation history store.
//!
//! Tracks per-session message history for multi-turn conversations.
//! Sessions are identified by a compound key of channel + sender and
//! expire after 1 hour of inactivity.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use steward_types::actions::{ChatMessage, ChatRole};

/// Maximum number of messages to retain per session.
const MAX_HISTORY: usize = 20;

/// How long a session can be idle before it is considered expired.
const SESSION_TTL: Duration = Duration::from_secs(3600);

/// A single conversation session.
struct Session {
    /// Ordered list of messages (oldest first).
    messages: Vec<ChatMessage>,
    /// Wall-clock time of the most recent activity.
    last_activity: Instant,
}

impl Session {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            last_activity: Instant::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > SESSION_TTL
    }
}

/// Shared, thread-safe store of per-session conversation histories.
///
/// Sessions are keyed by `"<channel>:<sender>"` and hold the last
/// [`MAX_HISTORY`] messages. Expired sessions (idle > 1 hour) are cleaned
/// up lazily on each write.
pub struct ConversationStore {
    sessions: RwLock<HashMap<String, Session>>,
}

impl ConversationStore {
    /// Create a new, empty conversation store.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Retrieve the recent message history for a session.
    ///
    /// Returns a cloned snapshot of stored messages (oldest-first).
    /// Returns an empty `Vec` if the session does not exist or has expired.
    pub fn get_history(&self, key: &str) -> Vec<ChatMessage> {
        let sessions = self.sessions.read().unwrap();
        match sessions.get(key) {
            Some(session) if !session.is_expired() => session.messages.clone(),
            _ => vec![],
        }
    }

    /// Append a user message and an assistant reply to a session.
    ///
    /// Creates the session if it does not exist. Trims to the last
    /// [`MAX_HISTORY`] messages. Expired sessions are garbage-collected
    /// on each call to this method.
    pub fn store_turn(&self, key: &str, user_message: String, assistant_reply: String) {
        let mut sessions = self.sessions.write().unwrap();

        // Lazy cleanup: remove expired sessions on every write.
        sessions.retain(|_, v| !v.is_expired());

        let session = sessions.entry(key.to_string()).or_insert_with(Session::new);
        session.last_activity = Instant::now();

        session.messages.push(ChatMessage {
            role: ChatRole::User,
            content: user_message,
        });
        session.messages.push(ChatMessage {
            role: ChatRole::Assistant,
            content: assistant_reply,
        });

        // Keep only the last MAX_HISTORY messages.
        if session.messages.len() > MAX_HISTORY {
            let excess = session.messages.len() - MAX_HISTORY;
            session.messages.drain(..excess);
        }
    }
}

impl Default for ConversationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> ConversationStore {
        ConversationStore::new()
    }

    #[test]
    fn test_empty_store_returns_no_history() {
        let store = make_store();
        assert!(store.get_history("webchat:alice").is_empty());
    }

    #[test]
    fn test_store_turn_and_retrieve() {
        let store = make_store();
        store.store_turn(
            "webchat:alice",
            "Hello".to_string(),
            "Hi there!".to_string(),
        );
        let history = store.get_history("webchat:alice");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].content, "Hello");
        assert_eq!(history[0].role, ChatRole::User);
        assert_eq!(history[1].content, "Hi there!");
        assert_eq!(history[1].role, ChatRole::Assistant);
    }

    #[test]
    fn test_multiple_turns_accumulate() {
        let store = make_store();
        store.store_turn("webchat:alice", "Turn 1".to_string(), "Reply 1".to_string());
        store.store_turn("webchat:alice", "Turn 2".to_string(), "Reply 2".to_string());
        let history = store.get_history("webchat:alice");
        assert_eq!(history.len(), 4);
    }

    #[test]
    fn test_history_trimmed_to_max() {
        let store = make_store();
        // Store 11 turns (22 messages) — should be trimmed to MAX_HISTORY=20.
        for i in 0..11 {
            store.store_turn(
                "webchat:alice",
                format!("User message {i}"),
                format!("Assistant reply {i}"),
            );
        }
        let history = store.get_history("webchat:alice");
        assert_eq!(history.len(), MAX_HISTORY);
        // The first two messages (turn 0) should have been dropped.
        assert_eq!(history[0].content, "User message 1");
    }

    #[test]
    fn test_different_sessions_are_isolated() {
        let store = make_store();
        store.store_turn(
            "webchat:alice",
            "Alice's message".to_string(),
            "Reply to Alice".to_string(),
        );
        store.store_turn(
            "telegram:bob",
            "Bob's message".to_string(),
            "Reply to Bob".to_string(),
        );
        let alice = store.get_history("webchat:alice");
        let bob = store.get_history("telegram:bob");
        assert_eq!(alice.len(), 2);
        assert_eq!(bob.len(), 2);
        assert_eq!(alice[0].content, "Alice's message");
        assert_eq!(bob[0].content, "Bob's message");
    }

    #[test]
    fn test_unknown_session_returns_empty() {
        let store = make_store();
        store.store_turn("webchat:alice", "Hello".to_string(), "Hi".to_string());
        // Different channel key → should get nothing.
        assert!(store.get_history("telegram:alice").is_empty());
    }
}
