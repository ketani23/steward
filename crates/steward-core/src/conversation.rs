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

/// Maximum number of concurrent sessions. When exceeded, the oldest session
/// (by `last_activity`) is evicted to bound memory usage and prevent DoS.
const MAX_SESSIONS: usize = 1000;

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
    /// Returns an empty `Vec` if the session does not exist, has expired,
    /// or if the lock is poisoned.
    pub fn get_history(&self, key: &str) -> Vec<ChatMessage> {
        let sessions = match self.sessions.read() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "conversation store read lock poisoned");
                return vec![];
            }
        };
        match sessions.get(key) {
            Some(session) if !session.is_expired() => session.messages.clone(),
            _ => vec![],
        }
    }

    /// Append a user message and an assistant reply to a session.
    ///
    /// Creates the session if it does not exist. Trims to the last
    /// [`MAX_HISTORY`] messages. Expired sessions are garbage-collected
    /// on each call to this method. If the store would exceed [`MAX_SESSIONS`]
    /// after cleanup, the oldest session (by `last_activity`) is evicted to
    /// prevent unbounded memory growth (memory DoS).
    pub fn store_turn(&self, key: &str, user_message: String, assistant_reply: String) {
        let mut sessions = match self.sessions.write() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "conversation store write lock poisoned");
                return;
            }
        };

        // Lazy cleanup: remove expired sessions on every write.
        sessions.retain(|_, v| !v.is_expired());

        // Cap total session count: evict the least-recently-active session when
        // we would exceed MAX_SESSIONS and the key is not already present.
        if sessions.len() >= MAX_SESSIONS && !sessions.contains_key(key) {
            if let Some(oldest_key) = sessions
                .iter()
                .min_by_key(|(_, v)| v.last_activity)
                .map(|(k, _)| k.clone())
            {
                sessions.remove(&oldest_key);
                tracing::warn!(
                    evicted_key = %oldest_key,
                    max_sessions = MAX_SESSIONS,
                    "Session cap reached — evicted oldest session"
                );
            }
        }

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

    #[test]
    fn test_session_cap_evicts_oldest_on_overflow() {
        let store = make_store();

        // Fill up to MAX_SESSIONS.
        for i in 0..MAX_SESSIONS {
            store.store_turn(
                &format!("session:{i}"),
                format!("msg {i}"),
                format!("reply {i}"),
            );
        }

        // At MAX_SESSIONS, adding a new key should evict the oldest.
        store.store_turn(
            "session:new",
            "new msg".to_string(),
            "new reply".to_string(),
        );

        // The new session must exist.
        assert!(!store.get_history("session:new").is_empty());

        // Total session count must not exceed MAX_SESSIONS.
        let count = store.sessions.read().unwrap().len();
        assert!(
            count <= MAX_SESSIONS,
            "Session count {count} exceeds MAX_SESSIONS {MAX_SESSIONS}"
        );
    }

    #[test]
    fn test_existing_session_not_evicted_on_update() {
        let store = make_store();

        // Fill to MAX_SESSIONS-1 other sessions, then add "session:keep" as the
        // MAX_SESSIONS-th entry so it is present when we update it.
        for i in 0..(MAX_SESSIONS - 1) {
            store.store_turn(
                &format!("other:{i}"),
                format!("msg {i}"),
                format!("reply {i}"),
            );
        }
        store.store_turn("session:keep", "initial".to_string(), "ok".to_string());

        // Store is now at capacity. Updating an existing key must not trigger
        // eviction (the cap guard only runs when the key is new).
        store.store_turn(
            "session:keep",
            "follow-up".to_string(),
            "got it".to_string(),
        );
        let history = store.get_history("session:keep");
        assert_eq!(
            history.len(),
            4,
            "Existing session should still have its messages"
        );
    }
}
