//! Intent classification and message routing.
//!
//! Determines how to handle an inbound message:
//! - Conversational response (no tool use needed)
//! - Tool-assisted response (LLM may call tools)
//!
//! The router uses heuristic analysis of the message text to classify intent.
//! This avoids an extra LLM call for obvious cases while still routing ambiguous
//! messages through the full tool-use pipeline.
//!
//! See `docs/architecture.md` section 6 for the generalist architecture.

use serde::{Deserialize, Serialize};

/// Classified intent for an inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageIntent {
    /// Pure conversation — no tools needed. The LLM can respond directly.
    Conversation,
    /// The message likely requires tool use (actions, lookups, modifications).
    ToolAssisted,
}

/// Heuristic router that classifies inbound messages by intent.
///
/// Uses keyword and pattern analysis to determine whether a message is
/// conversational or requires tool use. Designed to be fast and conservative:
/// ambiguous messages are routed to `ToolAssisted` so the LLM can decide.
#[derive(Debug, Clone)]
pub struct MessageRouter {
    /// Action verbs that strongly suggest tool use.
    action_verbs: Vec<&'static str>,
    /// Prefixes that indicate conversational intent.
    conversation_prefixes: Vec<&'static str>,
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageRouter {
    /// Create a new router with default heuristic patterns.
    pub fn new() -> Self {
        Self {
            action_verbs: vec![
                "send",
                "create",
                "delete",
                "update",
                "modify",
                "add",
                "remove",
                "schedule",
                "book",
                "order",
                "buy",
                "purchase",
                "cancel",
                "submit",
                "upload",
                "download",
                "install",
                "deploy",
                "run",
                "execute",
                "search",
                "find",
                "look up",
                "lookup",
                "check",
                "fetch",
                "get",
                "set",
                "configure",
                "enable",
                "disable",
                "turn on",
                "turn off",
                "open",
                "close",
                "start",
                "stop",
                "restart",
                "move",
                "copy",
                "rename",
                "list",
                "show me",
                "read",
                "write",
                "edit",
                "draft",
            ],
            conversation_prefixes: vec![
                "hi",
                "hello",
                "hey",
                "thanks",
                "thank you",
                "good morning",
                "good afternoon",
                "good evening",
                "good night",
                "bye",
                "goodbye",
                "how are you",
                "what are you",
                "who are you",
                "tell me about yourself",
                "nice to meet",
                "pleased to meet",
            ],
        }
    }

    /// Classify a message's intent using heuristic analysis.
    ///
    /// The classification logic:
    /// 1. If the message matches a greeting/conversational prefix → Conversation
    /// 2. If the message contains action verbs → ToolAssisted
    /// 3. If the message is a question (contains "?") → ToolAssisted (might need lookup)
    /// 4. If the message references a tool/service by name → ToolAssisted
    /// 5. Default: Conversation (pure chat)
    pub fn classify(&self, message: &str) -> MessageIntent {
        let lower = message.to_lowercase();
        let trimmed = lower.trim();

        // Empty messages are conversational
        if trimmed.is_empty() {
            return MessageIntent::Conversation;
        }

        // Check for conversational prefixes first — these override action verbs
        for prefix in &self.conversation_prefixes {
            if trimmed.starts_with(prefix) && trimmed.len() < prefix.len() + 30 {
                // Short messages starting with greetings are conversational
                return MessageIntent::Conversation;
            }
        }

        // Check for action verbs — strong signal for tool use
        for verb in &self.action_verbs {
            if contains_word(trimmed, verb) {
                return MessageIntent::ToolAssisted;
            }
        }

        // Questions with specific keywords suggest tool-assisted responses
        if trimmed.contains('?') && has_specific_question_words(trimmed) {
            return MessageIntent::ToolAssisted;
        }

        // References to services or tool-like nouns
        if has_service_reference(trimmed) {
            return MessageIntent::ToolAssisted;
        }

        // Default to conversation for ambiguous messages
        MessageIntent::Conversation
    }
}

/// Check if a string contains a word or phrase as a whole token (not a substring).
fn contains_word(text: &str, word: &str) -> bool {
    // For multi-word phrases, just check contains
    if word.contains(' ') {
        return text.contains(word);
    }

    text.split_whitespace().any(|w| {
        // Strip common punctuation from the word boundary
        let cleaned = w.trim_matches(|c: char| c.is_ascii_punctuation());
        cleaned == word
    })
}

/// Check if the text contains question words that suggest a lookup is needed.
fn has_specific_question_words(text: &str) -> bool {
    let question_patterns = [
        "what time",
        "what is the",
        "what's the",
        "when is",
        "when does",
        "where is",
        "where does",
        "how much",
        "how many",
        "how do i",
        "how can i",
        "can you",
        "could you",
        "would you",
        "will you",
        "what's on my",
        "what is on my",
        "do i have",
    ];
    question_patterns.iter().any(|p| text.contains(p))
}

/// Check if the text references known services or tool domains.
fn has_service_reference(text: &str) -> bool {
    let services = [
        "email",
        "calendar",
        "spreadsheet",
        "google sheets",
        "gmail",
        "slack",
        "spotify",
        "file",
        "database",
        "api",
        "server",
        "docker",
        "kubernetes",
        "github",
        "git",
        "terminal",
        "shell",
        "browser",
        "website",
        "home assistant",
        "smart home",
    ];
    services.iter().any(|s| text.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> MessageRouter {
        MessageRouter::new()
    }

    // --- Conversational messages ---

    #[test]
    fn test_greeting_hello() {
        assert_eq!(router().classify("Hello!"), MessageIntent::Conversation);
    }

    #[test]
    fn test_greeting_hi() {
        assert_eq!(router().classify("Hi there"), MessageIntent::Conversation);
    }

    #[test]
    fn test_greeting_thanks() {
        assert_eq!(
            router().classify("Thanks for that!"),
            MessageIntent::Conversation
        );
    }

    #[test]
    fn test_greeting_good_morning() {
        assert_eq!(
            router().classify("Good morning!"),
            MessageIntent::Conversation
        );
    }

    #[test]
    fn test_who_are_you() {
        assert_eq!(
            router().classify("Who are you?"),
            MessageIntent::Conversation
        );
    }

    #[test]
    fn test_empty_message() {
        assert_eq!(router().classify(""), MessageIntent::Conversation);
    }

    #[test]
    fn test_whitespace_only() {
        assert_eq!(router().classify("   "), MessageIntent::Conversation);
    }

    #[test]
    fn test_simple_chat() {
        assert_eq!(
            router().classify("That sounds interesting"),
            MessageIntent::Conversation
        );
    }

    // --- Tool-assisted messages ---

    #[test]
    fn test_send_email() {
        assert_eq!(
            router().classify("Send an email to John about the meeting"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_create_event() {
        assert_eq!(
            router().classify("Create a calendar event for tomorrow at 3pm"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_delete_file() {
        assert_eq!(
            router().classify("Delete the old backup file"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_search_request() {
        assert_eq!(
            router().classify("Search for restaurants nearby"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_question_with_lookup() {
        assert_eq!(
            router().classify("What time is my next meeting?"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_question_can_you() {
        assert_eq!(
            router().classify("Can you check my inbox?"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_service_reference_email() {
        assert_eq!(
            router().classify("I need to access my email"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_service_reference_calendar() {
        assert_eq!(
            router().classify("What's on my calendar today?"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_schedule_action() {
        assert_eq!(
            router().classify("Schedule a meeting with Sarah"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_run_command() {
        assert_eq!(
            router().classify("Run the test suite"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_update_action() {
        assert_eq!(
            router().classify("Update the spreadsheet with new numbers"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_order_action() {
        assert_eq!(
            router().classify("Order groceries from the usual list"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_turn_on_lights() {
        assert_eq!(
            router().classify("Turn on the living room lights"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_show_me() {
        assert_eq!(
            router().classify("Show me the latest sales report"),
            MessageIntent::ToolAssisted
        );
    }

    // --- Edge cases ---

    #[test]
    fn test_long_greeting_becomes_tool_assisted() {
        // A long message starting with "hello" but containing action verbs
        assert_eq!(
            router().classify(
                "Hello, can you please send an email to my manager about the project update?"
            ),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_case_insensitive() {
        assert_eq!(
            router().classify("SEND an EMAIL to John"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_question_without_specific_words() {
        // A vague question without actionable keywords
        assert_eq!(
            router().classify("Is it going to rain?"),
            MessageIntent::Conversation
        );
    }

    #[test]
    fn test_draft_email() {
        assert_eq!(
            router().classify("Draft an email to the team"),
            MessageIntent::ToolAssisted
        );
    }

    #[test]
    fn test_default_returns_new_router() {
        let r = MessageRouter::default();
        assert_eq!(r.classify("hello"), MessageIntent::Conversation);
    }
}
