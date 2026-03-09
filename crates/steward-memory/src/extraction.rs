//! Post-turn fact extraction pipeline.
//!
//! After each agent turn, calls a lightweight LLM to extract factual
//! claims from the conversation and stores them in memory with deduplication.

use std::sync::Arc;

use serde::Deserialize;

use steward_types::actions::{
    ChatMessage, ChatRole, CompletionRequest, MemoryEntry, MemoryProvenance,
};
use steward_types::errors::StewardError;
use steward_types::traits::{LlmProvider, MemorySearch, MemoryStore};

/// Configuration for the extraction pipeline.
pub struct ExtractionConfig {
    /// LLM model to use for extraction (should be a cheap/fast model).
    pub model: String,
    /// Similarity threshold above which a new fact is considered a duplicate.
    pub dedup_threshold: f64,
    /// Maximum facts to extract per turn.
    pub max_facts_per_turn: usize,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            model: "claude-haiku-4-5-20251001".to_string(),
            dedup_threshold: 0.9,
            max_facts_per_turn: 10,
        }
    }
}

/// A fact extracted from a conversation turn.
#[derive(Debug, Deserialize)]
struct ExtractedFact {
    content: String,
    scope_suggestion: Option<String>,
    confidence: Option<f64>,
}

/// Post-turn extraction pipeline.
///
/// Calls a lightweight LLM to extract durable facts from each conversation
/// turn, deduplicates against existing memory, and stores new facts.
pub struct FactExtractor {
    llm: Arc<dyn LlmProvider>,
    store: Arc<dyn MemoryStore>,
    search: Arc<dyn MemorySearch>,
    config: ExtractionConfig,
}

impl FactExtractor {
    /// Create a new extraction pipeline.
    pub fn new(
        llm: Arc<dyn LlmProvider>,
        store: Arc<dyn MemoryStore>,
        search: Arc<dyn MemorySearch>,
        config: ExtractionConfig,
    ) -> Self {
        Self {
            llm,
            store,
            search,
            config,
        }
    }

    /// Extract facts from a conversation turn and store non-duplicates.
    ///
    /// Returns the count of new facts stored. Returns 0 (not an error) if
    /// no new facts found or if the LLM returns an empty array.
    pub async fn extract_from_turn(
        &self,
        user_message: &str,
        agent_response: &str,
        session_id: &str,
        channel: &str,
    ) -> Result<usize, StewardError> {
        let prompt = build_extraction_prompt(user_message, agent_response);

        let request = CompletionRequest {
            system: EXTRACTION_SYSTEM_PROMPT.to_string(),
            messages: vec![ChatMessage {
                role: ChatRole::User,
                content: prompt,
            }],
            model: self.config.model.clone(),
            max_tokens: 1024,
            temperature: Some(0.0),
        };

        let response = self
            .llm
            .complete(request)
            .await
            .map_err(|e| StewardError::Memory(format!("extraction LLM failed: {e}")))?;

        let facts: Vec<ExtractedFact> = match parse_extraction_response(&response.content) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse extraction response, skipping");
                return Ok(0);
            }
        };

        let mut stored_count = 0;

        for fact in facts.into_iter().take(self.config.max_facts_per_turn) {
            if fact.content.trim().is_empty() {
                continue;
            }

            // Deduplication check
            if self.is_duplicate(&fact.content).await {
                tracing::debug!(content = %fact.content, "Skipping duplicate fact");
                continue;
            }

            let entry = MemoryEntry {
                id: None,
                content: fact.content,
                provenance: MemoryProvenance::AgentObservation,
                trust_score: 0.6,
                created_at: chrono::Utc::now(),
                embedding: None,
                scope: Some(
                    fact.scope_suggestion
                        .unwrap_or_else(|| "shared".to_string()),
                ),
                source_session: uuid::Uuid::parse_str(session_id).ok(),
                source_channel: Some(channel.to_string()),
                confidence: Some(fact.confidence.unwrap_or(0.8)),
            };

            match self.store.store(entry).await {
                Ok(_) => stored_count += 1,
                Err(e) => tracing::warn!(error = %e, "Failed to store extracted fact"),
            }
        }

        tracing::debug!(stored = stored_count, "Extraction complete");
        Ok(stored_count)
    }

    /// Check if a fact already exists (similarity > threshold).
    async fn is_duplicate(&self, content: &str) -> bool {
        match self.search.search(content, 3, None).await {
            Ok(results) => results
                .first()
                .map(|r| r.score > self.config.dedup_threshold)
                .unwrap_or(false),
            Err(e) => {
                tracing::warn!(error = %e, "Dedup search failed, assuming not duplicate");
                false
            }
        }
    }
}

const EXTRACTION_SYSTEM_PROMPT: &str = "\
You extract factual claims from conversations that are worth remembering.
Return a JSON array of facts. Each fact must be a complete, self-contained sentence.
If no new facts are present, return an empty array [].
Do not extract opinions, questions, or transient information.
Only extract durable facts: user preferences, project decisions, technical facts, user identity.

Response format: [{\"content\": \"...\", \"scope_suggestion\": \"shared\", \"confidence\": 0.9}]";

fn build_extraction_prompt(user_message: &str, agent_response: &str) -> String {
    format!("Conversation turn:\nUser: {user_message}\n\nAgent: {agent_response}\n\nExtract facts:")
}

fn parse_extraction_response(content: &str) -> Result<Vec<ExtractedFact>, StewardError> {
    let start = content
        .find('[')
        .ok_or_else(|| StewardError::Memory("no JSON array in response".to_string()))?;
    let end = content
        .rfind(']')
        .ok_or_else(|| StewardError::Memory("unclosed JSON array".to_string()))?;
    let json_str = &content[start..=end];

    serde_json::from_str(json_str)
        .map_err(|e| StewardError::Memory(format!("JSON parse failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_extraction_response_valid() {
        let input = r#"[{"content": "User prefers dark mode", "scope_suggestion": "shared", "confidence": 0.9}]"#;
        let facts = parse_extraction_response(input).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].content, "User prefers dark mode");
        assert!((facts[0].confidence.unwrap() - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_extraction_response_empty() {
        let input = "[]";
        let facts = parse_extraction_response(input).unwrap();
        assert!(facts.is_empty());
    }

    #[test]
    fn test_parse_extraction_response_embedded_json() {
        let input = "Here are the facts:\n[{\"content\": \"The project uses Rust\", \"scope_suggestion\": \"shared\", \"confidence\": 0.95}]\nThat's all.";
        let facts = parse_extraction_response(input).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].content, "The project uses Rust");
    }

    #[test]
    fn test_parse_extraction_response_invalid() {
        let input = "No facts here.";
        assert!(parse_extraction_response(input).is_err());
    }

    #[test]
    fn test_build_extraction_prompt() {
        let prompt = build_extraction_prompt("hello", "hi there");
        assert!(prompt.contains("User: hello"));
        assert!(prompt.contains("Agent: hi there"));
    }

    #[test]
    fn test_default_config() {
        let config = ExtractionConfig::default();
        assert_eq!(config.max_facts_per_turn, 10);
        assert!((config.dedup_threshold - 0.9).abs() < f64::EPSILON);
    }
}
