//! Embedding provider implementations.
//!
//! Provides [`OpenAiEmbeddingProvider`] which calls the OpenAI embeddings API
//! (`text-embedding-3-small`, 1536 dimensions) to generate vector embeddings
//! for memory search.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use steward_types::errors::StewardError;

use crate::search::EmbeddingProvider;

// ============================================================
// OpenAI API response types
// ============================================================

/// Response from the OpenAI embeddings endpoint.
#[derive(Debug, Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
}

/// A single embedding object in the response.
#[derive(Debug, Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

// ============================================================
// OpenAiEmbeddingProvider
// ============================================================

/// Embedding provider backed by the OpenAI `text-embedding-3-small` model.
///
/// Calls `POST https://api.openai.com/v1/embeddings` and returns the
/// resulting 1536-dimensional vector.
pub struct OpenAiEmbeddingProvider {
    api_key: String,
    model: String,
    client: reqwest::Client,
}

impl OpenAiEmbeddingProvider {
    /// Create a new provider with the given API key.
    ///
    /// Uses `text-embedding-3-small` by default (1536 dimensions).
    /// The underlying HTTP client is configured with a 5-second connect timeout
    /// and a 10-second per-request timeout.
    ///
    /// # Errors
    ///
    /// Returns `StewardError::Config` if the HTTP client cannot be constructed
    /// (e.g. TLS initialisation failure).
    pub fn new(api_key: String) -> Result<Self, StewardError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| StewardError::Config(format!("failed to build reqwest client: {e}")))?;
        Ok(Self {
            api_key,
            model: "text-embedding-3-small".to_string(),
            client,
        })
    }

    /// Create a provider with a custom model name and pre-built HTTP client.
    ///
    /// Useful for testing with a mock HTTP server or for using a different
    /// embedding model.
    pub fn with_client(api_key: String, model: String, client: reqwest::Client) -> Self {
        Self {
            api_key,
            model,
            client,
        }
    }
}

#[async_trait]
impl EmbeddingProvider for OpenAiEmbeddingProvider {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, StewardError> {
        let body = serde_json::json!({
            "input": text,
            "model": self.model,
        });

        let response = self
            .client
            .post("https://api.openai.com/v1/embeddings")
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| StewardError::Memory(format!("embedding request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let raw = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            // Truncate to 200 chars and strip non-printable bytes to avoid
            // leaking large upstream error bodies into log sinks.
            let truncated: String = raw
                .chars()
                .filter(|c| !c.is_control() || *c == ' ')
                .take(200)
                .collect();
            return Err(StewardError::Memory(format!(
                "embedding API returned {status}: {truncated}"
            )));
        }

        let parsed: EmbeddingResponse = response.json().await.map_err(|e| {
            StewardError::Memory(format!("failed to parse embedding response: {e}"))
        })?;

        parsed
            .data
            .into_iter()
            .next()
            .map(|d| d.embedding)
            .ok_or_else(|| StewardError::Memory("empty embedding response".to_string()))
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // --------------------------------------------------------
    // Unit tests for construction
    // --------------------------------------------------------

    #[test]
    fn test_new_uses_default_model() {
        let provider = OpenAiEmbeddingProvider::new("sk-test".to_string()).unwrap();
        assert_eq!(provider.model, "text-embedding-3-small");
        assert_eq!(provider.api_key, "sk-test");
    }

    #[test]
    fn test_with_client_uses_custom_model() {
        let client = reqwest::Client::new();
        let provider = OpenAiEmbeddingProvider::with_client(
            "sk-test".to_string(),
            "text-embedding-3-large".to_string(),
            client,
        );
        assert_eq!(provider.model, "text-embedding-3-large");
    }

    // --------------------------------------------------------
    // Integration test with mock HTTP server (requires wiremock or similar)
    // Use #[ignore] so it only runs when explicitly requested.
    // --------------------------------------------------------

    /// Mock embedding provider for use in other module tests.
    pub struct MockEmbeddingProvider {
        /// Fixed embedding vector to return for every call.
        pub embedding: Vec<f32>,
    }

    #[async_trait]
    impl EmbeddingProvider for MockEmbeddingProvider {
        async fn embed(&self, _text: &str) -> Result<Vec<f32>, StewardError> {
            Ok(self.embedding.clone())
        }
    }

    #[test]
    fn test_mock_embedding_provider() {
        let mock = MockEmbeddingProvider {
            embedding: vec![0.1_f32; 1536],
        };
        // Verify it's usable as Arc<dyn EmbeddingProvider>
        let _: Arc<dyn EmbeddingProvider> = Arc::new(mock);
    }

    #[tokio::test]
    async fn test_mock_embed_returns_fixed_vector() {
        let mock = MockEmbeddingProvider {
            embedding: vec![0.5_f32; 4],
        };
        let result = mock.embed("test text").await.unwrap();
        assert_eq!(result, vec![0.5_f32; 4]);
    }

    #[tokio::test]
    #[ignore]
    async fn test_openai_embed_live() {
        let api_key = match std::env::var("OPENAI_API_KEY") {
            Ok(k) => k,
            Err(_) => return,
        };
        let provider = OpenAiEmbeddingProvider::new(api_key).unwrap();
        let result = provider.embed("Hello world").await.unwrap();
        assert_eq!(result.len(), 1536);
    }
}
