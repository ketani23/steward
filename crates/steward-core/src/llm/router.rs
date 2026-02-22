//! Provider router with fallback chain.
//!
//! Selects an LLM provider based on configuration and implements automatic
//! fallback: if the primary provider fails, the router tries the next provider
//! in the chain until one succeeds or all have been exhausted.

use async_trait::async_trait;
use std::sync::Arc;
use steward_types::errors::StewardError;
use steward_types::traits::LlmProvider;
use steward_types::{CompletionRequest, CompletionResponse, ToolDefinition};

/// Routes LLM requests to a primary provider with automatic fallback.
///
/// The router holds an ordered list of providers. Requests are sent to the
/// primary (first) provider; on failure, each fallback is tried in order.
pub struct ProviderRouter {
    /// Ordered list of providers: primary first, then fallbacks.
    providers: Vec<Arc<dyn LlmProvider>>,
}

impl std::fmt::Debug for ProviderRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderRouter")
            .field("provider_count", &self.providers.len())
            .finish()
    }
}

impl ProviderRouter {
    /// Create a new router with a primary provider and fallback chain.
    ///
    /// The `primary` provider is tried first. If it fails, each provider in
    /// `fallbacks` is tried in order until one succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if no providers are given (empty primary and fallbacks).
    pub fn new(primary: Arc<dyn LlmProvider>, fallbacks: Vec<Arc<dyn LlmProvider>>) -> Self {
        let mut providers = Vec::with_capacity(1 + fallbacks.len());
        providers.push(primary);
        providers.extend(fallbacks);
        Self { providers }
    }

    /// Create a router from an ordered list of providers.
    ///
    /// The first provider is the primary; the rest are fallbacks.
    ///
    /// # Errors
    ///
    /// Returns an error if the list is empty.
    pub fn from_providers(providers: Vec<Arc<dyn LlmProvider>>) -> Result<Self, StewardError> {
        if providers.is_empty() {
            return Err(StewardError::Config(
                "ProviderRouter requires at least one provider".to_string(),
            ));
        }
        Ok(Self { providers })
    }
}

#[async_trait]
impl LlmProvider for ProviderRouter {
    /// Send a completion request, falling back through providers on failure.
    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, StewardError> {
        let mut last_error = None;

        for (i, provider) in self.providers.iter().enumerate() {
            match provider.complete(request.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::warn!(
                        provider_index = i,
                        error = %e,
                        "LLM provider failed, trying next in fallback chain"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| StewardError::LlmProvider("No providers available".to_string())))
    }

    /// Send a completion request with tools, falling back through providers on failure.
    async fn complete_with_tools(
        &self,
        request: CompletionRequest,
        tools: &[ToolDefinition],
    ) -> Result<CompletionResponse, StewardError> {
        let mut last_error = None;

        for (i, provider) in self.providers.iter().enumerate() {
            match provider.complete_with_tools(request.clone(), tools).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::warn!(
                        provider_index = i,
                        error = %e,
                        "LLM provider failed (with tools), trying next in fallback chain"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| StewardError::LlmProvider("No providers available".to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use steward_types::{ChatMessage, ChatRole, TokenUsage};

    /// A mock provider that always succeeds with a configurable response.
    struct SuccessProvider {
        response_text: String,
        call_count: AtomicU32,
    }

    impl SuccessProvider {
        fn new(text: &str) -> Self {
            Self {
                response_text: text.to_string(),
                call_count: AtomicU32::new(0),
            }
        }

        fn calls(&self) -> u32 {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl LlmProvider for SuccessProvider {
        async fn complete(
            &self,
            _request: CompletionRequest,
        ) -> Result<CompletionResponse, StewardError> {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            Ok(CompletionResponse {
                content: self.response_text.clone(),
                tool_calls: vec![],
                model: "mock".to_string(),
                usage: TokenUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                },
            })
        }

        async fn complete_with_tools(
            &self,
            _request: CompletionRequest,
            _tools: &[ToolDefinition],
        ) -> Result<CompletionResponse, StewardError> {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            Ok(CompletionResponse {
                content: self.response_text.clone(),
                tool_calls: vec![],
                model: "mock".to_string(),
                usage: TokenUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                },
            })
        }
    }

    /// A mock provider that always fails.
    struct FailingProvider {
        call_count: AtomicU32,
    }

    impl FailingProvider {
        fn new() -> Self {
            Self {
                call_count: AtomicU32::new(0),
            }
        }

        fn calls(&self) -> u32 {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl LlmProvider for FailingProvider {
        async fn complete(
            &self,
            _request: CompletionRequest,
        ) -> Result<CompletionResponse, StewardError> {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            Err(StewardError::LlmProvider("provider down".to_string()))
        }

        async fn complete_with_tools(
            &self,
            _request: CompletionRequest,
            _tools: &[ToolDefinition],
        ) -> Result<CompletionResponse, StewardError> {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            Err(StewardError::LlmProvider("provider down".to_string()))
        }
    }

    fn sample_request() -> CompletionRequest {
        CompletionRequest {
            system: String::new(),
            messages: vec![ChatMessage {
                role: ChatRole::User,
                content: "test".to_string(),
            }],
            model: "test-model".to_string(),
            max_tokens: 100,
            temperature: None,
        }
    }

    #[tokio::test]
    async fn test_primary_succeeds() {
        let primary = Arc::new(SuccessProvider::new("primary response"));
        let fallback = Arc::new(SuccessProvider::new("fallback response"));

        let router = ProviderRouter::new(primary.clone(), vec![fallback.clone()]);
        let result = router.complete(sample_request()).await.unwrap();

        assert_eq!(result.content, "primary response");
        assert_eq!(primary.calls(), 1);
        assert_eq!(fallback.calls(), 0);
    }

    #[tokio::test]
    async fn test_fallback_on_primary_failure() {
        let primary = Arc::new(FailingProvider::new());
        let fallback = Arc::new(SuccessProvider::new("fallback response"));

        let router = ProviderRouter::new(primary.clone(), vec![fallback.clone()]);
        let result = router.complete(sample_request()).await.unwrap();

        assert_eq!(result.content, "fallback response");
        assert_eq!(primary.calls(), 1);
        assert_eq!(fallback.calls(), 1);
    }

    #[tokio::test]
    async fn test_all_providers_fail() {
        let primary = Arc::new(FailingProvider::new());
        let fallback1 = Arc::new(FailingProvider::new());
        let fallback2 = Arc::new(FailingProvider::new());

        let router =
            ProviderRouter::new(primary.clone(), vec![fallback1.clone(), fallback2.clone()]);
        let err = router.complete(sample_request()).await.unwrap_err();

        match err {
            StewardError::LlmProvider(msg) => {
                assert!(msg.contains("provider down"), "unexpected: {msg}");
            }
            other => panic!("Expected LlmProvider error, got: {other:?}"),
        }
        assert_eq!(primary.calls(), 1);
        assert_eq!(fallback1.calls(), 1);
        assert_eq!(fallback2.calls(), 1);
    }

    #[tokio::test]
    async fn test_second_fallback_succeeds() {
        let primary = Arc::new(FailingProvider::new());
        let fallback1 = Arc::new(FailingProvider::new());
        let fallback2 = Arc::new(SuccessProvider::new("third time's the charm"));

        let router =
            ProviderRouter::new(primary.clone(), vec![fallback1.clone(), fallback2.clone()]);
        let result = router.complete(sample_request()).await.unwrap();

        assert_eq!(result.content, "third time's the charm");
        assert_eq!(primary.calls(), 1);
        assert_eq!(fallback1.calls(), 1);
        assert_eq!(fallback2.calls(), 1);
    }

    #[tokio::test]
    async fn test_complete_with_tools_fallback() {
        let primary = Arc::new(FailingProvider::new());
        let fallback = Arc::new(SuccessProvider::new("tools fallback"));

        let router = ProviderRouter::new(primary.clone(), vec![fallback.clone()]);
        let result = router
            .complete_with_tools(sample_request(), &[])
            .await
            .unwrap();

        assert_eq!(result.content, "tools fallback");
        assert_eq!(primary.calls(), 1);
        assert_eq!(fallback.calls(), 1);
    }

    #[tokio::test]
    async fn test_from_providers_empty() {
        let err = ProviderRouter::from_providers(vec![]).unwrap_err();
        match err {
            StewardError::Config(msg) => {
                assert!(msg.contains("at least one"), "unexpected: {msg}");
            }
            other => panic!("Expected Config error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_from_providers_single() {
        let provider = Arc::new(SuccessProvider::new("only one"));
        let router = ProviderRouter::from_providers(vec![provider]).unwrap();
        let result = router.complete(sample_request()).await.unwrap();
        assert_eq!(result.content, "only one");
    }
}
