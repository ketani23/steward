//! LLM provider implementations for the Steward agent framework.
//!
//! Provides concrete implementations of the [`LlmProvider`] trait for:
//! - **Anthropic** (`AnthropicProvider`): Claude models via the Messages API
//! - **Ollama** (`OllamaProvider`): Local models via the Ollama chat API
//! - **ProviderRouter**: Selects provider based on config with fallback chain

pub mod anthropic;
pub mod ollama;
pub mod router;

pub use anthropic::AnthropicProvider;
pub use ollama::OllamaProvider;
pub use router::ProviderRouter;
