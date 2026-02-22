//! Anthropic Messages API provider.
//!
//! Implements [`LlmProvider`] for Claude models (Opus, Sonnet, Haiku) via the
//! Anthropic Messages API. Handles tool_use responses and respects rate limits
//! from response headers.
//!
//! See `docs/architecture.md` section 11 for model support specification.

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use steward_types::errors::StewardError;
use steward_types::traits::LlmProvider;
use steward_types::{
    ChatMessage, ChatRole, CompletionRequest, CompletionResponse, TokenUsage, ToolCallRequest,
    ToolDefinition,
};
use tokio::sync::Mutex;

/// Default Anthropic API base URL.
const DEFAULT_API_BASE: &str = "https://api.anthropic.com";

/// Current Anthropic API version header value.
const API_VERSION: &str = "2023-06-01";

/// Anthropic LLM provider using the Messages API.
///
/// Supports Claude Opus 4.6, Sonnet 4.5, and Haiku 4.5 models with tool calling.
pub struct AnthropicProvider {
    /// HTTP client for API requests.
    client: Client,
    /// Anthropic API key.
    api_key: String,
    /// Base URL for the API (overridable for testing).
    api_base: String,
    /// Rate limit state from the most recent response headers.
    rate_limit_state: Mutex<RateLimitState>,
}

/// Tracks rate limit information from Anthropic response headers.
struct RateLimitState {
    /// Remaining requests in the current window.
    remaining_requests: AtomicU64,
    /// When the rate limit window resets.
    reset_at: Option<Instant>,
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self {
            remaining_requests: AtomicU64::new(u64::MAX),
            reset_at: None,
        }
    }
}

// -- Anthropic Messages API request/response types --

/// Request body for the Anthropic Messages API.
#[derive(Debug, Serialize)]
struct MessagesRequest {
    model: String,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<ApiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<ApiToolDef>>,
}

/// A message in the Anthropic Messages API format.
#[derive(Debug, Serialize, Deserialize)]
struct ApiMessage {
    role: String,
    content: ApiContent,
}

/// Content can be a simple string or an array of content blocks.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum ApiContent {
    /// Simple text string.
    Text(String),
    /// Array of content blocks (text + tool_use).
    Blocks(Vec<ContentBlock>),
}

/// A content block in the response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum ContentBlock {
    /// Text content block.
    #[serde(rename = "text")]
    Text { text: String },
    /// Tool use content block — the model wants to call a tool.
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

/// Tool definition in Anthropic's API format.
#[derive(Debug, Serialize)]
struct ApiToolDef {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

/// Response from the Anthropic Messages API.
#[derive(Debug, Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
    model: String,
    usage: ApiUsage,
    #[serde(rename = "type")]
    _type: Option<String>,
}

/// Token usage from the API response.
#[derive(Debug, Deserialize)]
struct ApiUsage {
    input_tokens: u32,
    output_tokens: u32,
}

/// Error response from the Anthropic API.
#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    error: ApiError,
}

/// Error detail from the API.
#[derive(Debug, Deserialize)]
struct ApiError {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider with the given API key.
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            api_base: DEFAULT_API_BASE.to_string(),
            rate_limit_state: Mutex::new(RateLimitState::default()),
        }
    }

    /// Create a new Anthropic provider with a custom base URL (for testing).
    pub fn with_base_url(api_key: String, api_base: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            api_base,
            rate_limit_state: Mutex::new(RateLimitState::default()),
        }
    }

    /// Convert internal ChatMessage to Anthropic API format.
    fn convert_messages(messages: &[ChatMessage]) -> Vec<ApiMessage> {
        messages
            .iter()
            .map(|m| ApiMessage {
                role: match m.role {
                    ChatRole::User => "user".to_string(),
                    ChatRole::Assistant => "assistant".to_string(),
                },
                content: ApiContent::Text(m.content.clone()),
            })
            .collect()
    }

    /// Convert internal ToolDefinition to Anthropic API tool format.
    fn convert_tools(tools: &[ToolDefinition]) -> Vec<ApiToolDef> {
        tools
            .iter()
            .map(|t| ApiToolDef {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: t.input_schema.clone(),
            })
            .collect()
    }

    /// Parse the API response into a CompletionResponse.
    fn parse_response(resp: MessagesResponse) -> CompletionResponse {
        let mut text_parts = Vec::new();
        let mut tool_calls = Vec::new();

        for block in &resp.content {
            match block {
                ContentBlock::Text { text } => text_parts.push(text.clone()),
                ContentBlock::ToolUse { id, name, input } => {
                    tool_calls.push(ToolCallRequest {
                        id: id.clone(),
                        tool_name: name.clone(),
                        arguments: input.clone(),
                    });
                }
            }
        }

        CompletionResponse {
            content: text_parts.join(""),
            tool_calls,
            model: resp.model,
            usage: TokenUsage {
                input_tokens: resp.usage.input_tokens,
                output_tokens: resp.usage.output_tokens,
            },
        }
    }

    /// Update rate limit state from response headers.
    fn update_rate_limits(&self, state: &mut RateLimitState, headers: &reqwest::header::HeaderMap) {
        if let Some(remaining) = headers
            .get("anthropic-ratelimit-requests-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        {
            state.remaining_requests.store(remaining, Ordering::Relaxed);
        }

        if let Some(reset_secs) = headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        {
            state.reset_at = Some(Instant::now() + Duration::from_secs(reset_secs));
        }
    }

    /// Check if we should wait before making a request due to rate limits.
    async fn check_rate_limit(&self) -> Result<(), StewardError> {
        let state = self.rate_limit_state.lock().await;
        if let Some(reset_at) = state.reset_at {
            if Instant::now() < reset_at && state.remaining_requests.load(Ordering::Relaxed) == 0 {
                let wait = reset_at.duration_since(Instant::now());
                return Err(StewardError::RateLimitExceeded(format!(
                    "Anthropic rate limit reached, retry after {}s",
                    wait.as_secs()
                )));
            }
        }
        Ok(())
    }

    /// Send a request to the Messages API.
    async fn send_request(
        &self,
        request: MessagesRequest,
    ) -> Result<CompletionResponse, StewardError> {
        self.check_rate_limit().await?;

        let url = format!("{}/v1/messages", self.api_base);
        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| StewardError::LlmProvider(format!("HTTP request failed: {e}")))?;

        // Update rate limit state from headers
        {
            let mut state = self.rate_limit_state.lock().await;
            self.update_rate_limits(&mut state, response.headers());
        }

        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(StewardError::RateLimitExceeded(
                "Anthropic API rate limit exceeded (429)".to_string(),
            ));
        }

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(StewardError::LlmProvider(
                "Anthropic API authentication failed: invalid API key".to_string(),
            ));
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            if let Ok(err_resp) = serde_json::from_str::<ApiErrorResponse>(&body) {
                return Err(StewardError::LlmProvider(format!(
                    "Anthropic API error ({}): {}",
                    err_resp.error.error_type, err_resp.error.message
                )));
            }
            return Err(StewardError::LlmProvider(format!(
                "Anthropic API error (HTTP {status}): {body}"
            )));
        }

        let resp_body: MessagesResponse = response
            .json()
            .await
            .map_err(|e| StewardError::LlmProvider(format!("Failed to parse response: {e}")))?;

        Ok(Self::parse_response(resp_body))
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    /// Send a completion request to the Anthropic Messages API.
    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, StewardError> {
        let api_request = MessagesRequest {
            model: request.model,
            max_tokens: request.max_tokens,
            system: if request.system.is_empty() {
                None
            } else {
                Some(request.system)
            },
            messages: Self::convert_messages(&request.messages),
            temperature: request.temperature,
            tools: None,
        };

        self.send_request(api_request).await
    }

    /// Send a completion request with tool definitions.
    async fn complete_with_tools(
        &self,
        request: CompletionRequest,
        tools: &[ToolDefinition],
    ) -> Result<CompletionResponse, StewardError> {
        let api_tools = if tools.is_empty() {
            None
        } else {
            Some(Self::convert_tools(tools))
        };

        let api_request = MessagesRequest {
            model: request.model,
            max_tokens: request.max_tokens,
            system: if request.system.is_empty() {
                None
            } else {
                Some(request.system)
            },
            messages: Self::convert_messages(&request.messages),
            temperature: request.temperature,
            tools: api_tools,
        };

        self.send_request(api_request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_request() -> CompletionRequest {
        CompletionRequest {
            system: "You are a helpful assistant.".to_string(),
            messages: vec![ChatMessage {
                role: ChatRole::User,
                content: "Hello!".to_string(),
            }],
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 1024,
            temperature: Some(0.7),
        }
    }

    fn sample_tools() -> Vec<ToolDefinition> {
        vec![ToolDefinition {
            name: "get_weather".to_string(),
            description: "Get current weather for a location".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "location": { "type": "string" }
                },
                "required": ["location"]
            }),
            source: steward_types::ToolSource::BuiltIn,
            permission_tier: steward_types::PermissionTier::AutoExecute,
        }]
    }

    #[tokio::test]
    async fn test_request_serialization() {
        let request = sample_request();
        let messages = AnthropicProvider::convert_messages(&request.messages);

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].role, "user");
        match &messages[0].content {
            ApiContent::Text(t) => assert_eq!(t, "Hello!"),
            _ => panic!("Expected text content"),
        }
    }

    #[tokio::test]
    async fn test_tool_serialization() {
        let tools = sample_tools();
        let api_tools = AnthropicProvider::convert_tools(&tools);

        assert_eq!(api_tools.len(), 1);
        assert_eq!(api_tools[0].name, "get_weather");
        assert_eq!(
            api_tools[0].description,
            "Get current weather for a location"
        );
        assert!(api_tools[0].input_schema.get("properties").is_some());
    }

    #[tokio::test]
    async fn test_response_deserialization_text() {
        let resp = MessagesResponse {
            content: vec![ContentBlock::Text {
                text: "Hello! How can I help?".to_string(),
            }],
            model: "claude-sonnet-4-5-20250929".to_string(),
            usage: ApiUsage {
                input_tokens: 10,
                output_tokens: 8,
            },
            _type: Some("message".to_string()),
        };

        let result = AnthropicProvider::parse_response(resp);
        assert_eq!(result.content, "Hello! How can I help?");
        assert!(result.tool_calls.is_empty());
        assert_eq!(result.model, "claude-sonnet-4-5-20250929");
        assert_eq!(result.usage.input_tokens, 10);
        assert_eq!(result.usage.output_tokens, 8);
    }

    #[tokio::test]
    async fn test_response_deserialization_tool_use() {
        let resp = MessagesResponse {
            content: vec![
                ContentBlock::Text {
                    text: "Let me check the weather.".to_string(),
                },
                ContentBlock::ToolUse {
                    id: "toolu_123".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"location": "San Francisco"}),
                },
            ],
            model: "claude-opus-4-6".to_string(),
            usage: ApiUsage {
                input_tokens: 50,
                output_tokens: 30,
            },
            _type: Some("message".to_string()),
        };

        let result = AnthropicProvider::parse_response(resp);
        assert_eq!(result.content, "Let me check the weather.");
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].id, "toolu_123");
        assert_eq!(result.tool_calls[0].tool_name, "get_weather");
        assert_eq!(
            result.tool_calls[0].arguments,
            serde_json::json!({"location": "San Francisco"})
        );
    }

    #[tokio::test]
    async fn test_successful_completion() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "test-key"))
            .and(header("anthropic-version", API_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "type": "message",
                "content": [{"type": "text", "text": "Hi there!"}],
                "model": "claude-sonnet-4-5-20250929",
                "usage": {"input_tokens": 10, "output_tokens": 5}
            })))
            .mount(&server)
            .await;

        let provider = AnthropicProvider::with_base_url("test-key".to_string(), server.uri());
        let result = provider.complete(sample_request()).await.unwrap();

        assert_eq!(result.content, "Hi there!");
        assert_eq!(result.model, "claude-sonnet-4-5-20250929");
    }

    #[tokio::test]
    async fn test_completion_with_tools() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "type": "message",
                "content": [
                    {"type": "text", "text": "Checking weather..."},
                    {
                        "type": "tool_use",
                        "id": "toolu_abc",
                        "name": "get_weather",
                        "input": {"location": "NYC"}
                    }
                ],
                "model": "claude-sonnet-4-5-20250929",
                "usage": {"input_tokens": 50, "output_tokens": 30}
            })))
            .mount(&server)
            .await;

        let provider = AnthropicProvider::with_base_url("test-key".to_string(), server.uri());
        let result = provider
            .complete_with_tools(sample_request(), &sample_tools())
            .await
            .unwrap();

        assert_eq!(result.content, "Checking weather...");
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].tool_name, "get_weather");
    }

    #[tokio::test]
    async fn test_rate_limit_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "type": "error",
                "error": {
                    "type": "rate_limit_error",
                    "message": "Rate limit exceeded"
                }
            })))
            .mount(&server)
            .await;

        let provider = AnthropicProvider::with_base_url("test-key".to_string(), server.uri());
        let err = provider.complete(sample_request()).await.unwrap_err();

        match err {
            StewardError::RateLimitExceeded(msg) => {
                assert!(msg.contains("rate limit"), "unexpected message: {msg}");
            }
            other => panic!("Expected RateLimitExceeded, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_auth_failure() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "type": "error",
                "error": {
                    "type": "authentication_error",
                    "message": "Invalid API key"
                }
            })))
            .mount(&server)
            .await;

        let provider = AnthropicProvider::with_base_url("bad-key".to_string(), server.uri());
        let err = provider.complete(sample_request()).await.unwrap_err();

        match err {
            StewardError::LlmProvider(msg) => {
                assert!(msg.contains("authentication"), "unexpected message: {msg}");
            }
            other => panic!("Expected LlmProvider error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_timeout_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;

        let provider = AnthropicProvider {
            client: Client::builder()
                .timeout(Duration::from_millis(100))
                .build()
                .unwrap(),
            api_key: "test-key".to_string(),
            api_base: server.uri(),
            rate_limit_state: Mutex::new(RateLimitState::default()),
        };

        let err = provider.complete(sample_request()).await.unwrap_err();
        match err {
            StewardError::LlmProvider(msg) => {
                assert!(
                    msg.contains("request") || msg.contains("timed out") || msg.contains("timeout"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("Expected LlmProvider error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_rate_limit_headers_respected() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("anthropic-ratelimit-requests-remaining", "42")
                    .set_body_json(serde_json::json!({
                        "type": "message",
                        "content": [{"type": "text", "text": "ok"}],
                        "model": "claude-sonnet-4-5-20250929",
                        "usage": {"input_tokens": 5, "output_tokens": 2}
                    })),
            )
            .mount(&server)
            .await;

        let provider = AnthropicProvider::with_base_url("test-key".to_string(), server.uri());
        provider.complete(sample_request()).await.unwrap();

        let state = provider.rate_limit_state.lock().await;
        assert_eq!(state.remaining_requests.load(Ordering::Relaxed), 42);
    }

    #[tokio::test]
    async fn test_empty_system_prompt_omitted() {
        let request = CompletionRequest {
            system: String::new(),
            messages: vec![ChatMessage {
                role: ChatRole::User,
                content: "Hi".to_string(),
            }],
            model: "claude-haiku-4-5-20251001".to_string(),
            max_tokens: 256,
            temperature: None,
        };

        let api_request = MessagesRequest {
            model: request.model.clone(),
            max_tokens: request.max_tokens,
            system: if request.system.is_empty() {
                None
            } else {
                Some(request.system.clone())
            },
            messages: AnthropicProvider::convert_messages(&request.messages),
            temperature: request.temperature,
            tools: None,
        };

        let json = serde_json::to_value(&api_request).unwrap();
        assert!(json.get("system").is_none());
    }

    #[tokio::test]
    async fn test_request_body_structure() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "type": "message",
                "content": [{"type": "text", "text": "ok"}],
                "model": "claude-opus-4-6",
                "usage": {"input_tokens": 5, "output_tokens": 2}
            })))
            .mount(&server)
            .await;

        let provider = AnthropicProvider::with_base_url("test-key".to_string(), server.uri());
        let request = CompletionRequest {
            system: "Be brief.".to_string(),
            messages: vec![
                ChatMessage {
                    role: ChatRole::User,
                    content: "Hello".to_string(),
                },
                ChatMessage {
                    role: ChatRole::Assistant,
                    content: "Hi there".to_string(),
                },
                ChatMessage {
                    role: ChatRole::User,
                    content: "How are you?".to_string(),
                },
            ],
            model: "claude-opus-4-6".to_string(),
            max_tokens: 2048,
            temperature: Some(0.5),
        };

        let result = provider.complete(request).await.unwrap();
        assert_eq!(result.content, "ok");
    }
}
