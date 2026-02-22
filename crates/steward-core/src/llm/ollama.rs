//! Ollama local LLM provider.
//!
//! Implements [`LlmProvider`] for local models running via the Ollama API.
//! Supports any model available in the local Ollama instance and converts
//! between Ollama's chat format and Steward's CompletionRequest/Response.
//!
//! See `docs/architecture.md` section 11 for model support specification.

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use steward_types::errors::StewardError;
use steward_types::traits::LlmProvider;
use steward_types::{
    ChatMessage, ChatRole, CompletionRequest, CompletionResponse, TokenUsage, ToolCallRequest,
    ToolDefinition,
};

/// Default Ollama API base URL for local instances.
const DEFAULT_OLLAMA_BASE: &str = "http://localhost:11434";

/// Ollama LLM provider for local model execution.
///
/// Connects to a running Ollama instance and supports any locally available model.
/// Converts between Ollama's chat completion format and Steward's types.
pub struct OllamaProvider {
    /// HTTP client for API requests.
    client: Client,
    /// Base URL for the Ollama API (default: `http://localhost:11434`).
    api_base: String,
}

// -- Ollama API request/response types --

/// Request body for Ollama's `/api/chat` endpoint.
#[derive(Debug, Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<OllamaToolDef>>,
    /// Disable streaming to get a single response object.
    stream: bool,
}

/// A message in Ollama's chat format.
#[derive(Debug, Serialize, Deserialize)]
struct OllamaMessage {
    role: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<OllamaToolCall>>,
}

/// Generation options for Ollama.
#[derive(Debug, Serialize)]
struct OllamaOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
}

/// Tool definition in Ollama's format.
#[derive(Debug, Serialize)]
struct OllamaToolDef {
    #[serde(rename = "type")]
    tool_type: String,
    function: OllamaFunction,
}

/// Function definition within an Ollama tool.
#[derive(Debug, Serialize)]
struct OllamaFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

/// A tool call in Ollama's response format.
#[derive(Debug, Serialize, Deserialize)]
struct OllamaToolCall {
    function: OllamaFunctionCall,
}

/// Function call details from Ollama.
#[derive(Debug, Serialize, Deserialize)]
struct OllamaFunctionCall {
    name: String,
    arguments: serde_json::Value,
}

/// Response from Ollama's `/api/chat` endpoint (non-streaming).
#[derive(Debug, Deserialize)]
struct OllamaChatResponse {
    message: OllamaMessage,
    model: String,
    #[serde(default)]
    prompt_eval_count: Option<u32>,
    #[serde(default)]
    eval_count: Option<u32>,
}

impl OllamaProvider {
    /// Create a new Ollama provider connecting to localhost.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            api_base: DEFAULT_OLLAMA_BASE.to_string(),
        }
    }

    /// Create a new Ollama provider with a custom base URL.
    pub fn with_base_url(api_base: String) -> Self {
        Self {
            client: Client::new(),
            api_base,
        }
    }

    /// Convert internal ChatMessage list to Ollama format, prepending system message.
    fn convert_messages(system: &str, messages: &[ChatMessage]) -> Vec<OllamaMessage> {
        let mut result = Vec::with_capacity(messages.len() + 1);

        if !system.is_empty() {
            result.push(OllamaMessage {
                role: "system".to_string(),
                content: system.to_string(),
                tool_calls: None,
            });
        }

        for msg in messages {
            result.push(OllamaMessage {
                role: match msg.role {
                    ChatRole::User => "user".to_string(),
                    ChatRole::Assistant => "assistant".to_string(),
                },
                content: msg.content.clone(),
                tool_calls: None,
            });
        }

        result
    }

    /// Convert internal ToolDefinition list to Ollama format.
    fn convert_tools(tools: &[ToolDefinition]) -> Vec<OllamaToolDef> {
        tools
            .iter()
            .map(|t| OllamaToolDef {
                tool_type: "function".to_string(),
                function: OllamaFunction {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    parameters: t.input_schema.clone(),
                },
            })
            .collect()
    }

    /// Parse an Ollama response into a CompletionResponse.
    fn parse_response(resp: OllamaChatResponse) -> CompletionResponse {
        let tool_calls = resp
            .message
            .tool_calls
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(i, tc)| ToolCallRequest {
                id: format!("ollama_call_{i}"),
                tool_name: tc.function.name,
                arguments: tc.function.arguments,
            })
            .collect();

        CompletionResponse {
            content: resp.message.content,
            tool_calls,
            model: resp.model,
            usage: TokenUsage {
                input_tokens: resp.prompt_eval_count.unwrap_or(0),
                output_tokens: resp.eval_count.unwrap_or(0),
            },
        }
    }

    /// Send a chat request to the Ollama API.
    async fn send_request(
        &self,
        request: OllamaChatRequest,
    ) -> Result<CompletionResponse, StewardError> {
        let url = format!("{}/api/chat", self.api_base);
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| StewardError::LlmProvider(format!("Ollama HTTP request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(StewardError::LlmProvider(format!(
                "Ollama API error (HTTP {status}): {body}"
            )));
        }

        let resp_body: OllamaChatResponse = response.json().await.map_err(|e| {
            StewardError::LlmProvider(format!("Failed to parse Ollama response: {e}"))
        })?;

        Ok(Self::parse_response(resp_body))
    }
}

impl Default for OllamaProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    /// Send a completion request to the Ollama chat API.
    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, StewardError> {
        let ollama_request = OllamaChatRequest {
            model: request.model,
            messages: Self::convert_messages(&request.system, &request.messages),
            options: Some(OllamaOptions {
                temperature: request.temperature,
                num_predict: Some(request.max_tokens),
            }),
            tools: None,
            stream: false,
        };

        self.send_request(ollama_request).await
    }

    /// Send a completion request with tool definitions to Ollama.
    async fn complete_with_tools(
        &self,
        request: CompletionRequest,
        tools: &[ToolDefinition],
    ) -> Result<CompletionResponse, StewardError> {
        let ollama_tools = if tools.is_empty() {
            None
        } else {
            Some(Self::convert_tools(tools))
        };

        let ollama_request = OllamaChatRequest {
            model: request.model,
            messages: Self::convert_messages(&request.system, &request.messages),
            options: Some(OllamaOptions {
                temperature: request.temperature,
                num_predict: Some(request.max_tokens),
            }),
            tools: ollama_tools,
            stream: false,
        };

        self.send_request(ollama_request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_request() -> CompletionRequest {
        CompletionRequest {
            system: "You are helpful.".to_string(),
            messages: vec![ChatMessage {
                role: ChatRole::User,
                content: "Hello!".to_string(),
            }],
            model: "llama3".to_string(),
            max_tokens: 512,
            temperature: Some(0.8),
        }
    }

    fn sample_tools() -> Vec<ToolDefinition> {
        vec![ToolDefinition {
            name: "calculator".to_string(),
            description: "Perform arithmetic calculations".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "expression": { "type": "string" }
                },
                "required": ["expression"]
            }),
            source: steward_types::ToolSource::BuiltIn,
            permission_tier: steward_types::PermissionTier::AutoExecute,
        }]
    }

    #[tokio::test]
    async fn test_message_conversion() {
        let messages = OllamaProvider::convert_messages(
            "System prompt",
            &[
                ChatMessage {
                    role: ChatRole::User,
                    content: "Hi".to_string(),
                },
                ChatMessage {
                    role: ChatRole::Assistant,
                    content: "Hello".to_string(),
                },
            ],
        );

        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].role, "system");
        assert_eq!(messages[0].content, "System prompt");
        assert_eq!(messages[1].role, "user");
        assert_eq!(messages[2].role, "assistant");
    }

    #[tokio::test]
    async fn test_empty_system_becomes_no_system_message() {
        let messages = OllamaProvider::convert_messages(
            "",
            &[ChatMessage {
                role: ChatRole::User,
                content: "Hi".to_string(),
            }],
        );

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].role, "user");
    }

    #[tokio::test]
    async fn test_tool_conversion() {
        let tools = sample_tools();
        let ollama_tools = OllamaProvider::convert_tools(&tools);

        assert_eq!(ollama_tools.len(), 1);
        assert_eq!(ollama_tools[0].tool_type, "function");
        assert_eq!(ollama_tools[0].function.name, "calculator");
    }

    #[tokio::test]
    async fn test_response_deserialization_text() {
        let resp = OllamaChatResponse {
            message: OllamaMessage {
                role: "assistant".to_string(),
                content: "Hello there!".to_string(),
                tool_calls: None,
            },
            model: "llama3".to_string(),
            prompt_eval_count: Some(15),
            eval_count: Some(8),
        };

        let result = OllamaProvider::parse_response(resp);
        assert_eq!(result.content, "Hello there!");
        assert!(result.tool_calls.is_empty());
        assert_eq!(result.model, "llama3");
        assert_eq!(result.usage.input_tokens, 15);
        assert_eq!(result.usage.output_tokens, 8);
    }

    #[tokio::test]
    async fn test_response_deserialization_tool_calls() {
        let resp = OllamaChatResponse {
            message: OllamaMessage {
                role: "assistant".to_string(),
                content: String::new(),
                tool_calls: Some(vec![OllamaToolCall {
                    function: OllamaFunctionCall {
                        name: "calculator".to_string(),
                        arguments: serde_json::json!({"expression": "2+2"}),
                    },
                }]),
            },
            model: "llama3".to_string(),
            prompt_eval_count: Some(20),
            eval_count: Some(10),
        };

        let result = OllamaProvider::parse_response(resp);
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].tool_name, "calculator");
        assert_eq!(result.tool_calls[0].id, "ollama_call_0");
    }

    #[tokio::test]
    async fn test_successful_completion() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {
                    "role": "assistant",
                    "content": "Hi! How can I help?"
                },
                "model": "llama3",
                "prompt_eval_count": 12,
                "eval_count": 6
            })))
            .mount(&server)
            .await;

        let provider = OllamaProvider::with_base_url(server.uri());
        let result = provider.complete(sample_request()).await.unwrap();

        assert_eq!(result.content, "Hi! How can I help?");
        assert_eq!(result.model, "llama3");
    }

    #[tokio::test]
    async fn test_completion_with_tool_calls() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "function": {
                            "name": "calculator",
                            "arguments": {"expression": "3*4"}
                        }
                    }]
                },
                "model": "llama3",
                "prompt_eval_count": 25,
                "eval_count": 12
            })))
            .mount(&server)
            .await;

        let provider = OllamaProvider::with_base_url(server.uri());
        let result = provider
            .complete_with_tools(sample_request(), &sample_tools())
            .await
            .unwrap();

        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].tool_name, "calculator");
    }

    #[tokio::test]
    async fn test_server_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&server)
            .await;

        let provider = OllamaProvider::with_base_url(server.uri());
        let err = provider.complete(sample_request()).await.unwrap_err();

        match err {
            StewardError::LlmProvider(msg) => {
                assert!(msg.contains("500"), "unexpected message: {msg}");
            }
            other => panic!("Expected LlmProvider error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_connection_refused() {
        let provider = OllamaProvider::with_base_url("http://127.0.0.1:1".to_string());
        let err = provider.complete(sample_request()).await.unwrap_err();

        match err {
            StewardError::LlmProvider(msg) => {
                assert!(
                    msg.contains("request failed") || msg.contains("error"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("Expected LlmProvider error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_missing_token_counts_default_to_zero() {
        let resp = OllamaChatResponse {
            message: OllamaMessage {
                role: "assistant".to_string(),
                content: "ok".to_string(),
                tool_calls: None,
            },
            model: "mistral".to_string(),
            prompt_eval_count: None,
            eval_count: None,
        };

        let result = OllamaProvider::parse_response(resp);
        assert_eq!(result.usage.input_tokens, 0);
        assert_eq!(result.usage.output_tokens, 0);
    }

    #[tokio::test]
    async fn test_request_body_has_stream_false() {
        let request = OllamaChatRequest {
            model: "llama3".to_string(),
            messages: vec![],
            options: None,
            tools: None,
            stream: false,
        };

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["stream"], false);
    }
}
