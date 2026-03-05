//! Web search built-in tool.
//!
//! Searches the web via the Brave Search API and returns a numbered list of
//! results with title, URL, and snippet for each.
//!
//! Permission tier: LogAndExecute (read-only network access, audited).
//!
//! Requires the `BRAVE_SEARCH_API_KEY` environment variable to be set.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, warn};

use steward_types::actions::{PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;

use crate::registry::BuiltInHandler;

/// Brave Search API endpoint.
const BRAVE_API_URL: &str = "https://api.search.brave.com/res/v1/web/search";

/// Default number of search results to return.
const DEFAULT_COUNT: u64 = 5;

/// Maximum number of search results allowed.
const MAX_COUNT: u64 = 10;

/// Request timeout in seconds.
const TIMEOUT_SECS: u64 = 10;

/// Web search tool — queries the Brave Search API.
///
/// Implements [`BuiltInHandler`] to be registered with the tool registry.
/// Reads the `BRAVE_SEARCH_API_KEY` environment variable at construction time.
pub struct WebSearchTool {
    client: Client,
    api_key: String,
}

impl WebSearchTool {
    /// Create a new web search tool.
    ///
    /// Reads `BRAVE_SEARCH_API_KEY` from the environment.
    /// Returns an error if the variable is not set.
    pub fn new() -> Result<Self, StewardError> {
        let api_key = std::env::var("BRAVE_SEARCH_API_KEY").map_err(|_| {
            StewardError::Config("BRAVE_SEARCH_API_KEY environment variable not set".to_string())
        })?;

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
            .build()
            .map_err(|e| StewardError::Tool(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { client, api_key })
    }

    /// Return the [`ToolDefinition`] for this tool.
    ///
    /// Name: `web.search`, source: `BuiltIn`, tier: `LogAndExecute`.
    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: "web.search".to_string(),
            description: "Search the web for information. Returns titles, URLs, and snippets."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query"
                    },
                    "count": {
                        "type": "number",
                        "description": "Number of results to return (default 5, max 10)"
                    }
                },
                "required": ["query"]
            }),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::LogAndExecute,
        }
    }
}

/// Parameters for the `web.search` tool call.
#[derive(Debug, Deserialize)]
struct WebSearchParams {
    query: String,
    count: Option<u64>,
}

/// A single result entry from the Brave Search API.
#[derive(Debug, Deserialize)]
struct BraveSearchResult {
    title: String,
    url: String,
    description: Option<String>,
}

/// The `web` container returned by the Brave API response.
#[derive(Debug, Deserialize)]
struct BraveWebResults {
    results: Vec<BraveSearchResult>,
}

/// Top-level Brave Search API response.
#[derive(Debug, Deserialize)]
struct BraveApiResponse {
    web: Option<BraveWebResults>,
}

#[async_trait]
impl BuiltInHandler for WebSearchTool {
    /// Execute a web search via the Brave Search API.
    ///
    /// Flow:
    /// 1. Parse `{"query": "...", "count": N}` from JSON parameters
    /// 2. Reject empty query
    /// 3. Clamp count to `MAX_COUNT`
    /// 4. Send GET to Brave API with API key header
    /// 5. Parse response and format as numbered list
    /// 6. Return structured result with `text` and `count` fields
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        // 1. Parse parameters.
        let params: WebSearchParams = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid web.search parameters: {e}")))?;

        // 2. Reject empty query.
        if params.query.trim().is_empty() {
            return Err(StewardError::Tool(
                "search query cannot be empty".to_string(),
            ));
        }

        // 3. Clamp count.
        let count = params.count.unwrap_or(DEFAULT_COUNT).min(MAX_COUNT);

        debug!(query = %params.query, count = count, "executing web search");

        // 4. Send request.
        let response = self
            .client
            .get(BRAVE_API_URL)
            .header("Accept", "application/json")
            .header("X-Subscription-Token", &self.api_key)
            .query(&[("q", params.query.as_str()), ("count", &count.to_string())])
            .send()
            .await
            .map_err(|e| {
                warn!(error = %e, "web search request failed");
                StewardError::Tool(format!("web search request failed: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!(status = %status, "Brave Search API returned error");
            return Ok(ToolResult {
                success: false,
                output: serde_json::json!({
                    "error": format!("Brave API returned status {status}"),
                    "body": body,
                }),
                error: Some(format!("Brave API error: {status}")),
            });
        }

        // 5. Parse and format results.
        let api_resp: BraveApiResponse = response
            .json()
            .await
            .map_err(|e| StewardError::Tool(format!("failed to parse Brave API response: {e}")))?;

        let results = api_resp.web.map(|w| w.results).unwrap_or_default();

        if results.is_empty() {
            return Ok(ToolResult {
                success: true,
                output: serde_json::json!({"text": "No results found.", "count": 0}),
                error: None,
            });
        }

        let mut formatted = String::new();
        for (i, result) in results.iter().enumerate() {
            let snippet = result.description.as_deref().unwrap_or("(no snippet)");
            formatted.push_str(&format!(
                "{}. {}\n   URL: {}\n   {}\n\n",
                i + 1,
                result.title,
                result.url,
                snippet,
            ));
        }
        let formatted = formatted.trim_end().to_string();

        // 6. Return structured result.
        Ok(ToolResult {
            success: true,
            output: serde_json::json!({"text": formatted, "count": results.len()}),
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Tool definition ==========

    #[test]
    fn test_tool_definition_name_source_tier() {
        let def = WebSearchTool::tool_definition();
        assert_eq!(def.name, "web.search");
        assert!(matches!(def.source, ToolSource::BuiltIn));
        assert_eq!(def.permission_tier, PermissionTier::LogAndExecute);
    }

    #[test]
    fn test_tool_definition_has_query_required() {
        let def = WebSearchTool::tool_definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("query")));
    }

    #[test]
    fn test_tool_definition_count_is_optional() {
        let def = WebSearchTool::tool_definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(!required.iter().any(|v| v.as_str() == Some("count")));
        // count is defined in properties but not required
        assert!(def.input_schema["properties"]["count"].is_object());
    }

    // ========== Count clamping ==========

    #[test]
    fn test_count_clamped_to_max() {
        assert_eq!(20_u64.min(MAX_COUNT), MAX_COUNT);
        assert_eq!(10_u64.min(MAX_COUNT), MAX_COUNT);
        assert_eq!(5_u64.min(MAX_COUNT), 5);
    }

    // ========== Brave API response parsing ==========

    #[test]
    fn test_parse_brave_response_with_results() {
        let json = serde_json::json!({
            "web": {
                "results": [
                    {
                        "title": "Test Title",
                        "url": "https://example.com",
                        "description": "A test snippet"
                    },
                    {
                        "title": "No Snippet",
                        "url": "https://nosnippet.com"
                    }
                ]
            }
        });
        let resp: BraveApiResponse = serde_json::from_value(json).unwrap();
        let results = resp.web.unwrap().results;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].title, "Test Title");
        assert_eq!(results[0].url, "https://example.com");
        assert_eq!(results[0].description.as_deref(), Some("A test snippet"));
        assert_eq!(results[1].description, None);
    }

    #[test]
    fn test_parse_brave_response_no_web_field() {
        let json = serde_json::json!({});
        let resp: BraveApiResponse = serde_json::from_value(json).unwrap();
        assert!(resp.web.is_none());
    }

    #[test]
    fn test_parse_brave_response_empty_results() {
        let json = serde_json::json!({"web": {"results": []}});
        let resp: BraveApiResponse = serde_json::from_value(json).unwrap();
        assert!(resp.web.unwrap().results.is_empty());
    }

    // ========== Result formatting ==========

    #[test]
    fn test_format_results_numbered_correctly() {
        let results = [
            BraveSearchResult {
                title: "First Result".to_string(),
                url: "https://first.com".to_string(),
                description: Some("First snippet".to_string()),
            },
            BraveSearchResult {
                title: "Second Result".to_string(),
                url: "https://second.com".to_string(),
                description: None,
            },
        ];

        let mut formatted = String::new();
        for (i, result) in results.iter().enumerate() {
            let snippet = result.description.as_deref().unwrap_or("(no snippet)");
            formatted.push_str(&format!(
                "{}. {}\n   URL: {}\n   {}\n\n",
                i + 1,
                result.title,
                result.url,
                snippet,
            ));
        }
        let formatted = formatted.trim_end().to_string();

        assert!(formatted.starts_with("1. First Result"));
        assert!(formatted.contains("URL: https://first.com"));
        assert!(formatted.contains("First snippet"));
        assert!(formatted.contains("2. Second Result"));
        assert!(formatted.contains("URL: https://second.com"));
        assert!(formatted.contains("(no snippet)"));
    }

    // ========== Parameter validation ==========

    #[test]
    fn test_parse_params_with_query_only() {
        let params: WebSearchParams =
            serde_json::from_value(serde_json::json!({"query": "rust async"})).unwrap();
        assert_eq!(params.query, "rust async");
        assert!(params.count.is_none());
    }

    #[test]
    fn test_parse_params_with_count() {
        let params: WebSearchParams =
            serde_json::from_value(serde_json::json!({"query": "test", "count": 3})).unwrap();
        assert_eq!(params.count, Some(3));
    }

    #[test]
    fn test_parse_params_missing_query_fails() {
        let result: Result<WebSearchParams, _> =
            serde_json::from_value(serde_json::json!({"count": 5}));
        assert!(result.is_err());
    }
}
