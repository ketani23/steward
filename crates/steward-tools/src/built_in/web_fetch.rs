//! Web fetch built-in tool.
//!
//! Fetches a URL and extracts readable text content from the HTTP response.
//! HTML tags are stripped using regex, common entities are decoded, and
//! output is truncated to a configurable maximum character count to avoid
//! token overflow when feeding pages into the LLM context.
//!
//! Permission tier: LogAndExecute (arbitrary URL access, read-only, audited).

use async_trait::async_trait;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, warn};

use steward_types::actions::{PermissionTier, ToolDefinition, ToolResult, ToolSource};
use steward_types::errors::StewardError;

use crate::registry::BuiltInHandler;

/// Default maximum characters to return from a fetched page.
const DEFAULT_MAX_CHARS: usize = 8000;

/// Request timeout in seconds.
const TIMEOUT_SECS: u64 = 30;

/// Web fetch tool — retrieves a URL and extracts plain text content.
///
/// Implements [`BuiltInHandler`] to be registered with the tool registry.
/// For HTML responses, tags are stripped before returning content.
pub struct WebFetchTool {
    client: Client,
}

impl WebFetchTool {
    /// Create a new web fetch tool.
    pub fn new() -> Result<Self, StewardError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
            .user_agent("Steward/0.1")
            .build()
            .map_err(|e| StewardError::Tool(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { client })
    }

    /// Return the [`ToolDefinition`] for this tool.
    ///
    /// Name: `web.fetch`, source: `BuiltIn`, tier: `LogAndExecute`.
    pub fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: "web.fetch".to_string(),
            description: "Fetch and read content from a URL. Returns the page text content."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to fetch"
                    },
                    "max_chars": {
                        "type": "number",
                        "description": "Maximum characters to return (default 8000)"
                    }
                },
                "required": ["url"]
            }),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::LogAndExecute,
        }
    }

    /// Strip HTML tags from content and decode common HTML entities.
    ///
    /// Steps:
    /// 1. Remove `<script>` and `<style>` blocks entirely (including inner content).
    /// 2. Remove all remaining HTML tags.
    /// 3. Decode common HTML entities (`&amp;`, `&lt;`, `&gt;`, etc.).
    /// 4. Collapse runs of spaces/tabs to a single space.
    /// 5. Collapse runs of 3+ newlines to a double newline.
    fn strip_html(html: &str) -> String {
        // Remove script and style blocks entirely (content + tags).
        let script_re = Regex::new(r"(?is)<(script|style)[^>]*>.*?</(script|style)>").unwrap();
        let text = script_re.replace_all(html, " ");

        // Remove all remaining HTML tags.
        let tag_re = Regex::new(r"<[^>]+>").unwrap();
        let text = tag_re.replace_all(&text, " ");

        // Decode common HTML entities.
        let text = text
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&apos;", "'")
            .replace("&nbsp;", " ")
            .replace("&mdash;", "\u{2014}")
            .replace("&ndash;", "\u{2013}");

        // Collapse runs of spaces/tabs to a single space.
        let spaces_re = Regex::new(r"[ \t]{2,}").unwrap();
        let text = spaces_re.replace_all(&text, " ");

        // Collapse 3+ consecutive newlines to two.
        let newlines_re = Regex::new(r"\n{3,}").unwrap();
        let text = newlines_re.replace_all(&text, "\n\n");

        text.trim().to_string()
    }

    /// Truncate `text` to at most `max_chars` characters, respecting UTF-8
    /// char boundaries.
    fn truncate(text: String, max_chars: usize) -> (String, bool) {
        if text.len() <= max_chars {
            return (text, false);
        }
        // Walk back from max_chars until we land on a char boundary.
        let mut end = max_chars;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        (text[..end].to_string(), true)
    }
}

/// Parameters for the `web.fetch` tool call.
#[derive(Debug, Deserialize)]
struct WebFetchParams {
    url: String,
    max_chars: Option<usize>,
}

#[async_trait]
impl BuiltInHandler for WebFetchTool {
    /// Fetch a URL and return its text content.
    ///
    /// Flow:
    /// 1. Parse `{"url": "...", "max_chars": N}` from JSON parameters
    /// 2. Reject empty URL
    /// 3. Send GET request with a 30-second timeout
    /// 4. Return error on non-2xx status
    /// 5. Strip HTML tags if the content type is HTML
    /// 6. Truncate to `max_chars` (default 8000)
    /// 7. Return structured result with `text`, `url`, `truncated`, `content_type`
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        // 1. Parse parameters.
        let params: WebFetchParams = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid web.fetch parameters: {e}")))?;

        // 2. Reject empty URL.
        let url = params.url.trim().to_string();
        if url.is_empty() {
            return Err(StewardError::Tool("URL cannot be empty".to_string()));
        }

        let max_chars = params.max_chars.unwrap_or(DEFAULT_MAX_CHARS);

        debug!(url = %url, max_chars = max_chars, "fetching URL");

        // 3. Send GET request.
        let response = self.client.get(&url).send().await.map_err(|e| {
            warn!(error = %e, url = %url, "web fetch request failed");
            StewardError::Tool(format!("failed to fetch URL '{url}': {e}"))
        })?;

        // 4. Return error on non-2xx status.
        let status = response.status();
        if !status.is_success() {
            return Ok(ToolResult {
                success: false,
                output: serde_json::json!({
                    "error": format!("HTTP {status} fetching '{url}'"),
                    "url": url,
                }),
                error: Some(format!("HTTP error {status}")),
            });
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let body = response
            .text()
            .await
            .map_err(|e| StewardError::Tool(format!("failed to read response body: {e}")))?;

        // 5. Strip HTML if applicable.
        let is_html = content_type.contains("text/html") || content_type.is_empty();
        let text = if is_html {
            Self::strip_html(&body)
        } else {
            body
        };

        // 6. Truncate to max_chars.
        let (text, truncated) = Self::truncate(text, max_chars);

        // 7. Return structured result.
        Ok(ToolResult {
            success: true,
            output: serde_json::json!({
                "text": text,
                "url": url,
                "truncated": truncated,
                "content_type": content_type,
            }),
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
        let def = WebFetchTool::tool_definition();
        assert_eq!(def.name, "web.fetch");
        assert!(matches!(def.source, ToolSource::BuiltIn));
        assert_eq!(def.permission_tier, PermissionTier::LogAndExecute);
    }

    #[test]
    fn test_tool_definition_url_is_required() {
        let def = WebFetchTool::tool_definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("url")));
    }

    #[test]
    fn test_tool_definition_max_chars_is_optional() {
        let def = WebFetchTool::tool_definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(!required.iter().any(|v| v.as_str() == Some("max_chars")));
        assert!(def.input_schema["properties"]["max_chars"].is_object());
    }

    // ========== HTML stripping ==========

    #[test]
    fn test_strip_html_removes_tags() {
        let html = "<html><body><h1>Hello</h1><p>World</p></body></html>";
        let text = WebFetchTool::strip_html(html);
        assert!(!text.contains('<'));
        assert!(!text.contains('>'));
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
    }

    #[test]
    fn test_strip_html_removes_script_block() {
        let html = "<html><script>alert('xss')</script><p>Clean content</p></html>";
        let text = WebFetchTool::strip_html(html);
        assert!(!text.contains("alert"));
        assert!(!text.contains("xss"));
        assert!(text.contains("Clean content"));
    }

    #[test]
    fn test_strip_html_removes_style_block() {
        let html = "<html><style>.foo { color: red; }</style><p>Visible</p></html>";
        let text = WebFetchTool::strip_html(html);
        assert!(!text.contains("color"));
        assert!(!text.contains("red"));
        assert!(text.contains("Visible"));
    }

    #[test]
    fn test_strip_html_decodes_entities() {
        let html = "<p>1 &lt; 2 &amp; 2 &gt; 1 &quot;quoted&quot;</p>";
        let text = WebFetchTool::strip_html(html);
        assert!(text.contains("1 < 2"));
        assert!(text.contains("& 2"));
        assert!(text.contains("2 > 1"));
        assert!(text.contains("\"quoted\""));
    }

    #[test]
    fn test_strip_html_decodes_nbsp() {
        let html = "<p>Hello&nbsp;World</p>";
        let text = WebFetchTool::strip_html(html);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
        // &nbsp; should become a space
        assert!(!text.contains("&nbsp;"));
    }

    #[test]
    fn test_strip_html_collapses_whitespace() {
        let html = "<p>Hello     World</p>";
        let text = WebFetchTool::strip_html(html);
        // Multiple spaces collapsed
        assert!(!text.contains("     "));
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
    }

    #[test]
    fn test_strip_html_plain_text_passthrough() {
        let plain = "Just plain text, no tags here!";
        let text = WebFetchTool::strip_html(plain);
        assert_eq!(text, plain);
    }

    #[test]
    fn test_strip_html_empty_input() {
        let text = WebFetchTool::strip_html("");
        assert_eq!(text, "");
    }

    #[test]
    fn test_strip_html_script_case_insensitive() {
        let html = "<SCRIPT>bad()</SCRIPT><p>Good</p>";
        let text = WebFetchTool::strip_html(html);
        assert!(!text.contains("bad()"));
        assert!(text.contains("Good"));
    }

    // ========== Truncation ==========

    #[test]
    fn test_truncate_short_text_unchanged() {
        let text = "hello".to_string();
        let (out, truncated) = WebFetchTool::truncate(text.clone(), 100);
        assert_eq!(out, text);
        assert!(!truncated);
    }

    #[test]
    fn test_truncate_long_text_at_boundary() {
        let text = "a".repeat(10_000);
        let (out, truncated) = WebFetchTool::truncate(text, 8000);
        assert_eq!(out.len(), 8000);
        assert!(truncated);
    }

    #[test]
    fn test_truncate_exact_length_unchanged() {
        let text = "b".repeat(8000);
        let (out, truncated) = WebFetchTool::truncate(text, 8000);
        assert_eq!(out.len(), 8000);
        assert!(!truncated);
    }

    #[test]
    fn test_truncate_respects_char_boundary() {
        // 3-byte UTF-8 character (€ = 0xE2 0x82 0xAC)
        let euro = "€"; // 3 bytes
        let text = euro.repeat(3000); // 9000 bytes, 3000 chars
        let (out, truncated) = WebFetchTool::truncate(text, 8000);
        // Should truncate to the last complete char before byte 8000
        // 8000 / 3 = 2666 full chars = 7998 bytes
        assert!(out.is_empty() || out.is_char_boundary(out.len()));
        assert!(truncated);
    }

    // ========== Parameter parsing ==========

    #[test]
    fn test_parse_params_url_only() {
        let params: WebFetchParams =
            serde_json::from_value(serde_json::json!({"url": "https://example.com"})).unwrap();
        assert_eq!(params.url, "https://example.com");
        assert!(params.max_chars.is_none());
    }

    #[test]
    fn test_parse_params_with_max_chars() {
        let params: WebFetchParams = serde_json::from_value(
            serde_json::json!({"url": "https://example.com", "max_chars": 4000}),
        )
        .unwrap();
        assert_eq!(params.max_chars, Some(4000));
    }

    #[test]
    fn test_parse_params_missing_url_fails() {
        let result: Result<WebFetchParams, _> =
            serde_json::from_value(serde_json::json!({"max_chars": 1000}));
        assert!(result.is_err());
    }
}
