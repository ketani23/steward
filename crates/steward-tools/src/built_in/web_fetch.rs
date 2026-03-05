//! Web fetch built-in tool.
//!
//! Fetches a URL and extracts readable text content from the HTTP response.
//! HTML tags are stripped using regex, common entities are decoded, and
//! output is truncated to a configurable maximum character count to avoid
//! token overflow when feeding pages into the LLM context.
//!
//! Permission tier: LogAndExecute (arbitrary URL access, read-only, audited).

use std::net::{IpAddr, ToSocketAddrs};

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

/// Hard cap on response body size: 1 MiB.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Request timeout in seconds.
const TIMEOUT_SECS: u64 = 30;

/// Returns `true` if `ip` falls in a private, loopback, or link-local range.
///
/// Blocked IPv4 ranges:
/// - 127.0.0.0/8    — loopback
/// - 10.0.0.0/8     — RFC-1918 private
/// - 172.16.0.0/12  — RFC-1918 private
/// - 192.168.0.0/16 — RFC-1918 private
/// - 169.254.0.0/16 — link-local / cloud IMDS
///
/// Blocked IPv6 ranges:
/// - ::1       — loopback
/// - fc00::/7  — ULA (unique local)
fn is_private_or_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

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

    /// Validate a URL against SSRF attack vectors.
    ///
    /// Rejects:
    /// - Non-http/https schemes (e.g. `file://`, `ftp://`)
    /// - URLs that resolve to private, loopback, or link-local IP addresses
    fn validate_url_safety(url: &str) -> Result<(), StewardError> {
        // Parse URL.
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| StewardError::Tool(format!("invalid URL: {e}")))?;

        // Only http and https are permitted.
        match parsed.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(StewardError::Tool(format!(
                    "URL scheme '{scheme}' is not allowed; only http and https are permitted"
                )));
            }
        }

        // Extract hostname.
        let host = parsed
            .host_str()
            .ok_or_else(|| StewardError::Tool("URL has no host".to_string()))?;

        // Resolve hostname to socket addresses via std::net.
        let port = parsed.port_or_known_default().unwrap_or(80);
        let addrs = (host, port)
            .to_socket_addrs()
            .map_err(|e| StewardError::Tool(format!("failed to resolve host '{host}': {e}")))?;

        // Block any resolution to a private or internal IP.
        for addr in addrs {
            let ip = addr.ip();
            if is_private_or_internal(ip) {
                warn!(url = %url, ip = %ip, "blocked SSRF attempt to private/internal IP");
                return Err(StewardError::Tool(format!(
                    "URL is blocked: resolves to a private or internal IP address ({ip})"
                )));
            }
        }

        Ok(())
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

    /// Truncate `text` to at most `max_chars` Unicode scalar values.
    ///
    /// Returns `(truncated_string, was_truncated)`.
    fn truncate(text: String, max_chars: usize) -> (String, bool) {
        let mut chars = text.chars();
        let out: String = chars.by_ref().take(max_chars).collect();
        let is_truncated = chars.next().is_some();
        (out, is_truncated)
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
    /// 3. Validate URL safety (SSRF protection: scheme + IP range check)
    /// 4. Send GET request with a 30-second timeout
    /// 5. Return error on non-2xx status
    /// 6. Reject early if Content-Length exceeds 1 MiB
    /// 7. Read body bytes with a 1 MiB hard cap
    /// 8. Strip HTML tags if the content type is HTML
    /// 9. Truncate to `max_chars` Unicode characters (default 8000)
    /// 10. Return structured result with `text`, `url`, `truncated`, `content_type`
    async fn execute(&self, parameters: serde_json::Value) -> Result<ToolResult, StewardError> {
        // 1. Parse parameters.
        let params: WebFetchParams = serde_json::from_value(parameters)
            .map_err(|e| StewardError::Tool(format!("invalid web.fetch parameters: {e}")))?;

        // 2. Reject empty URL.
        let url = params.url.trim().to_string();
        if url.is_empty() {
            return Err(StewardError::Tool("URL cannot be empty".to_string()));
        }

        // 3. Validate URL safety (SSRF protection).
        Self::validate_url_safety(&url)?;

        let max_chars = params.max_chars.unwrap_or(DEFAULT_MAX_CHARS);

        debug!(url = %url, max_chars = max_chars, "fetching URL");

        // 4. Send GET request.
        let response = self.client.get(&url).send().await.map_err(|e| {
            warn!(error = %e, url = %url, "web fetch request failed");
            StewardError::Tool(format!("failed to fetch URL '{url}': {e}"))
        })?;

        // 5. Return error on non-2xx status.
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

        // 6. Reject oversized responses early using Content-Length header.
        if let Some(content_length) = response.content_length() {
            if content_length as usize > MAX_BODY_BYTES {
                return Err(StewardError::Tool(format!(
                    "response too large: Content-Length {content_length} exceeds 1 MiB limit"
                )));
            }
        }

        // 7. Read body bytes with a hard 1 MiB cap.
        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| StewardError::Tool(format!("failed to read response body: {e}")))?;

        if body_bytes.len() > MAX_BODY_BYTES {
            return Err(StewardError::Tool(
                "response body exceeds 1 MiB limit".to_string(),
            ));
        }

        let body = String::from_utf8_lossy(&body_bytes).into_owned();

        // 8. Strip HTML if applicable.
        let is_html = content_type.contains("text/html") || content_type.is_empty();
        let text = if is_html {
            Self::strip_html(&body)
        } else {
            body
        };

        // 9. Truncate to max_chars Unicode characters.
        let (text, truncated) = Self::truncate(text, max_chars);

        // 10. Return structured result.
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

    // ========== SSRF URL safety ==========

    #[test]
    fn test_ssrf_blocks_localhost() {
        // localhost resolves to 127.0.0.1 via /etc/hosts
        assert!(
            WebFetchTool::validate_url_safety("http://localhost/").is_err(),
            "localhost should be blocked"
        );
    }

    #[test]
    fn test_ssrf_blocks_127_0_0_1() {
        assert!(
            WebFetchTool::validate_url_safety("http://127.0.0.1/").is_err(),
            "127.0.0.1 should be blocked"
        );
    }

    #[test]
    fn test_ssrf_blocks_imds_169_254_169_254() {
        // AWS/GCP/Azure instance metadata service
        assert!(
            WebFetchTool::validate_url_safety("http://169.254.169.254/latest/meta-data/").is_err(),
            "169.254.169.254 should be blocked"
        );
    }

    #[test]
    fn test_ssrf_blocks_private_10_range() {
        assert!(WebFetchTool::validate_url_safety("http://10.0.0.1/").is_err());
    }

    #[test]
    fn test_ssrf_blocks_private_172_range() {
        assert!(WebFetchTool::validate_url_safety("http://172.16.0.1/").is_err());
        assert!(WebFetchTool::validate_url_safety("http://172.31.255.255/").is_err());
    }

    #[test]
    fn test_ssrf_blocks_private_192_168_range() {
        assert!(WebFetchTool::validate_url_safety("http://192.168.1.1/").is_err());
    }

    #[test]
    fn test_ssrf_blocks_file_scheme() {
        assert!(WebFetchTool::validate_url_safety("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_ssrf_blocks_ftp_scheme() {
        assert!(WebFetchTool::validate_url_safety("ftp://example.com/").is_err());
    }

    #[test]
    fn test_ssrf_allows_public_ip() {
        // 1.1.1.1 is Cloudflare DNS — a known public IP
        assert!(
            WebFetchTool::validate_url_safety("https://1.1.1.1/").is_ok(),
            "public IP 1.1.1.1 should be allowed"
        );
    }

    // ========== IP range classification ==========

    #[test]
    fn test_is_private_blocks_loopback_ipv4() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_private_or_internal(ip));
    }

    #[test]
    fn test_is_private_blocks_rfc1918() {
        for addr in &[
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(is_private_or_internal(ip), "{addr} should be private");
        }
    }

    #[test]
    fn test_is_private_blocks_link_local() {
        let ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(is_private_or_internal(ip));
    }

    #[test]
    fn test_is_private_blocks_ipv6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(is_private_or_internal(ip));
    }

    #[test]
    fn test_is_private_blocks_ipv6_ula() {
        // fc00::/7 covers fc00:: through fdff::
        let ip: IpAddr = "fd12:3456:789a:1::1".parse().unwrap();
        assert!(is_private_or_internal(ip));
    }

    #[test]
    fn test_is_private_allows_public_ips() {
        for addr in &["1.1.1.1", "8.8.8.8", "208.67.222.222"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(!is_private_or_internal(ip), "{addr} should be public");
        }
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
    fn test_truncate_multibyte_chars_counted_correctly() {
        // € is 3 bytes but 1 Unicode scalar value.
        // 10_000 chars × 3 bytes = 30_000 bytes, well over max_chars=8000 chars.
        let text = "€".repeat(10_000);
        let (out, truncated) = WebFetchTool::truncate(text, 8000);
        // Exactly 8000 Unicode characters must be returned.
        assert_eq!(out.chars().count(), 8000);
        // Each € is 3 bytes → byte length must be 24_000.
        assert_eq!(out.len(), 24_000);
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
