//! Web fetch built-in tool.
//!
//! Fetches a URL and extracts readable text content from the HTTP response.
//! HTML tags are stripped using regex, common entities are decoded, and
//! output is truncated to a configurable maximum character count to avoid
//! token overflow when feeding pages into the LLM context.
//!
//! Permission tier: LogAndExecute (arbitrary URL access, read-only, audited).
//!
//! # SSRF hardening
//!
//! Three layers of protection are applied:
//!
//! 1. **Scheme allowlist** — only `http` and `https` are permitted.
//! 2. **IP range check** — every URL (including redirect `Location` headers) is
//!    resolved via DNS and rejected if any resolved address falls in a private,
//!    loopback, or link-local range.
//! 3. **DNS pinning** — after validation the resolved address is passed to
//!    `reqwest::ClientBuilder::resolve()`, so the actual TCP connection is made
//!    to the IP that was validated, not whatever DNS returns at connect time.
//!    This prevents DNS-rebinding / TOCTOU attacks.
//!
//! Redirects are followed manually (up to [`MAX_REDIRECTS`] hops) so that
//! every hop is independently validated before the next request is sent.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use reqwest::{redirect, Client};
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

/// Maximum number of redirects to follow per fetch.
const MAX_REDIRECTS: u8 = 5;

/// Returns `true` if `ip` is NOT a globally routable address and should be blocked.
///
/// Only IPs that are clearly public and globally routable are permitted. Every
/// special-purpose or non-global range is blocked, including all of the following.
///
/// Blocked IPv4 ranges:
/// - 0.0.0.0/8          — unspecified
/// - 10.0.0.0/8         — RFC-1918 private
/// - 100.64.0.0/10      — shared address space / carrier-grade NAT (RFC 6598)
/// - 127.0.0.0/8        — loopback
/// - 169.254.0.0/16     — link-local / cloud IMDS (AWS, GCP, Azure)
/// - 172.16.0.0/12      — RFC-1918 private
/// - 192.0.0.0/24       — IETF protocol assignments (RFC 6890)
/// - 192.0.2.0/24       — TEST-NET-1 / documentation (RFC 5737)
/// - 192.88.99.0/24     — 6to4 relay anycast, deprecated (RFC 7526)
/// - 192.168.0.0/16     — RFC-1918 private
/// - 198.18.0.0/15      — network benchmarking (RFC 2544)
/// - 198.51.100.0/24    — TEST-NET-2 / documentation (RFC 5737)
/// - 203.0.113.0/24     — TEST-NET-3 / documentation (RFC 5737)
/// - 224.0.0.0/4        — multicast
/// - 255.255.255.255/32 — broadcast
///
/// Blocked IPv6 ranges:
/// - ::                 — unspecified
/// - ::1               — loopback
/// - fc00::/7          — ULA (unique local, RFC 4193)
/// - fe80::/10         — link-local
/// - ff00::/8          — multicast
/// - ::ffff:0:0/96     — IPv4-mapped (recursively checked against IPv4 rules above)
fn is_not_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || v4.is_unspecified()
                // 100.64.0.0/10 — shared address space / carrier-grade NAT (RFC 6598)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                // 192.0.0.0/24 — IETF protocol assignments (RFC 6890)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                // 192.88.99.0/24 — 6to4 relay anycast, deprecated (RFC 7526)
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
                // 198.18.0.0/15 — network benchmarking (RFC 2544)
                || (o[0] == 198 && (18..=19).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            // IPv4-mapped addresses (::ffff:0:0/96): unwrap the inner IPv4 and
            // recheck it against all IPv4 rules above. This prevents bypasses
            // via e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_not_globally_routable(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Web fetch tool — retrieves a URL and extracts plain text content.
///
/// Implements [`BuiltInHandler`] to be registered with the tool registry.
/// For HTML responses, tags are stripped before returning content.
pub struct WebFetchTool;

impl WebFetchTool {
    /// Create a new web fetch tool.
    pub fn new() -> Result<Self, StewardError> {
        Ok(Self)
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
                        "type": "integer",
                        "description": "Maximum characters to return (default 8000)"
                    }
                },
                "required": ["url"]
            }),
            source: ToolSource::BuiltIn,
            permission_tier: PermissionTier::LogAndExecute,
        }
    }

    /// Validate a URL against SSRF attack vectors and return the resolved socket address.
    ///
    /// Rejects:
    /// - Non-http/https schemes (e.g. `file://`, `ftp://`)
    /// - URLs that resolve to private, loopback, or link-local IP addresses
    ///
    /// Returns the first safe resolved [`SocketAddr`] for use with DNS pinning
    /// (`reqwest::ClientBuilder::resolve`).
    ///
    /// The DNS resolution step runs in a `spawn_blocking` thread so it does not
    /// stall the async runtime.
    async fn validate_url_safety(url: &str) -> Result<SocketAddr, StewardError> {
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

        // Extract hostname (owned so it can cross the spawn_blocking boundary).
        let host = parsed
            .host_str()
            .ok_or_else(|| StewardError::Tool("URL has no host".to_string()))?
            .to_string();

        // Resolve hostname to socket addresses in a blocking thread to avoid
        // stalling the async runtime (to_socket_addrs issues blocking syscalls).
        let port = parsed.port_or_known_default().unwrap_or(80);
        let host_for_dns = host.clone();
        let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
            (host_for_dns.as_str(), port)
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>())
        })
        .await
        .map_err(|e| StewardError::Tool(format!("DNS resolution task panicked: {e}")))?
        .map_err(|e| StewardError::Tool(format!("failed to resolve host '{host}': {e}")))?;

        // Block any resolution to a private or internal IP, and track the first safe addr.
        let mut safe_addr: Option<SocketAddr> = None;
        for addr in &addrs {
            let ip = addr.ip();
            if is_not_globally_routable(ip) {
                warn!(url = %url, ip = %ip, "blocked SSRF attempt to non-global IP");
                return Err(StewardError::Tool(format!(
                    "URL is blocked: resolves to a non-globally-routable IP address ({ip})"
                )));
            }
            if safe_addr.is_none() {
                safe_addr = Some(*addr);
            }
        }

        safe_addr
            .ok_or_else(|| StewardError::Tool(format!("no addresses resolved for host '{host}'")))
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
    /// 3. For each request hop (initial + up to MAX_REDIRECTS redirects):
    ///    a. Validate URL (SSRF: scheme allowlist + IP range check)
    ///    b. Build a per-request client with pinned DNS (prevents rebinding) and no auto-redirects
    ///    c. Send GET with a 30-second timeout
    ///    d. On 3xx, extract and re-validate the Location URL, then loop
    ///    e. On any other status, exit the loop
    /// 4. Return error on non-2xx status
    /// 5. Reject early if Content-Length exceeds 1 MiB
    /// 6. Stream body chunk-by-chunk, aborting if total exceeds 1 MiB
    /// 7. Strip HTML tags if the content type is HTML
    /// 8. Truncate to `max_chars` Unicode characters (default 8000)
    /// 9. Return structured result with `text`, `url`, `truncated`, `content_type`
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

        // 3. Manual redirect loop: validate + pin DNS at every hop.
        let mut current_url = url;
        let mut redirect_count = 0u8;

        let response = loop {
            // Validate URL safety and get the resolved address for DNS pinning.
            let resolved_addr = Self::validate_url_safety(&current_url).await?;

            // Safety: URL was successfully parsed inside `validate_url_safety` above.
            let parsed = reqwest::Url::parse(&current_url).unwrap();
            let host = parsed.host_str().unwrap().to_string();

            debug!(url = %current_url, ip = %resolved_addr, "fetching URL");

            // Build a per-request client with pinned DNS and no auto-redirects.
            // `resolve()` pins the hostname to the validated IP so that a second
            // DNS lookup cannot swap in a private address (DNS rebinding / TOCTOU).
            let client = Client::builder()
                .timeout(Duration::from_secs(TIMEOUT_SECS))
                .user_agent("Steward/0.1")
                .redirect(redirect::Policy::none())
                .resolve(&host, resolved_addr)
                .build()
                .map_err(|e| StewardError::Tool(format!("failed to build HTTP client: {e}")))?;

            let response = client.get(&current_url).send().await.map_err(|e| {
                warn!(error = %e, url = %current_url, "web fetch request failed");
                StewardError::Tool(format!("failed to fetch URL '{current_url}': {e}"))
            })?;

            if response.status().is_redirection() {
                if redirect_count >= MAX_REDIRECTS {
                    return Err(StewardError::Tool(format!(
                        "too many redirects (max {MAX_REDIRECTS})"
                    )));
                }

                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .ok_or_else(|| {
                        StewardError::Tool("redirect with no Location header".to_string())
                    })?
                    .to_str()
                    .map_err(|_| {
                        StewardError::Tool("invalid Location header encoding".to_string())
                    })?;

                // Resolve relative redirects against the current URL.
                let new_url = parsed
                    .join(location)
                    .map_err(|e| StewardError::Tool(format!("invalid redirect URL: {e}")))?;

                current_url = new_url.to_string();
                redirect_count += 1;
                continue;
            }

            break response;
        };

        let final_url = current_url;

        // 4. Return error on non-2xx status.
        let status = response.status();
        if !status.is_success() {
            return Ok(ToolResult {
                success: false,
                output: serde_json::json!({
                    "error": format!("HTTP {status} fetching '{final_url}'"),
                    "url": final_url,
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

        // 5. Reject oversized responses early using Content-Length header.
        if let Some(content_length) = response.content_length() {
            if content_length as usize > MAX_BODY_BYTES {
                return Err(StewardError::Tool(format!(
                    "response too large: Content-Length {content_length} exceeds 1 MiB limit"
                )));
            }
        }

        // 6. Stream body chunk-by-chunk with a hard 1 MiB cap.
        // Using `chunk()` instead of `bytes()` prevents buffering the entire body
        // in memory before the size check fires.
        let mut body_bytes: Vec<u8> = Vec::new();
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| StewardError::Tool(format!("failed to read response body: {e}")))?
        {
            if body_bytes.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(StewardError::Tool(
                    "response body exceeds 1 MiB limit".to_string(),
                ));
            }
            body_bytes.extend_from_slice(&chunk);
        }

        let body = String::from_utf8_lossy(&body_bytes).into_owned();

        // 7. Strip HTML if applicable.
        let is_html = content_type.contains("text/html") || content_type.is_empty();
        let text = if is_html {
            Self::strip_html(&body)
        } else {
            body
        };

        // 8. Truncate to max_chars Unicode characters.
        let (text, truncated) = Self::truncate(text, max_chars);

        // 9. Return structured result.
        Ok(ToolResult {
            success: true,
            output: serde_json::json!({
                "text": text,
                "url": final_url,
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

    #[tokio::test]
    async fn test_ssrf_blocks_localhost() {
        // localhost resolves to 127.0.0.1 via /etc/hosts
        assert!(
            WebFetchTool::validate_url_safety("http://localhost/")
                .await
                .is_err(),
            "localhost should be blocked"
        );
    }

    #[tokio::test]
    async fn test_ssrf_blocks_127_0_0_1() {
        assert!(
            WebFetchTool::validate_url_safety("http://127.0.0.1/")
                .await
                .is_err(),
            "127.0.0.1 should be blocked"
        );
    }

    #[tokio::test]
    async fn test_ssrf_blocks_imds_169_254_169_254() {
        // AWS/GCP/Azure instance metadata service
        assert!(
            WebFetchTool::validate_url_safety("http://169.254.169.254/latest/meta-data/")
                .await
                .is_err(),
            "169.254.169.254 should be blocked"
        );
    }

    #[tokio::test]
    async fn test_ssrf_blocks_private_10_range() {
        assert!(WebFetchTool::validate_url_safety("http://10.0.0.1/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_ssrf_blocks_private_172_range() {
        assert!(WebFetchTool::validate_url_safety("http://172.16.0.1/")
            .await
            .is_err());
        assert!(WebFetchTool::validate_url_safety("http://172.31.255.255/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_ssrf_blocks_private_192_168_range() {
        assert!(WebFetchTool::validate_url_safety("http://192.168.1.1/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_ssrf_blocks_file_scheme() {
        assert!(WebFetchTool::validate_url_safety("file:///etc/passwd")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_ssrf_blocks_ftp_scheme() {
        assert!(WebFetchTool::validate_url_safety("ftp://example.com/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_ssrf_allows_public_ip() {
        // 1.1.1.1 is Cloudflare DNS — a known public IP
        assert!(
            WebFetchTool::validate_url_safety("https://1.1.1.1/")
                .await
                .is_ok(),
            "public IP 1.1.1.1 should be allowed"
        );
    }

    // IPv6 SSRF bypass vectors — validate_url_safety must block these.

    #[tokio::test]
    async fn test_ssrf_blocks_ipv6_mapped_loopback() {
        // ::ffff:127.0.0.1 is an IPv4-mapped loopback address.
        assert!(
            WebFetchTool::validate_url_safety("http://[::ffff:127.0.0.1]/")
                .await
                .is_err(),
            "IPv4-mapped loopback ::ffff:127.0.0.1 should be blocked"
        );
    }

    #[tokio::test]
    async fn test_ssrf_blocks_ipv6_mapped_private_10() {
        // ::ffff:10.0.0.1 is an IPv4-mapped RFC-1918 address.
        assert!(
            WebFetchTool::validate_url_safety("http://[::ffff:10.0.0.1]/")
                .await
                .is_err(),
            "IPv4-mapped RFC-1918 ::ffff:10.0.0.1 should be blocked"
        );
    }

    #[tokio::test]
    async fn test_ssrf_blocks_ipv6_mapped_imds() {
        // ::ffff:169.254.169.254 targets the cloud IMDS via IPv4-mapped encoding.
        assert!(
            WebFetchTool::validate_url_safety("http://[::ffff:169.254.169.254]/")
                .await
                .is_err(),
            "IPv4-mapped IMDS address should be blocked"
        );
    }

    #[tokio::test]
    async fn test_ssrf_blocks_ipv6_link_local() {
        // fe80::1 is in the fe80::/10 link-local range.
        assert!(
            WebFetchTool::validate_url_safety("http://[fe80::1]/")
                .await
                .is_err(),
            "IPv6 link-local fe80::1 should be blocked"
        );
    }

    /// Validates the redirect-hop path: `validate_url_safety` is called for every
    /// Location header URL during the manual redirect loop, so any redirect to a
    /// private address is caught before the next connection is opened.
    #[tokio::test]
    async fn test_redirect_hop_private_url_is_rejected() {
        assert!(
            WebFetchTool::validate_url_safety("http://192.168.1.1/internal")
                .await
                .is_err(),
            "redirect to private IP 192.168.1.1 must be blocked"
        );
        assert!(
            WebFetchTool::validate_url_safety("http://[::ffff:10.0.0.1]/internal")
                .await
                .is_err(),
            "redirect to IPv4-mapped RFC-1918 must be blocked"
        );
    }

    // ========== IP range classification ==========

    #[test]
    fn test_is_private_blocks_loopback_ipv4() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_not_globally_routable(ip));
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
            assert!(is_not_globally_routable(ip), "{addr} should be private");
        }
    }

    #[test]
    fn test_is_private_blocks_link_local() {
        let ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(is_not_globally_routable(ip));
    }

    #[test]
    fn test_is_private_blocks_ipv6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(is_not_globally_routable(ip));
    }

    #[test]
    fn test_is_private_blocks_ipv6_ula() {
        // fc00::/7 covers fc00:: through fdff::
        let ip: IpAddr = "fd12:3456:789a:1::1".parse().unwrap();
        assert!(is_not_globally_routable(ip));
    }

    #[test]
    fn test_is_private_blocks_ipv6_link_local() {
        // fe80::/10 link-local range
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_not_globally_routable(ip));
        let ip: IpAddr = "febf::ffff".parse().unwrap();
        assert!(is_not_globally_routable(ip));
    }

    #[test]
    fn test_is_private_blocks_ipv4_mapped_loopback() {
        // ::ffff:127.0.0.1 — IPv4-mapped loopback
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_not_globally_routable(ip));
    }

    #[test]
    fn test_is_private_blocks_ipv4_mapped_rfc1918() {
        // ::ffff:10.0.0.1, ::ffff:172.16.0.1, ::ffff:192.168.0.1
        for addr in &["::ffff:10.0.0.1", "::ffff:172.16.0.1", "::ffff:192.168.0.1"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(is_not_globally_routable(ip), "{addr} should be private");
        }
    }

    #[test]
    fn test_is_private_blocks_ipv4_mapped_imds() {
        // ::ffff:169.254.169.254 — IPv4-mapped IMDS
        let ip: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_not_globally_routable(ip));
    }

    #[test]
    fn test_is_not_global_blocks_carrier_grade_nat() {
        // 100.64.0.0/10 — shared address space / carrier-grade NAT (RFC 6598)
        let ip: IpAddr = "100.64.0.0".parse().unwrap();
        assert!(
            is_not_globally_routable(ip),
            "100.64.0.0 (CGNAT) should be blocked"
        );
        let ip: IpAddr = "100.127.255.255".parse().unwrap();
        assert!(
            is_not_globally_routable(ip),
            "100.127.255.255 (CGNAT) should be blocked"
        );
    }

    #[test]
    fn test_is_not_global_blocks_benchmarking() {
        // 198.18.0.0/15 — network benchmarking (RFC 2544)
        let ip: IpAddr = "198.18.0.1".parse().unwrap();
        assert!(
            is_not_globally_routable(ip),
            "198.18.0.1 (benchmarking) should be blocked"
        );
        let ip: IpAddr = "198.19.255.255".parse().unwrap();
        assert!(
            is_not_globally_routable(ip),
            "198.19.255.255 (benchmarking) should be blocked"
        );
    }

    #[test]
    fn test_is_not_global_blocks_ietf_protocol_assignments() {
        // 192.0.0.0/24 — IETF protocol assignments (RFC 6890)
        let ip: IpAddr = "192.0.0.1".parse().unwrap();
        assert!(
            is_not_globally_routable(ip),
            "192.0.0.1 (IETF assignments) should be blocked"
        );
    }

    #[test]
    fn test_is_private_allows_public_ips() {
        for addr in &["1.1.1.1", "8.8.8.8", "208.67.222.222"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(!is_not_globally_routable(ip), "{addr} should be public");
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
