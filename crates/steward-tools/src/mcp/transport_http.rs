//! MCP HTTP/SSE transport implementation.
//!
//! HTTP client for remote MCP servers using streamable HTTP transport
//! (MCP 2025-11-25 spec):
//! - HTTP POST for JSON-RPC requests
//! - SSE stream for server responses
//! - Session management via Mcp-Session-Id header
//! - Reconnection with Last-Event-ID support
//!
//! See `docs/architecture.md` section 8.8 for transport specification.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;

use steward_types::actions::JsonRpcMessage;
use steward_types::errors::StewardError;
use steward_types::traits::McpTransport;

// ============================================================
// Configuration
// ============================================================

/// Configuration for the HTTP/SSE MCP transport.
#[derive(Debug, Clone)]
pub struct HttpTransportConfig {
    /// Base URL of the remote MCP server (e.g., `https://mcp.example.com`).
    pub base_url: String,
    /// Additional headers to include in every request (e.g., auth tokens).
    pub auth_headers: HashMap<String, String>,
    /// Timeout for establishing a connection.
    pub connect_timeout: Duration,
    /// Timeout for reading the response body / SSE events.
    pub read_timeout: Duration,
    /// Whether to accept invalid TLS certificates (testing only).
    pub danger_accept_invalid_certs: bool,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            auth_headers: HashMap::new(),
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            danger_accept_invalid_certs: false,
        }
    }
}

// ============================================================
// SSE Event Parser
// ============================================================

/// A parsed SSE event from a `text/event-stream` response.
#[derive(Debug, Clone, Default)]
struct SseEvent {
    /// The `id:` field, used for reconnection via `Last-Event-ID`.
    id: Option<String>,
    /// The `event:` field (event type).
    event: Option<String>,
    /// The `data:` field (accumulated across multiple `data:` lines).
    data: String,
}

/// Parse a raw SSE text chunk into individual events.
///
/// SSE events are separated by blank lines (`\n\n`). Each event can contain
/// `id:`, `event:`, `data:`, and `retry:` fields.
fn parse_sse_events(chunk: &str) -> Vec<SseEvent> {
    let mut events = Vec::new();
    // Split on double-newline boundaries to get individual events.
    for raw_event in chunk.split("\n\n") {
        let trimmed = raw_event.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut event = SseEvent::default();
        let mut has_data = false;

        for line in trimmed.lines() {
            if line.starts_with(':') {
                // Comment line — skip.
                continue;
            }

            let (field, value) = if let Some(colon_pos) = line.find(':') {
                let field = &line[..colon_pos];
                let value = line[colon_pos + 1..]
                    .strip_prefix(' ')
                    .unwrap_or(&line[colon_pos + 1..]);
                (field, value)
            } else {
                // Field with no value.
                (line, "")
            };

            match field {
                "id" => {
                    event.id = Some(value.to_string());
                }
                "event" => {
                    event.event = Some(value.to_string());
                }
                "data" => {
                    if has_data {
                        event.data.push('\n');
                    }
                    event.data.push_str(value);
                    has_data = true;
                }
                // `retry` and unknown fields are ignored.
                _ => {}
            }
        }

        if has_data {
            events.push(event);
        }
    }
    events
}

// ============================================================
// Transport State
// ============================================================

/// Internal mutable state shared across send/recv operations.
struct TransportState {
    /// The `Mcp-Session-Id` header value returned by the server.
    session_id: Option<String>,
    /// The last SSE event ID received, for reconnection.
    last_event_id: Option<String>,
    /// Whether the transport is currently connected.
    connected: bool,
    /// Buffer of received JSON-RPC messages not yet consumed by `recv()`.
    recv_buffer: Vec<JsonRpcMessage>,
}

// ============================================================
// McpHttpTransport
// ============================================================

/// HTTP/SSE transport for remote MCP servers.
///
/// Implements the MCP 2025-11-25 streamable HTTP transport:
/// - `send()`: HTTP POST with JSON-RPC body to the server endpoint
/// - `recv()`: Parses SSE events from the response stream
/// - Session management via `Mcp-Session-Id` header
/// - Reconnection support via `Last-Event-ID` header
///
/// # Thread Safety
///
/// Uses internal `Mutex` for shared state. Safe to use from multiple tasks
/// after wrapping in `Arc`.
pub struct McpHttpTransport {
    config: HttpTransportConfig,
    client: reqwest::Client,
    state: Arc<Mutex<TransportState>>,
}

impl McpHttpTransport {
    /// Create a new HTTP/SSE transport with the given configuration.
    ///
    /// Builds a `reqwest::Client` with the configured timeouts and TLS settings.
    pub fn new(config: HttpTransportConfig) -> Result<Self, StewardError> {
        let mut client_builder = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.read_timeout);

        if config.danger_accept_invalid_certs {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let client = client_builder
            .build()
            .map_err(|e| StewardError::Mcp(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            config,
            client,
            state: Arc::new(Mutex::new(TransportState {
                session_id: None,
                last_event_id: None,
                connected: true,
                recv_buffer: Vec::new(),
            })),
        })
    }

    /// Build the full endpoint URL for the MCP server.
    fn endpoint_url(&self) -> String {
        let base = self.config.base_url.trim_end_matches('/');
        format!("{base}/mcp")
    }

    /// Build common headers for a request, including session and auth headers.
    async fn build_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();

        // Content-Type for JSON-RPC POST.
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        // Accept SSE responses.
        headers.insert(
            reqwest::header::ACCEPT,
            "text/event-stream, application/json".parse().unwrap(),
        );

        // Auth headers from config.
        for (key, value) in &self.config.auth_headers {
            if let (Ok(name), Ok(val)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                reqwest::header::HeaderValue::from_str(value),
            ) {
                headers.insert(name, val);
            }
        }

        // Session ID if we have one.
        let state = self.state.lock().await;
        if let Some(ref session_id) = state.session_id {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(session_id) {
                headers.insert(
                    reqwest::header::HeaderName::from_static("mcp-session-id"),
                    val,
                );
            }
        }

        // Last-Event-ID for reconnection.
        if let Some(ref last_id) = state.last_event_id {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(last_id) {
                headers.insert(
                    reqwest::header::HeaderName::from_static("last-event-id"),
                    val,
                );
            }
        }

        headers
    }

    /// Process SSE events from a response body text, extracting JSON-RPC messages.
    async fn process_sse_body(&self, body: &str) -> Result<Vec<JsonRpcMessage>, StewardError> {
        let events = parse_sse_events(body);
        let mut messages = Vec::new();

        let mut state = self.state.lock().await;

        for event in events {
            // Track the last event ID for reconnection.
            if let Some(ref id) = event.id {
                state.last_event_id = Some(id.clone());
            }

            // Only process "message" events or events with no explicit type
            // (default SSE event type is "message").
            let is_message = event.event.as_deref().is_none_or(|e| e == "message");

            if is_message && !event.data.is_empty() {
                match serde_json::from_str::<JsonRpcMessage>(&event.data) {
                    Ok(msg) => messages.push(msg),
                    Err(e) => {
                        tracing::warn!(
                            data = event.data,
                            error = %e,
                            "failed to parse SSE event data as JSON-RPC message"
                        );
                    }
                }
            }
        }

        Ok(messages)
    }

    /// Extract and store the session ID from response headers.
    async fn capture_session_id(&self, headers: &reqwest::header::HeaderMap) {
        if let Some(session_id) = headers.get("mcp-session-id") {
            if let Ok(value) = session_id.to_str() {
                let mut state = self.state.lock().await;
                state.session_id = Some(value.to_string());
                tracing::debug!(session_id = value, "captured MCP session ID");
            }
        }
    }

    /// Classify an HTTP error status code.
    ///
    /// - 4xx: permanent errors (client-side issue, won't help to retry)
    /// - 5xx: retryable errors (server-side issue, may succeed on retry)
    fn classify_http_error(status: reqwest::StatusCode) -> StewardError {
        if status.is_client_error() {
            StewardError::Mcp(format!(
                "permanent HTTP error {status}: client request was rejected"
            ))
        } else if status.is_server_error() {
            StewardError::Mcp(format!(
                "retryable HTTP error {status}: server encountered an error"
            ))
        } else {
            StewardError::Mcp(format!("unexpected HTTP status {status}"))
        }
    }
}

#[async_trait]
impl McpTransport for McpHttpTransport {
    /// Send a JSON-RPC message to the MCP server via HTTP POST.
    ///
    /// The response may be:
    /// - `application/json`: A single JSON-RPC response (buffered for `recv()`)
    /// - `text/event-stream`: An SSE stream with one or more JSON-RPC messages
    ///
    /// Session ID is captured from the `Mcp-Session-Id` response header.
    async fn send(&mut self, message: JsonRpcMessage) -> Result<(), StewardError> {
        {
            let state = self.state.lock().await;
            if !state.connected {
                return Err(StewardError::Mcp("transport is closed".to_string()));
            }
        }

        let url = self.endpoint_url();
        let headers = self.build_headers().await;
        let body = serde_json::to_string(&message)?;

        tracing::debug!(
            url = url,
            method = ?message.method,
            id = ?message.id,
            "sending JSON-RPC message via HTTP POST"
        );

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    StewardError::Timeout(format!("HTTP request timed out: {e}"))
                } else if e.is_connect() {
                    StewardError::Mcp(format!("failed to connect to MCP server: {e}"))
                } else {
                    StewardError::Mcp(format!("HTTP request failed: {e}"))
                }
            })?;

        // Capture session ID from response headers.
        self.capture_session_id(response.headers()).await;

        let status = response.status();
        if !status.is_success() {
            return Err(Self::classify_http_error(status));
        }

        // Determine response content type to choose parsing strategy.
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let response_body = response
            .text()
            .await
            .map_err(|e| StewardError::Mcp(format!("failed to read response body: {e}")))?;

        if response_body.is_empty() {
            // Some methods (like notifications) may return empty 2xx responses.
            return Ok(());
        }

        if content_type.contains("text/event-stream") {
            // Parse SSE events and buffer resulting messages.
            let messages = self.process_sse_body(&response_body).await?;
            if !messages.is_empty() {
                let mut state = self.state.lock().await;
                state.recv_buffer.extend(messages);
            }
        } else {
            // Treat as a single JSON-RPC response (application/json or fallback).
            match serde_json::from_str::<JsonRpcMessage>(&response_body) {
                Ok(msg) => {
                    let mut state = self.state.lock().await;
                    state.recv_buffer.push(msg);
                }
                Err(e) => {
                    tracing::warn!(
                        body = response_body,
                        error = %e,
                        "failed to parse response as JSON-RPC message"
                    );
                }
            }
        }

        Ok(())
    }

    /// Receive the next JSON-RPC message from the buffer.
    ///
    /// Messages are buffered from SSE events or JSON responses received during
    /// `send()`. Returns `Err` if the transport is closed and the buffer is empty.
    async fn recv(&mut self) -> Result<JsonRpcMessage, StewardError> {
        let mut state = self.state.lock().await;

        if let Some(msg) = state.recv_buffer.first().cloned() {
            state.recv_buffer.remove(0);
            return Ok(msg);
        }

        if !state.connected {
            return Err(StewardError::Mcp(
                "transport is closed and no buffered messages".to_string(),
            ));
        }

        Err(StewardError::Mcp(
            "no messages available; call send() first to receive responses".to_string(),
        ))
    }

    /// Close the transport connection.
    ///
    /// Marks the transport as disconnected and clears any buffered messages.
    async fn close(&mut self) -> Result<(), StewardError> {
        let mut state = self.state.lock().await;
        state.connected = false;
        state.recv_buffer.clear();
        tracing::info!("HTTP/SSE transport closed");
        Ok(())
    }

    /// Check if the transport is still connected.
    fn is_connected(&self) -> bool {
        // Use try_lock to avoid blocking in a sync context.
        match self.state.try_lock() {
            Ok(state) => state.connected,
            // If we can't acquire the lock, the transport is likely in use (connected).
            Err(_) => true,
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::response::Response;
    use axum::routing::post;
    use axum::Router;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::net::TcpListener;

    /// Start a test server and return its base URL.
    async fn start_test_server(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn test_config(base_url: &str) -> HttpTransportConfig {
        HttpTransportConfig {
            base_url: base_url.to_string(),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            ..Default::default()
        }
    }

    fn make_request(method: &str, id: u64) -> JsonRpcMessage {
        JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::Value::Number(id.into())),
            method: Some(method.to_string()),
            params: Some(serde_json::json!({})),
            result: None,
            error: None,
        }
    }

    fn make_response(id: u64, result: serde_json::Value) -> JsonRpcMessage {
        JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::Value::Number(id.into())),
            method: None,
            params: None,
            result: Some(result),
            error: None,
        }
    }

    // ----------------------------------------------------------
    // Test: SSE event parsing
    // ----------------------------------------------------------

    #[test]
    fn test_parse_single_sse_event() {
        let raw = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}\n\n";
        let events = parse_sse_events(raw);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].data,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}"
        );
        assert!(events[0].id.is_none());
        assert!(events[0].event.is_none());
    }

    #[test]
    fn test_parse_multiple_sse_events() {
        let raw = "\
id: evt-1\n\
event: message\n\
data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"first\"}\n\
\n\
id: evt-2\n\
event: message\n\
data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"second\"}\n\
\n";
        let events = parse_sse_events(raw);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id.as_deref(), Some("evt-1"));
        assert_eq!(events[0].event.as_deref(), Some("message"));
        assert!(events[0].data.contains("\"first\""));
        assert_eq!(events[1].id.as_deref(), Some("evt-2"));
        assert!(events[1].data.contains("\"second\""));
    }

    #[test]
    fn test_parse_sse_multiline_data() {
        let raw = "data: line1\ndata: line2\ndata: line3\n\n";
        let events = parse_sse_events(raw);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "line1\nline2\nline3");
    }

    #[test]
    fn test_parse_sse_with_comments() {
        let raw = ": this is a comment\ndata: {\"jsonrpc\":\"2.0\"}\n\n";
        let events = parse_sse_events(raw);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "{\"jsonrpc\":\"2.0\"}");
    }

    #[test]
    fn test_parse_sse_empty_input() {
        let events = parse_sse_events("");
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_sse_no_data_field_skipped() {
        let raw = "id: 123\nevent: ping\n\n";
        let events = parse_sse_events(raw);
        assert!(
            events.is_empty(),
            "events with no data field should be skipped"
        );
    }

    // ----------------------------------------------------------
    // Test: send/recv round trip with JSON response
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_send_recv_json_response() {
        let response_msg = make_response(1, serde_json::json!({"tools": []}));
        let response_body = serde_json::to_string(&response_msg).unwrap();

        let app = Router::new().route(
            "/mcp",
            post(move || {
                let body = response_body.clone();
                async move {
                    Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );

        let base_url = start_test_server(app).await;
        let config = test_config(&base_url);
        let mut transport = McpHttpTransport::new(config).unwrap();

        let request = make_request("tools/list", 1);
        transport.send(request).await.unwrap();

        let received = transport.recv().await.unwrap();
        assert_eq!(received.id, Some(serde_json::Value::Number(1.into())));
        assert!(received.result.is_some());
    }

    // ----------------------------------------------------------
    // Test: send/recv round trip with SSE response
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_send_recv_sse_response() {
        let sse_body = "\
id: evt-1\n\
data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\
\n";

        let app = Router::new().route(
            "/mcp",
            post(move || {
                let body = sse_body.to_string();
                async move {
                    Response::builder()
                        .status(200)
                        .header("content-type", "text/event-stream")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );

        let base_url = start_test_server(app).await;
        let config = test_config(&base_url);
        let mut transport = McpHttpTransport::new(config).unwrap();

        transport.send(make_request("tools/list", 1)).await.unwrap();

        let received = transport.recv().await.unwrap();
        assert_eq!(received.id, Some(serde_json::Value::Number(1.into())));
        assert!(received.result.is_some());
    }

    // ----------------------------------------------------------
    // Test: SSE stream with multiple events buffered
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_sse_multiple_events_buffered() {
        let sse_body = "\
id: e1\n\
data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"first\"}\n\
\n\
id: e2\n\
data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"second\"}\n\
\n\
id: e3\n\
data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":\"third\"}\n\
\n";

        let app = Router::new().route(
            "/mcp",
            post(move || {
                let body = sse_body.to_string();
                async move {
                    Response::builder()
                        .status(200)
                        .header("content-type", "text/event-stream")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );

        let base_url = start_test_server(app).await;
        let config = test_config(&base_url);
        let mut transport = McpHttpTransport::new(config).unwrap();

        transport.send(make_request("test", 1)).await.unwrap();

        // Should receive three buffered messages in order.
        let msg1 = transport.recv().await.unwrap();
        let msg2 = transport.recv().await.unwrap();
        let msg3 = transport.recv().await.unwrap();

        assert_eq!(msg1.id, Some(serde_json::Value::Number(1.into())));
        assert_eq!(msg2.id, Some(serde_json::Value::Number(2.into())));
        assert_eq!(msg3.id, Some(serde_json::Value::Number(3.into())));

        // Fourth recv should fail — buffer is empty.
        assert!(transport.recv().await.is_err());
    }

    // ----------------------------------------------------------
    // Test: session ID tracking
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_session_id_tracking() {
        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let app = Router::new().route(
            "/mcp",
            post(move |req: Request| {
                let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count == 0 {
                        // First request: no session ID expected, return one.
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .header("mcp-session-id", "session-abc-123")
                            .body(Body::from(
                                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"init\"}",
                            ))
                            .unwrap()
                    } else {
                        // Second request: verify session ID was sent.
                        let has_session = req
                            .headers()
                            .get("mcp-session-id")
                            .and_then(|v| v.to_str().ok())
                            .map(|v| v == "session-abc-123")
                            .unwrap_or(false);

                        let result = if has_session {
                            "session_confirmed"
                        } else {
                            "session_missing"
                        };

                        Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .header("mcp-session-id", "session-abc-123")
                            .body(Body::from(format!(
                                "{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"{result}\"}}"
                            )))
                            .unwrap()
                    }
                }
            }),
        );

        let base_url = start_test_server(app).await;
        let config = test_config(&base_url);
        let mut transport = McpHttpTransport::new(config).unwrap();

        // First request — should receive and store session ID.
        transport.send(make_request("initialize", 1)).await.unwrap();
        let _ = transport.recv().await.unwrap();

        // Verify session ID is stored.
        {
            let state = transport.state.lock().await;
            assert_eq!(state.session_id.as_deref(), Some("session-abc-123"));
        }

        // Second request — should include session ID in headers.
        transport.send(make_request("tools/list", 2)).await.unwrap();
        let msg = transport.recv().await.unwrap();
        assert_eq!(
            msg.result,
            Some(serde_json::Value::String("session_confirmed".to_string()))
        );
    }

    // ----------------------------------------------------------
    // Test: Last-Event-ID for reconnection
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_last_event_id_reconnection() {
        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let app = Router::new().route(
            "/mcp",
            post(move |req: Request| {
                let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count == 0 {
                        // First response: SSE with event IDs.
                        let sse = "id: evt-42\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"data\"}\n\n";
                        Response::builder()
                            .status(200)
                            .header("content-type", "text/event-stream")
                            .body(Body::from(sse))
                            .unwrap()
                    } else {
                        // Second request: check Last-Event-ID header.
                        let last_event_id = req
                            .headers()
                            .get("last-event-id")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("none")
                            .to_string();

                        let body = format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"{last_event_id}\"}}"
                        );
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap()
                    }
                }
            }),
        );

        let base_url = start_test_server(app).await;
        let config = test_config(&base_url);
        let mut transport = McpHttpTransport::new(config).unwrap();

        // First request gets SSE response with event ID "evt-42".
        transport.send(make_request("subscribe", 1)).await.unwrap();
        let _ = transport.recv().await.unwrap();

        // Verify last event ID is stored.
        {
            let state = transport.state.lock().await;
            assert_eq!(state.last_event_id.as_deref(), Some("evt-42"));
        }

        // Second request should include Last-Event-ID header.
        transport
            .send(make_request("resubscribe", 2))
            .await
            .unwrap();
        let msg = transport.recv().await.unwrap();
        assert_eq!(
            msg.result,
            Some(serde_json::Value::String("evt-42".to_string()))
        );
    }

    // ----------------------------------------------------------
    // Test: HTTP 404 (permanent error)
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_http_404_permanent_error() {
        let app = Router::new().route(
            "/mcp",
            post(|| async {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from("not found"))
                    .unwrap()
            }),
        );

        let base_url = start_test_server(app).await;
        let config = test_config(&base_url);
        let mut transport = McpHttpTransport::new(config).unwrap();

        let result = transport.send(make_request("test", 1)).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("permanent"),
            "expected permanent error, got: {err}"
        );
    }

    // ----------------------------------------------------------
    // Test: HTTP 500 (retryable error)
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_http_500_retryable_error() {
        let app = Router::new().route(
            "/mcp",
            post(|| async {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("internal server error"))
                    .unwrap()
            }),
        );

        let base_url = start_test_server(app).await;
        let config = test_config(&base_url);
        let mut transport = McpHttpTransport::new(config).unwrap();

        let result = transport.send(make_request("test", 1)).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("retryable"),
            "expected retryable error, got: {err}"
        );
    }

    // ----------------------------------------------------------
    // Test: connection timeout
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_connection_timeout() {
        // Use a non-routable address to trigger a connection timeout.
        let config = HttpTransportConfig {
            base_url: "http://192.0.2.1:1".to_string(), // TEST-NET, non-routable
            connect_timeout: Duration::from_millis(100),
            read_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let mut transport = McpHttpTransport::new(config).unwrap();

        let result = transport.send(make_request("test", 1)).await;
        assert!(result.is_err());
    }

    // ----------------------------------------------------------
    // Test: close and is_connected
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_close_and_is_connected() {
        let config = HttpTransportConfig {
            base_url: "http://localhost:0".to_string(),
            ..Default::default()
        };
        let mut transport = McpHttpTransport::new(config).unwrap();

        assert!(transport.is_connected());

        transport.close().await.unwrap();

        assert!(!transport.is_connected());

        // Send should fail after close.
        let result = transport.send(make_request("test", 1)).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("closed"));
    }

    // ----------------------------------------------------------
    // Test: recv on empty buffer
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_recv_empty_buffer_returns_error() {
        let config = HttpTransportConfig {
            base_url: "http://localhost:0".to_string(),
            ..Default::default()
        };
        let mut transport = McpHttpTransport::new(config).unwrap();

        let result = transport.recv().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no messages"));
    }

    // ----------------------------------------------------------
    // Test: auth headers sent with request
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_auth_headers_included() {
        let app = Router::new().route(
            "/mcp",
            post(|req: Request| async move {
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("none")
                    .to_string();

                let body = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{auth}\"}}");
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap()
            }),
        );

        let base_url = start_test_server(app).await;
        let mut config = test_config(&base_url);
        config.auth_headers.insert(
            "authorization".to_string(),
            "Bearer test-token-xyz".to_string(),
        );

        let mut transport = McpHttpTransport::new(config).unwrap();
        transport.send(make_request("test", 1)).await.unwrap();

        let msg = transport.recv().await.unwrap();
        assert_eq!(
            msg.result,
            Some(serde_json::Value::String(
                "Bearer test-token-xyz".to_string()
            ))
        );
    }

    // ----------------------------------------------------------
    // Test: TLS configuration (config-only)
    // ----------------------------------------------------------

    #[test]
    fn test_tls_config_default_rejects_invalid_certs() {
        let config = HttpTransportConfig {
            base_url: "https://localhost".to_string(),
            danger_accept_invalid_certs: false,
            ..Default::default()
        };
        // Should build successfully with default (strict) TLS.
        let transport = McpHttpTransport::new(config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_tls_config_accepts_invalid_certs_when_enabled() {
        let config = HttpTransportConfig {
            base_url: "https://localhost".to_string(),
            danger_accept_invalid_certs: true,
            ..Default::default()
        };
        // Should build successfully with permissive TLS.
        let transport = McpHttpTransport::new(config);
        assert!(transport.is_ok());
    }

    // ----------------------------------------------------------
    // Test: empty response body (notification acknowledgement)
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_empty_response_body_accepted() {
        let app = Router::new().route(
            "/mcp",
            post(|| async {
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Body::empty())
                    .unwrap()
            }),
        );

        let base_url = start_test_server(app).await;
        let config = test_config(&base_url);
        let mut transport = McpHttpTransport::new(config).unwrap();

        // Sending a notification — empty response is fine.
        let notification = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some("notifications/initialized".to_string()),
            params: None,
            result: None,
            error: None,
        };
        let result = transport.send(notification).await;
        assert!(result.is_ok());
    }

    // ----------------------------------------------------------
    // Test: request body is valid JSON-RPC
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_request_body_is_valid_json_rpc() {
        let app = Router::new().route(
            "/mcp",
            post(|req: Request| async move {
                let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

                // Verify it's a valid JSON-RPC 2.0 message.
                assert_eq!(parsed["jsonrpc"], "2.0");
                assert!(parsed.get("method").is_some());

                // Echo the method back as the result.
                let method = parsed["method"].as_str().unwrap_or("unknown");
                let body = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{method}\"}}");
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap()
            }),
        );

        let base_url = start_test_server(app).await;
        let config = test_config(&base_url);
        let mut transport = McpHttpTransport::new(config).unwrap();

        transport.send(make_request("tools/list", 1)).await.unwrap();

        let msg = transport.recv().await.unwrap();
        assert_eq!(
            msg.result,
            Some(serde_json::Value::String("tools/list".to_string()))
        );
    }
}
