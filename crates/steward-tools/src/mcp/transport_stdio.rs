//! MCP stdio transport implementation.
//!
//! Spawns MCP servers as child processes and communicates via stdin/stdout:
//! - JSON-RPC message framing (one JSON object per line)
//! - Child process lifecycle management
//! - Stderr capture and logging
//!
//! See `docs/architecture.md` section 8.8 for transport specification.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use steward_types::actions::JsonRpcMessage;
use steward_types::errors::StewardError;
use steward_types::traits::McpTransport;

/// Configuration for spawning an MCP server child process.
#[derive(Debug, Clone)]
pub struct StdioTransportConfig {
    /// Path to the MCP server executable.
    pub command: String,
    /// Arguments to pass to the child process.
    pub args: Vec<String>,
    /// Environment variables to set for the child process.
    pub env: HashMap<String, String>,
    /// Working directory for the child process.
    pub working_dir: Option<PathBuf>,
    /// Timeout in seconds for graceful shutdown (SIGTERM) before SIGKILL.
    pub shutdown_timeout_secs: u64,
}

impl Default for StdioTransportConfig {
    fn default() -> Self {
        Self {
            command: String::new(),
            args: Vec::new(),
            env: HashMap::new(),
            working_dir: None,
            shutdown_timeout_secs: 5,
        }
    }
}

/// MCP stdio transport that spawns an MCP server as a child process.
///
/// Communicates via stdin (write JSON-RPC) and stdout (read JSON-RPC).
/// Each message is a single line of JSON followed by a newline (MCP stdio convention).
/// Stderr is captured in a background task and logged as warnings.
pub struct StdioTransport {
    config: StdioTransportConfig,
    /// The child process (None if not connected or after close).
    child: Option<Child>,
    /// Buffered reader for stdout.
    stdout_reader: Option<BufReader<tokio::process::ChildStdout>>,
    /// Writer for stdin, wrapped in Mutex for safety.
    stdin_writer: Option<tokio::process::ChildStdin>,
    /// Handle to the stderr logging task.
    stderr_task: Option<tokio::task::JoinHandle<()>>,
    /// Whether the transport has been explicitly closed.
    closed: bool,
}

impl StdioTransport {
    /// Create a new stdio transport with the given configuration.
    ///
    /// This does not spawn the child process yet — call [`connect`] to start it.
    pub fn new(config: StdioTransportConfig) -> Self {
        Self {
            config,
            child: None,
            stdout_reader: None,
            stdin_writer: None,
            stderr_task: None,
            closed: false,
        }
    }

    /// Spawn the MCP server child process and set up I/O pipes.
    ///
    /// After this call, `send()` and `recv()` can be used to communicate.
    pub async fn connect(&mut self) -> Result<(), StewardError> {
        if self.child.is_some() {
            return Err(StewardError::Mcp("transport already connected".to_string()));
        }

        let mut cmd = Command::new(&self.config.command);
        cmd.args(&self.config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .envs(&self.config.env)
            .kill_on_drop(true);

        if let Some(ref dir) = self.config.working_dir {
            cmd.current_dir(dir);
        }

        let mut child = cmd.spawn().map_err(|e| {
            StewardError::Mcp(format!(
                "failed to spawn MCP server '{}': {}",
                self.config.command, e
            ))
        })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| StewardError::Mcp("failed to capture child stdout".to_string()))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| StewardError::Mcp("failed to capture child stdin".to_string()))?;

        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| StewardError::Mcp("failed to capture child stderr".to_string()))?;

        // Spawn a background task to capture stderr and log as warnings.
        let server_name = self.config.command.clone();
        let stderr_task = tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::warn!(
                    server = %server_name,
                    "MCP server stderr: {}",
                    line
                );
            }
        });

        self.stdout_reader = Some(BufReader::new(stdout));
        self.stdin_writer = Some(stdin);
        self.child = Some(child);
        self.stderr_task = Some(stderr_task);
        self.closed = false;

        tracing::info!(
            command = %self.config.command,
            "MCP stdio transport connected"
        );

        Ok(())
    }

    /// Check if the child process has exited.
    fn check_child_alive(&mut self) -> bool {
        if let Some(ref mut child) = self.child {
            // try_wait returns Ok(Some(status)) if exited, Ok(None) if still running
            match child.try_wait() {
                Ok(Some(_status)) => false,
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }
}

#[async_trait]
impl McpTransport for StdioTransport {
    /// Send a JSON-RPC message to the MCP server via stdin.
    ///
    /// Serializes the message as a single line of JSON followed by a newline,
    /// then flushes the write buffer.
    async fn send(&mut self, message: JsonRpcMessage) -> Result<(), StewardError> {
        if self.closed {
            return Err(StewardError::Mcp("transport is closed".to_string()));
        }

        if self.stdin_writer.is_none() {
            return Err(StewardError::Mcp("transport not connected".to_string()));
        }

        // Check if child is still alive before writing
        if !self.check_child_alive() {
            return Err(StewardError::Mcp(
                "child process has exited unexpectedly".to_string(),
            ));
        }

        // Safe to unwrap: we checked is_none() above and nothing takes it between here.
        let stdin = self.stdin_writer.as_mut().unwrap();

        let json = serde_json::to_string(&message).map_err(|e| {
            StewardError::Serialization(format!("failed to serialize JSON-RPC message: {}", e))
        })?;

        stdin
            .write_all(json.as_bytes())
            .await
            .map_err(|e| StewardError::Mcp(format!("failed to write to child stdin: {}", e)))?;

        stdin.write_all(b"\n").await.map_err(|e| {
            StewardError::Mcp(format!("failed to write newline to child stdin: {}", e))
        })?;

        stdin
            .flush()
            .await
            .map_err(|e| StewardError::Mcp(format!("failed to flush child stdin: {}", e)))?;

        Ok(())
    }

    /// Receive the next JSON-RPC message from the MCP server via stdout.
    ///
    /// Reads a single line from stdout and parses it as a JSON-RPC message.
    /// Blocks until a message is available or the pipe closes.
    async fn recv(&mut self) -> Result<JsonRpcMessage, StewardError> {
        if self.closed {
            return Err(StewardError::Mcp("transport is closed".to_string()));
        }

        let reader = self
            .stdout_reader
            .as_mut()
            .ok_or_else(|| StewardError::Mcp("transport not connected".to_string()))?;

        let mut line = String::new();
        let bytes_read = reader
            .read_line(&mut line)
            .await
            .map_err(|e| StewardError::Mcp(format!("failed to read from child stdout: {}", e)))?;

        if bytes_read == 0 {
            return Err(StewardError::Mcp(
                "child process stdout closed (process likely exited)".to_string(),
            ));
        }

        let message: JsonRpcMessage = serde_json::from_str(line.trim()).map_err(|e| {
            StewardError::Mcp(format!(
                "failed to parse JSON-RPC message from child stdout: {} (raw: {:?})",
                e,
                line.trim()
            ))
        })?;

        Ok(message)
    }

    /// Close the transport by terminating the child process.
    ///
    /// Sends SIGTERM first, waits up to `shutdown_timeout_secs`, then sends SIGKILL
    /// if the process hasn't exited.
    async fn close(&mut self) -> Result<(), StewardError> {
        if self.closed {
            return Ok(());
        }

        self.closed = true;

        // Drop stdin to signal EOF to the child.
        self.stdin_writer.take();

        if let Some(ref mut child) = self.child {
            // First try graceful shutdown with SIGTERM.
            #[cfg(unix)]
            {
                if let Some(pid) = child.id() {
                    // Send SIGTERM
                    unsafe {
                        libc::kill(pid as i32, libc::SIGTERM);
                    }
                }
            }

            // On non-unix, just start_kill (sends appropriate signal).
            #[cfg(not(unix))]
            {
                let _ = child.start_kill();
            }

            // Wait with timeout for graceful exit.
            let timeout = tokio::time::Duration::from_secs(self.config.shutdown_timeout_secs);
            match tokio::time::timeout(timeout, child.wait()).await {
                Ok(Ok(status)) => {
                    tracing::info!(
                        command = %self.config.command,
                        status = %status,
                        "MCP server exited gracefully"
                    );
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        command = %self.config.command,
                        error = %e,
                        "error waiting for MCP server to exit"
                    );
                }
                Err(_) => {
                    // Timeout — force kill.
                    tracing::warn!(
                        command = %self.config.command,
                        "MCP server did not exit within timeout, sending SIGKILL"
                    );
                    let _ = child.kill().await;
                }
            }
        }

        // Clean up the child handle.
        self.child.take();
        self.stdout_reader.take();

        // Abort the stderr logging task.
        if let Some(task) = self.stderr_task.take() {
            task.abort();
        }

        tracing::info!(
            command = %self.config.command,
            "MCP stdio transport closed"
        );

        Ok(())
    }

    /// Check if the transport is still connected.
    ///
    /// Returns true if the child process is running and the transport hasn't been closed.
    fn is_connected(&self) -> bool {
        if self.closed {
            return false;
        }

        if let Some(ref child) = self.child {
            // We can't call try_wait on &self (needs &mut), so we check if
            // the child handle exists and we haven't marked as closed.
            // For a definitive check, callers should attempt send/recv.
            child.id().is_some()
        } else {
            false
        }
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        // Abort the stderr task if it's still running.
        if let Some(task) = self.stderr_task.take() {
            task.abort();
        }
        // The child process will be killed on drop due to kill_on_drop(true).
    }
}

/// Thread-safe wrapper around `StdioTransport` for concurrent access.
///
/// Since `McpTransport` requires `&mut self`, this wrapper uses a `Mutex`
/// to allow shared access from multiple tasks.
pub struct SharedStdioTransport {
    inner: Mutex<StdioTransport>,
}

impl SharedStdioTransport {
    /// Create a new shared transport.
    pub fn new(transport: StdioTransport) -> Self {
        Self {
            inner: Mutex::new(transport),
        }
    }

    /// Send a JSON-RPC message.
    pub async fn send(&self, message: JsonRpcMessage) -> Result<(), StewardError> {
        let mut transport = self.inner.lock().await;
        transport.send(message).await
    }

    /// Receive the next JSON-RPC message.
    pub async fn recv(&self) -> Result<JsonRpcMessage, StewardError> {
        let mut transport = self.inner.lock().await;
        transport.recv().await
    }

    /// Close the transport.
    pub async fn close(&self) -> Result<(), StewardError> {
        let mut transport = self.inner.lock().await;
        transport.close().await
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        // try_lock to avoid blocking; if locked, it's likely in use (connected).
        match self.inner.try_lock() {
            Ok(transport) => transport.is_connected(),
            Err(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Helper to create a basic JSON-RPC request message.
    fn make_request(id: u64, method: &str) -> JsonRpcMessage {
        JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(id)),
            method: Some(method.to_string()),
            params: Some(json!({})),
            result: None,
            error: None,
        }
    }

    // ----------------------------------------------------------------
    // Test: send/recv round trip using `cat` as an echo MCP server
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_send_recv_round_trip_with_cat() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        assert!(transport.is_connected());

        // Send a JSON-RPC request
        let request = make_request(1, "initialize");
        transport.send(request.clone()).await.unwrap();

        // cat echoes back exactly what we sent
        let response = transport.recv().await.unwrap();
        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(1)));
        assert_eq!(response.method, Some("initialize".to_string()));

        transport.close().await.unwrap();
        assert!(!transport.is_connected());
    }

    // ----------------------------------------------------------------
    // Test: multiple messages round trip
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_multiple_messages_round_trip() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        for i in 1..=5 {
            let msg = make_request(i, &format!("method_{}", i));
            transport.send(msg).await.unwrap();
            let received = transport.recv().await.unwrap();
            assert_eq!(received.id, Some(json!(i)));
        }

        transport.close().await.unwrap();
    }

    // ----------------------------------------------------------------
    // Test: handling malformed output from child process
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_malformed_output_from_child() {
        // Use `echo` to produce non-JSON output
        let config = StdioTransportConfig {
            command: "echo".to_string(),
            args: vec!["not-valid-json".to_string()],
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        // recv should fail because echo outputs non-JSON
        let result = transport.recv().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("failed to parse JSON-RPC message"),
            "unexpected error: {}",
            err_msg
        );

        transport.close().await.unwrap();
    }

    // ----------------------------------------------------------------
    // Test: recv on closed stdout (process exits)
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_recv_after_child_exits() {
        // `true` exits immediately with no output
        let config = StdioTransportConfig {
            command: "true".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        // Give the process a moment to exit
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // recv should return an error because stdout is closed
        let result = transport.recv().await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("stdout closed") || err_msg.contains("process likely exited"),
            "unexpected error: {}",
            err_msg
        );
    }

    // ----------------------------------------------------------------
    // Test: send after child exits returns error
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_send_after_child_exits() {
        let config = StdioTransportConfig {
            command: "true".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        // Wait for process to exit
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let msg = make_request(1, "test");
        let result = transport.send(msg).await;
        assert!(result.is_err());
    }

    // ----------------------------------------------------------------
    // Test: close is idempotent
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_close_idempotent() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        transport.close().await.unwrap();
        // Second close should succeed without error
        transport.close().await.unwrap();
        assert!(!transport.is_connected());
    }

    // ----------------------------------------------------------------
    // Test: close sends SIGTERM then SIGKILL after timeout
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_close_sigterm_then_sigkill() {
        // `sleep 300` will ignore stdin EOF and keep running, requiring SIGTERM/SIGKILL
        let config = StdioTransportConfig {
            command: "sleep".to_string(),
            args: vec!["300".to_string()],
            shutdown_timeout_secs: 1,
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();
        assert!(transport.is_connected());

        // close should terminate the long-running process
        let start = std::time::Instant::now();
        transport.close().await.unwrap();
        let elapsed = start.elapsed();

        // Should not take more than shutdown_timeout + some margin
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "close took too long: {:?}",
            elapsed
        );
        assert!(!transport.is_connected());
    }

    // ----------------------------------------------------------------
    // Test: operations after close return errors
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_operations_after_close() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();
        transport.close().await.unwrap();

        let send_result = transport.send(make_request(1, "test")).await;
        assert!(send_result.is_err());
        assert!(send_result.unwrap_err().to_string().contains("closed"));

        let recv_result = transport.recv().await;
        assert!(recv_result.is_err());
        assert!(recv_result.unwrap_err().to_string().contains("closed"));
    }

    // ----------------------------------------------------------------
    // Test: double connect returns error
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_double_connect_error() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        let result = transport.connect().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("already connected"));

        transport.close().await.unwrap();
    }

    // ----------------------------------------------------------------
    // Test: spawn failure for non-existent command
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_spawn_failure() {
        let config = StdioTransportConfig {
            command: "/nonexistent/mcp-server-12345".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        let result = transport.connect().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to spawn"));
    }

    // ----------------------------------------------------------------
    // Test: not connected before connect
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_not_connected_before_connect() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let transport = StdioTransport::new(config);
        assert!(!transport.is_connected());
    }

    // ----------------------------------------------------------------
    // Test: send/recv without connect returns error
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_operations_without_connect() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);

        let send_result = transport.send(make_request(1, "test")).await;
        assert!(send_result.is_err());
        assert!(send_result
            .unwrap_err()
            .to_string()
            .contains("not connected"));

        let recv_result = transport.recv().await;
        assert!(recv_result.is_err());
        assert!(recv_result
            .unwrap_err()
            .to_string()
            .contains("not connected"));
    }

    // ----------------------------------------------------------------
    // Test: complex JSON-RPC message round trip
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_complex_json_rpc_round_trip() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        // Send a tools/call request with nested parameters
        let msg = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(42)),
            method: Some("tools/call".to_string()),
            params: Some(json!({
                "name": "gmail.send",
                "arguments": {
                    "to": "user@example.com",
                    "subject": "Test",
                    "body": "Hello, world!\nSecond line with \"quotes\" and special chars: <>&"
                }
            })),
            result: None,
            error: None,
        };

        transport.send(msg.clone()).await.unwrap();
        let received = transport.recv().await.unwrap();

        assert_eq!(received.jsonrpc, "2.0");
        assert_eq!(received.id, Some(json!(42)));
        assert_eq!(received.method, Some("tools/call".to_string()));

        let params = received.params.unwrap();
        assert_eq!(params["name"], "gmail.send");
        assert_eq!(params["arguments"]["to"], "user@example.com");

        transport.close().await.unwrap();
    }

    // ----------------------------------------------------------------
    // Test: JSON-RPC error response round trip
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_error_response_round_trip() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        let msg = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(99)),
            method: None,
            params: None,
            result: None,
            error: Some(steward_types::actions::JsonRpcError {
                code: -32600,
                message: "Invalid Request".to_string(),
                data: Some(json!({"detail": "missing method"})),
            }),
        };

        transport.send(msg).await.unwrap();
        let received = transport.recv().await.unwrap();

        assert_eq!(received.id, Some(json!(99)));
        let err = received.error.unwrap();
        assert_eq!(err.code, -32600);
        assert_eq!(err.message, "Invalid Request");

        transport.close().await.unwrap();
    }

    // ----------------------------------------------------------------
    // Test: environment variables and working directory
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_env_and_working_dir() {
        // Use `env` command to print an environment variable, verifying config is passed
        let mut env = HashMap::new();
        env.insert("STEWARD_TEST_VAR".to_string(), "hello_steward".to_string());

        let config = StdioTransportConfig {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), "echo $STEWARD_TEST_VAR".to_string()],
            env,
            working_dir: Some(PathBuf::from("/tmp")),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        // Read the output (not JSON-RPC, but verifies env was passed)
        let reader = transport.stdout_reader.as_mut().unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line.trim(), "hello_steward");

        transport.close().await.unwrap();
    }

    // ----------------------------------------------------------------
    // Test: stderr is captured (doesn't block or crash)
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_stderr_captured() {
        let config = StdioTransportConfig {
            command: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "echo error_output >&2; echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}'"
                    .to_string(),
            ],
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        // Give stderr task time to capture
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Verify we can still read from stdout despite stderr output
        let msg = transport.recv().await.unwrap();
        assert_eq!(msg.id, Some(json!(1)));
        assert_eq!(msg.result, Some(json!("ok")));

        transport.close().await.unwrap();
    }

    // ----------------------------------------------------------------
    // Test: SharedStdioTransport concurrent access
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_shared_transport_concurrent_access() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        let shared = std::sync::Arc::new(SharedStdioTransport::new(transport));

        // Since cat echoes sequentially, we send then recv in order,
        // but from multiple tasks to verify the mutex works.
        let mut handles = Vec::new();

        for i in 0..5u64 {
            let shared = shared.clone();
            handles.push(tokio::spawn(async move {
                let msg = make_request(i, &format!("method_{}", i));
                shared.send(msg).await.unwrap();
                let received = shared.recv().await.unwrap();
                assert_eq!(received.jsonrpc, "2.0");
                // We can't assert the exact id because messages may interleave,
                // but we can verify we get valid JSON-RPC messages back.
                assert!(received.id.is_some());
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        shared.close().await.unwrap();
        assert!(!shared.is_connected());
    }

    // ----------------------------------------------------------------
    // Test: notification (no id) round trip
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_notification_round_trip() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        let msg = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: Some("notifications/initialized".to_string()),
            params: None,
            result: None,
            error: None,
        };

        transport.send(msg).await.unwrap();
        let received = transport.recv().await.unwrap();
        assert_eq!(received.id, None);
        assert_eq!(
            received.method,
            Some("notifications/initialized".to_string())
        );

        transport.close().await.unwrap();
    }

    // ----------------------------------------------------------------
    // Test: large message round trip
    // ----------------------------------------------------------------
    #[tokio::test]
    async fn test_large_message_round_trip() {
        let config = StdioTransportConfig {
            command: "cat".to_string(),
            ..Default::default()
        };

        let mut transport = StdioTransport::new(config);
        transport.connect().await.unwrap();

        // Create a message with a large payload
        let large_content = "x".repeat(100_000);
        let msg = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: Some("test".to_string()),
            params: Some(json!({ "data": large_content })),
            result: None,
            error: None,
        };

        transport.send(msg).await.unwrap();
        let received = transport.recv().await.unwrap();
        assert_eq!(received.params.unwrap()["data"], large_content);

        transport.close().await.unwrap();
    }
}
