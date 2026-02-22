/// Config directory loader with validation and hot-reload support.
///
/// Reads all config from a directory path, validates on load, watches for
/// file changes via `notify`, and emits config change events via
/// `tokio::sync::watch`.
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::watch;

use crate::config::*;
use crate::errors::StewardError;

/// Loads, validates, and watches configuration from a directory.
///
/// Expected directory structure:
/// ```text
/// config/
/// ├── permissions.yaml
/// ├── guardrails.yaml
/// ├── identity.md
/// └── mcp-manifests/
///     ├── gmail.yaml
///     └── gcal.yaml
/// ```
pub struct ConfigLoader {
    /// Root config directory path.
    config_dir: PathBuf,
    /// Watch sender for broadcasting config changes.
    tx: watch::Sender<StewardConfig>,
    /// File watcher handle (kept alive to maintain the watch).
    _watcher: Option<RecommendedWatcher>,
}

impl ConfigLoader {
    /// Load all configuration from a directory, validate, and return a `ConfigLoader`
    /// along with a `watch::Receiver` for subscribing to config changes.
    ///
    /// This performs initial load and validation. Call `watch()` afterwards to
    /// start hot-reload file watching.
    pub fn load(config_dir: &Path) -> Result<(Self, watch::Receiver<StewardConfig>), StewardError> {
        let config = Self::load_all(config_dir)?;
        Self::validate(&config)?;

        let (tx, rx) = watch::channel(config);

        Ok((
            Self {
                config_dir: config_dir.to_path_buf(),
                tx,
                _watcher: None,
            },
            rx,
        ))
    }

    /// Start watching the config directory for changes.
    ///
    /// File changes trigger a reload of the affected config file. If the
    /// new config is valid, it's broadcast via the watch channel. Invalid
    /// configs are logged but don't replace the current valid config.
    pub fn watch(&mut self) -> Result<(), StewardError> {
        let config_dir = self.config_dir.clone();
        let tx = self.tx.clone();

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) {
                        match Self::load_all(&config_dir) {
                            Ok(config) => match Self::validate(&config) {
                                Ok(()) => {
                                    let _ = tx.send(config);
                                    tracing::info!("config reloaded successfully");
                                }
                                Err(e) => {
                                    tracing::warn!("config validation failed after file change, keeping previous config: {e}");
                                }
                            },
                            Err(e) => {
                                tracing::warn!("config load failed after file change, keeping previous config: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("file watcher error: {e}");
                }
            }
        })
        .map_err(|e| StewardError::Config(format!("failed to create file watcher: {e}")))?;

        watcher
            .watch(&self.config_dir, RecursiveMode::Recursive)
            .map_err(|e| StewardError::Config(format!("failed to watch config directory: {e}")))?;

        self._watcher = Some(watcher);
        tracing::info!(dir = %self.config_dir.display(), "started watching config directory");
        Ok(())
    }

    /// Load all config files from a directory.
    pub fn load_all(config_dir: &Path) -> Result<StewardConfig, StewardError> {
        let permissions = Self::load_permissions(config_dir)?;
        let guardrails = Self::load_guardrails(config_dir)?;
        let mcp_manifests = Self::load_mcp_manifests(config_dir)?;
        let identity = Self::load_identity(config_dir)?;

        Ok(StewardConfig {
            permissions,
            guardrails,
            mcp_manifests,
            identity,
        })
    }

    /// Load permissions.yaml from the config directory.
    fn load_permissions(config_dir: &Path) -> Result<PermissionsConfig, StewardError> {
        let path = config_dir.join("permissions.yaml");
        let content = std::fs::read_to_string(&path)
            .map_err(|e| StewardError::Config(format!("failed to read {}: {e}", path.display())))?;
        serde_yaml::from_str(&content)
            .map_err(|e| StewardError::Config(format!("failed to parse {}: {e}", path.display())))
    }

    /// Load guardrails.yaml from the config directory.
    fn load_guardrails(config_dir: &Path) -> Result<GuardrailsConfig, StewardError> {
        let path = config_dir.join("guardrails.yaml");
        let content = std::fs::read_to_string(&path)
            .map_err(|e| StewardError::Config(format!("failed to read {}: {e}", path.display())))?;
        serde_yaml::from_str(&content)
            .map_err(|e| StewardError::Config(format!("failed to parse {}: {e}", path.display())))
    }

    /// Load all MCP manifests from `config/mcp-manifests/`.
    fn load_mcp_manifests(
        config_dir: &Path,
    ) -> Result<HashMap<String, McpManifestConfig>, StewardError> {
        let manifests_dir = config_dir.join("mcp-manifests");
        let mut manifests = HashMap::new();

        if !manifests_dir.exists() {
            return Ok(manifests);
        }

        let entries = std::fs::read_dir(&manifests_dir).map_err(|e| {
            StewardError::Config(format!("failed to read {}: {e}", manifests_dir.display()))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                StewardError::Config(format!("failed to read directory entry: {e}"))
            })?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                let content = std::fs::read_to_string(&path).map_err(|e| {
                    StewardError::Config(format!("failed to read {}: {e}", path.display()))
                })?;
                let manifest: McpManifestConfig = serde_yaml::from_str(&content).map_err(|e| {
                    StewardError::Config(format!("failed to parse {}: {e}", path.display()))
                })?;
                manifests.insert(manifest.server.clone(), manifest);
            }
        }

        Ok(manifests)
    }

    /// Load identity.md from the config directory.
    fn load_identity(config_dir: &Path) -> Result<IdentityConfig, StewardError> {
        let path = config_dir.join("identity.md");
        let content = std::fs::read_to_string(&path)
            .map_err(|e| StewardError::Config(format!("failed to read {}: {e}", path.display())))?;
        IdentityConfig::from_markdown(&content)
    }

    /// Validate the aggregate config for internal consistency.
    ///
    /// Checks:
    /// - No duplicate action patterns across permission tiers
    /// - Rate limit strings are valid format (N/period)
    /// - Global rate limit is positive
    /// - MCP manifest tool names are not duplicated
    /// - Time-of-day windows have valid HH:MM format
    pub fn validate(config: &StewardConfig) -> Result<(), StewardError> {
        Self::validate_permissions(&config.permissions)?;
        Self::validate_guardrails(&config.guardrails)?;
        for (server, manifest) in &config.mcp_manifests {
            Self::validate_mcp_manifest(server, manifest)?;
        }
        Ok(())
    }

    /// Validate permissions config.
    fn validate_permissions(config: &PermissionsConfig) -> Result<(), StewardError> {
        let tiers = &config.tiers;
        let mut seen_actions: HashSet<&str> = HashSet::new();

        for (tier_name, tier) in [
            ("auto_execute", &tiers.auto_execute),
            ("log_and_execute", &tiers.log_and_execute),
            ("human_approval", &tiers.human_approval),
            ("forbidden", &tiers.forbidden),
        ] {
            for action in &tier.actions {
                if !seen_actions.insert(action.as_str()) {
                    return Err(StewardError::Config(format!(
                        "duplicate action pattern '{action}' found in tier '{tier_name}' (already defined in another tier)"
                    )));
                }
            }

            // Validate rate limit format if present
            if let Some(constraints) = &tier.constraints {
                if let Some(rate_limit) = &constraints.rate_limit {
                    validate_rate_limit_format(rate_limit)?;
                }
                if let Some(windows) = &constraints.time_of_day {
                    for window in windows {
                        validate_time_format(&window.start)?;
                        validate_time_format(&window.end)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate guardrails config.
    fn validate_guardrails(config: &GuardrailsConfig) -> Result<(), StewardError> {
        if let Some(limit) = config.global_rate_limit {
            if limit == 0 {
                return Err(StewardError::Config(
                    "global_rate_limit must be positive (got 0)".to_string(),
                ));
            }
        }

        // Validate forbidden patterns are valid regex
        for pattern in &config.forbidden_patterns {
            regex::Regex::new(pattern).map_err(|e| {
                StewardError::Config(format!(
                    "invalid regex in forbidden_patterns '{pattern}': {e}"
                ))
            })?;
        }

        // Validate circuit breaker defaults
        if let Some(cb) = &config.circuit_breaker_defaults {
            validate_circuit_breaker(cb, "circuit_breaker_defaults")?;
        }

        Ok(())
    }

    /// Validate an MCP manifest.
    fn validate_mcp_manifest(
        server: &str,
        manifest: &McpManifestConfig,
    ) -> Result<(), StewardError> {
        // Validate transport type
        match manifest.transport.as_str() {
            "stdio" | "http" | "sse" => {}
            other => {
                return Err(StewardError::Config(format!(
                    "MCP manifest '{server}': invalid transport '{other}' (expected 'stdio', 'http', or 'sse')"
                )));
            }
        }

        // Check for duplicate tool names
        let mut tool_names: HashSet<&str> = HashSet::new();
        for tool in &manifest.allowed_tools {
            if !tool_names.insert(&tool.name) {
                return Err(StewardError::Config(format!(
                    "MCP manifest '{server}': duplicate tool name '{}'",
                    tool.name
                )));
            }

            // Validate tool rate limits
            if let Some(rate_limit) = &tool.rate_limit {
                validate_rate_limit_format(rate_limit).map_err(|e| {
                    StewardError::Config(format!(
                        "MCP manifest '{server}', tool '{}': {e}",
                        tool.name
                    ))
                })?;
            }
        }

        // Validate circuit breaker
        if let Some(cb) = &manifest.circuit_breaker {
            validate_circuit_breaker(cb, &format!("MCP manifest '{server}'"))?;
        }

        Ok(())
    }
}

/// Validate rate limit format: "N/period" where period is second, minute, hour, day.
fn validate_rate_limit_format(rate_limit: &str) -> Result<(), StewardError> {
    let parts: Vec<&str> = rate_limit.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(StewardError::Config(format!(
            "invalid rate limit format '{rate_limit}': expected 'N/period' (e.g., '60/minute')"
        )));
    }

    let count: u32 = parts[0].parse().map_err(|_| {
        StewardError::Config(format!(
            "invalid rate limit format '{rate_limit}': count '{}' is not a positive integer",
            parts[0]
        ))
    })?;

    if count == 0 {
        return Err(StewardError::Config(format!(
            "invalid rate limit format '{rate_limit}': count must be positive"
        )));
    }

    match parts[1] {
        "second" | "minute" | "hour" | "day" => Ok(()),
        other => Err(StewardError::Config(format!(
            "invalid rate limit format '{rate_limit}': unknown period '{other}' (expected 'second', 'minute', 'hour', or 'day')"
        ))),
    }
}

/// Validate HH:MM time format.
fn validate_time_format(time: &str) -> Result<(), StewardError> {
    let parts: Vec<&str> = time.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(StewardError::Config(format!(
            "invalid time format '{time}': expected 'HH:MM'"
        )));
    }

    let hour: u32 = parts[0].parse().map_err(|_| {
        StewardError::Config(format!(
            "invalid time format '{time}': hour '{}' is not a number",
            parts[0]
        ))
    })?;
    let minute: u32 = parts[1].parse().map_err(|_| {
        StewardError::Config(format!(
            "invalid time format '{time}': minute '{}' is not a number",
            parts[1]
        ))
    })?;

    if hour > 23 {
        return Err(StewardError::Config(format!(
            "invalid time format '{time}': hour must be 0-23"
        )));
    }
    if minute > 59 {
        return Err(StewardError::Config(format!(
            "invalid time format '{time}': minute must be 0-59"
        )));
    }

    Ok(())
}

/// Validate circuit breaker configuration values.
fn validate_circuit_breaker(cb: &CircuitBreakerConfig, context: &str) -> Result<(), StewardError> {
    if cb.error_threshold == 0 {
        return Err(StewardError::Config(format!(
            "{context}: error_threshold must be positive"
        )));
    }
    if cb.error_window_secs == 0 {
        return Err(StewardError::Config(format!(
            "{context}: error_window_secs must be positive"
        )));
    }
    if cb.recovery_timeout_secs == 0 {
        return Err(StewardError::Config(format!(
            "{context}: recovery_timeout_secs must be positive"
        )));
    }
    if cb.recovery_probes == 0 {
        return Err(StewardError::Config(format!(
            "{context}: recovery_probes must be positive"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    /// Create a temporary config directory with valid default files.
    fn setup_config_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();

        // permissions.yaml
        fs::write(
            dir.path().join("permissions.yaml"),
            r#"
tiers:
  auto_execute:
    description: "Safe read-only operations"
    actions:
      - calendar.read
      - email.read
    constraints:
      rate_limit: 60/minute
  log_and_execute:
    description: "Low-risk writes"
    actions:
      - reminder.create
      - note.create
    constraints:
      rate_limit: 30/minute
  human_approval:
    description: "High-risk actions"
    actions:
      - email.send
      - file.modify
    confirmation:
      channel: same_as_request
      show:
        - action
        - params
      timeout: 5m
  forbidden:
    description: "Hard-blocked"
    actions:
      - credentials.read_raw
      - agent.self_modify
"#,
        )
        .unwrap();

        // guardrails.yaml
        fs::write(
            dir.path().join("guardrails.yaml"),
            r#"
global_rate_limit: 120
forbidden_patterns:
  - "(?i)ignore\\s+previous\\s+instructions?"
circuit_breaker_defaults:
  error_threshold: 5
  error_window_secs: 60
  latency_threshold_secs: 30
  recovery_timeout_secs: 120
  recovery_probes: 3
  max_recovery_backoff_secs: 900
egress:
  max_outbound_per_minute: 20
  max_recipients_per_message: 10
  pii_scan_enabled: true
  secret_scan_enabled: true
ingress:
  max_content_chars: 100000
  injection_detection_enabled: true
"#,
        )
        .unwrap();

        // identity.md
        fs::write(
            dir.path().join("identity.md"),
            r#"# Steward Agent Identity

You are Steward, a security-conscious personal AI assistant.

## Personality

- Helpful, precise, and transparent about your actions
- Security-first: you always explain what you're about to do before doing it

## Behavioral Boundaries

- Never share credentials, API keys, or sensitive data in messages
- Always explain your reasoning when proposing actions
"#,
        )
        .unwrap();

        // mcp-manifests/
        let manifests_dir = dir.path().join("mcp-manifests");
        fs::create_dir_all(&manifests_dir).unwrap();

        fs::write(
            manifests_dir.join("gmail.yaml"),
            r#"
server: gmail-mcp
transport: stdio
allowed_tools:
  - name: gmail.search
    allowed: true
    rate_limit: 30/minute
  - name: gmail.read
    allowed: true
    rate_limit: 60/minute
  - name: gmail.send
    allowed: true
    requires_approval: true
  - name: gmail.delete
    allowed: false
blocked_params:
  - "*.bcc"
  - "*.forward_to"
schema_rewrites:
  gmail.send:
    strip_params:
      - bcc
      - forward_to
    constrain_params:
      to:
        max_recipients: 5
      attachments:
        max_size_bytes: 10485760
circuit_breaker:
  error_threshold: 5
  error_window_secs: 60
  latency_threshold_secs: 30
  recovery_timeout_secs: 120
  recovery_probes: 3
  max_recovery_backoff_secs: 900
"#,
        )
        .unwrap();

        dir
    }

    // ============================
    // Parsing tests
    // ============================

    #[test]
    fn test_parse_permissions_yaml() {
        let dir = setup_config_dir();
        let config = ConfigLoader::load_all(dir.path()).unwrap();

        assert_eq!(config.permissions.tiers.auto_execute.actions.len(), 2);
        assert!(config
            .permissions
            .tiers
            .auto_execute
            .actions
            .contains(&"calendar.read".to_string()));
        assert_eq!(
            config
                .permissions
                .tiers
                .auto_execute
                .constraints
                .as_ref()
                .unwrap()
                .rate_limit
                .as_ref()
                .unwrap(),
            "60/minute"
        );
        assert_eq!(
            config
                .permissions
                .tiers
                .human_approval
                .confirmation
                .as_ref()
                .unwrap()
                .timeout
                .as_ref()
                .unwrap(),
            "5m"
        );
        assert_eq!(config.permissions.tiers.forbidden.actions.len(), 2);
    }

    #[test]
    fn test_parse_guardrails_yaml() {
        let dir = setup_config_dir();
        let config = ConfigLoader::load_all(dir.path()).unwrap();

        assert_eq!(config.guardrails.global_rate_limit, Some(120));
        assert_eq!(config.guardrails.forbidden_patterns.len(), 1);

        let cb = config.guardrails.circuit_breaker_defaults.as_ref().unwrap();
        assert_eq!(cb.error_threshold, 5);
        assert_eq!(cb.recovery_probes, 3);

        let egress = config.guardrails.egress.as_ref().unwrap();
        assert_eq!(egress.max_outbound_per_minute, Some(20));
        assert!(egress.pii_scan_enabled);

        let ingress = config.guardrails.ingress.as_ref().unwrap();
        assert_eq!(ingress.max_content_chars, Some(100000));
        assert!(ingress.injection_detection_enabled);
    }

    #[test]
    fn test_parse_mcp_manifest() {
        let dir = setup_config_dir();
        let config = ConfigLoader::load_all(dir.path()).unwrap();

        let gmail = config.mcp_manifests.get("gmail-mcp").unwrap();
        assert_eq!(gmail.server, "gmail-mcp");
        assert_eq!(gmail.transport, "stdio");
        assert_eq!(gmail.allowed_tools.len(), 4);
        assert_eq!(gmail.blocked_params.len(), 2);

        // Check schema rewrites
        let rewrite = gmail.schema_rewrites.get("gmail.send").unwrap();
        assert_eq!(rewrite.strip_params, vec!["bcc", "forward_to"]);
        assert_eq!(
            rewrite.constrain_params.get("to").unwrap().max_recipients,
            Some(5)
        );

        // Check circuit breaker
        let cb = gmail.circuit_breaker.as_ref().unwrap();
        assert_eq!(cb.error_threshold, 5);
    }

    #[test]
    fn test_parse_identity_markdown() {
        let dir = setup_config_dir();
        let config = ConfigLoader::load_all(dir.path()).unwrap();

        assert_eq!(config.identity.name, "Steward Agent Identity");
        assert!(config.identity.personality.contains("Helpful"));
        assert_eq!(config.identity.boundaries.len(), 2);
        assert!(config.identity.boundaries[0].contains("Never share credentials"));
        assert!(!config.identity.raw_markdown.is_empty());
    }

    #[test]
    fn test_parse_identity_from_markdown_string() {
        let md = r#"# Test Agent

A test agent.

## Personality

- Friendly
- Precise

## Behavioral Boundaries

- No secrets
- No bulk actions
- Always confirm
"#;
        let identity = IdentityConfig::from_markdown(md).unwrap();
        assert_eq!(identity.name, "Test Agent");
        assert!(identity.personality.contains("Friendly"));
        assert_eq!(identity.boundaries.len(), 3);
    }

    #[test]
    fn test_parse_identity_missing_title() {
        let md = "No title here\n\n## Personality\n\n- Friendly\n";
        let result = IdentityConfig::from_markdown(md);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("title"));
    }

    // ============================
    // Validation tests
    // ============================

    #[test]
    fn test_validation_catches_duplicate_actions() {
        let dir = setup_config_dir();
        // Write permissions with duplicate action
        fs::write(
            dir.path().join("permissions.yaml"),
            r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - email.read
  log_and_execute:
    description: "Low-risk"
    actions:
      - email.read
  human_approval:
    description: "High-risk"
    actions: []
  forbidden:
    description: "Blocked"
    actions: []
"#,
        )
        .unwrap();

        let config = ConfigLoader::load_all(dir.path()).unwrap();
        let result = ConfigLoader::validate(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("duplicate action pattern"));
        assert!(err.contains("email.read"));
    }

    #[test]
    fn test_validation_catches_invalid_rate_limit_format() {
        let dir = setup_config_dir();
        fs::write(
            dir.path().join("permissions.yaml"),
            r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - calendar.read
    constraints:
      rate_limit: "not-a-rate-limit"
  log_and_execute:
    description: "Low-risk"
    actions: []
  human_approval:
    description: "High-risk"
    actions: []
  forbidden:
    description: "Blocked"
    actions: []
"#,
        )
        .unwrap();

        let config = ConfigLoader::load_all(dir.path()).unwrap();
        let result = ConfigLoader::validate(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid rate limit format"));
    }

    #[test]
    fn test_validation_catches_zero_rate_limit() {
        let result = validate_rate_limit_format("0/minute");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be positive"));
    }

    #[test]
    fn test_validation_catches_invalid_rate_limit_period() {
        let result = validate_rate_limit_format("10/fortnight");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown period"));
    }

    #[test]
    fn test_validation_catches_zero_global_rate_limit() {
        let dir = setup_config_dir();
        fs::write(
            dir.path().join("guardrails.yaml"),
            r#"
global_rate_limit: 0
forbidden_patterns: []
"#,
        )
        .unwrap();

        let config = ConfigLoader::load_all(dir.path()).unwrap();
        let result = ConfigLoader::validate(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("global_rate_limit must be positive"));
    }

    #[test]
    fn test_validation_catches_invalid_regex() {
        let dir = setup_config_dir();
        fs::write(
            dir.path().join("guardrails.yaml"),
            r#"
global_rate_limit: 100
forbidden_patterns:
  - "[invalid regex"
"#,
        )
        .unwrap();

        let config = ConfigLoader::load_all(dir.path()).unwrap();
        let result = ConfigLoader::validate(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid regex"));
    }

    #[test]
    fn test_validation_catches_duplicate_mcp_tool_names() {
        let dir = setup_config_dir();
        let manifests_dir = dir.path().join("mcp-manifests");
        fs::write(
            manifests_dir.join("gmail.yaml"),
            r#"
server: gmail-mcp
transport: stdio
allowed_tools:
  - name: gmail.read
    allowed: true
  - name: gmail.read
    allowed: false
blocked_params: []
"#,
        )
        .unwrap();

        let config = ConfigLoader::load_all(dir.path()).unwrap();
        let result = ConfigLoader::validate(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("duplicate tool name"));
    }

    #[test]
    fn test_validation_catches_invalid_transport() {
        let dir = setup_config_dir();
        let manifests_dir = dir.path().join("mcp-manifests");
        fs::write(
            manifests_dir.join("gmail.yaml"),
            r#"
server: gmail-mcp
transport: pigeon
allowed_tools: []
blocked_params: []
"#,
        )
        .unwrap();

        let config = ConfigLoader::load_all(dir.path()).unwrap();
        let result = ConfigLoader::validate(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid transport"));
    }

    #[test]
    fn test_validation_catches_invalid_time_format() {
        let result = validate_time_format("25:00");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("hour must be 0-23"));

        let result = validate_time_format("12:70");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("minute must be 0-59"));

        let result = validate_time_format("noon");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected 'HH:MM'"));
    }

    #[test]
    fn test_valid_time_formats() {
        assert!(validate_time_format("00:00").is_ok());
        assert!(validate_time_format("23:59").is_ok());
        assert!(validate_time_format("09:30").is_ok());
    }

    #[test]
    fn test_valid_rate_limit_formats() {
        assert!(validate_rate_limit_format("60/minute").is_ok());
        assert!(validate_rate_limit_format("10/second").is_ok());
        assert!(validate_rate_limit_format("1000/hour").is_ok());
        assert!(validate_rate_limit_format("50000/day").is_ok());
    }

    #[test]
    fn test_validation_catches_zero_circuit_breaker_threshold() {
        let cb = CircuitBreakerConfig {
            error_threshold: 0,
            ..Default::default()
        };
        let result = validate_circuit_breaker(&cb, "test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("error_threshold must be positive"));
    }

    // ============================
    // Hot-reload tests
    // ============================

    #[tokio::test]
    async fn test_hot_reload_detects_file_changes() {
        let dir = setup_config_dir();
        let (mut loader, mut rx) = ConfigLoader::load(dir.path()).unwrap();

        // Verify initial load
        let initial = rx.borrow().clone();
        assert_eq!(initial.permissions.tiers.auto_execute.actions.len(), 2);

        loader.watch().unwrap();

        // Modify permissions.yaml to add an action
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(dir.path().join("permissions.yaml"))
            .unwrap();
        write!(
            file,
            r#"
tiers:
  auto_execute:
    description: "Safe read-only operations"
    actions:
      - calendar.read
      - email.read
      - weather.check
    constraints:
      rate_limit: 60/minute
  log_and_execute:
    description: "Low-risk writes"
    actions:
      - reminder.create
      - note.create
    constraints:
      rate_limit: 30/minute
  human_approval:
    description: "High-risk actions"
    actions:
      - email.send
      - file.modify
    confirmation:
      channel: same_as_request
      show:
        - action
        - params
      timeout: 5m
  forbidden:
    description: "Hard-blocked"
    actions:
      - credentials.read_raw
      - agent.self_modify
"#
        )
        .unwrap();

        // Wait for the file watcher to detect the change
        let changed = tokio::time::timeout(std::time::Duration::from_secs(5), rx.changed()).await;

        // The file watcher should detect the change
        assert!(changed.is_ok(), "timed out waiting for config change");
        assert!(changed.unwrap().is_ok());

        let updated = rx.borrow().clone();
        assert_eq!(updated.permissions.tiers.auto_execute.actions.len(), 3);
        assert!(updated
            .permissions
            .tiers
            .auto_execute
            .actions
            .contains(&"weather.check".to_string()));
    }

    // ============================
    // Default config tests
    // ============================

    #[test]
    fn test_default_configs_parse_successfully() {
        // Test that the actual config/ directory in the project root parses
        let config_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("config");

        if config_dir.exists() {
            let result = ConfigLoader::load_all(&config_dir);
            assert!(
                result.is_ok(),
                "default configs failed to parse: {result:?}"
            );

            let config = result.unwrap();
            let validation = ConfigLoader::validate(&config);
            assert!(
                validation.is_ok(),
                "default configs failed validation: {validation:?}"
            );
        }
    }

    #[test]
    fn test_config_loader_load_and_validate() {
        let dir = setup_config_dir();
        let result = ConfigLoader::load(dir.path());
        assert!(result.is_ok());

        let (_, rx) = result.unwrap();
        let config = rx.borrow().clone();
        assert_eq!(config.permissions.tiers.auto_execute.actions.len(), 2);
        assert!(!config.mcp_manifests.is_empty());
    }

    // ============================
    // Error message quality tests
    // ============================

    #[test]
    fn test_error_for_missing_permissions_file() {
        let dir = tempfile::tempdir().unwrap();
        // Create only guardrails and identity, not permissions
        fs::write(
            dir.path().join("guardrails.yaml"),
            "global_rate_limit: 100\nforbidden_patterns: []\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("identity.md"),
            "# Test\n\n## Personality\n\n- Friendly\n\n## Behavioral Boundaries\n\n- Safe\n",
        )
        .unwrap();

        let result = ConfigLoader::load_all(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("permissions.yaml"));
        assert!(err.contains("failed to read"));
    }

    #[test]
    fn test_error_for_invalid_yaml() {
        let dir = setup_config_dir();
        fs::write(
            dir.path().join("permissions.yaml"),
            "this is not: valid: yaml: [",
        )
        .unwrap();

        let result = ConfigLoader::load_all(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to parse"));
        assert!(err.contains("permissions.yaml"));
    }

    #[test]
    fn test_error_for_missing_required_field() {
        let dir = setup_config_dir();
        // Write permissions with missing tiers
        fs::write(
            dir.path().join("permissions.yaml"),
            "not_tiers:\n  something: true\n",
        )
        .unwrap();

        let result = ConfigLoader::load_all(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("permissions.yaml"));
    }

    #[test]
    fn test_no_mcp_manifests_dir_is_ok() {
        let dir = setup_config_dir();
        // Remove the mcp-manifests directory
        fs::remove_dir_all(dir.path().join("mcp-manifests")).unwrap();

        let config = ConfigLoader::load_all(dir.path()).unwrap();
        assert!(config.mcp_manifests.is_empty());
        assert!(ConfigLoader::validate(&config).is_ok());
    }

    #[test]
    fn test_permissions_with_time_of_day() {
        let dir = setup_config_dir();
        fs::write(
            dir.path().join("permissions.yaml"),
            r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - calendar.read
    constraints:
      rate_limit: 60/minute
      time_of_day:
        - start: "09:00"
          end: "17:00"
          timezone: "America/New_York"
  log_and_execute:
    description: "Low-risk"
    actions:
      - note.create
  human_approval:
    description: "High-risk"
    actions:
      - email.send
  forbidden:
    description: "Blocked"
    actions:
      - credentials.read_raw
"#,
        )
        .unwrap();

        let config = ConfigLoader::load_all(dir.path()).unwrap();
        let result = ConfigLoader::validate(&config);
        assert!(result.is_ok());

        let tod = config
            .permissions
            .tiers
            .auto_execute
            .constraints
            .as_ref()
            .unwrap()
            .time_of_day
            .as_ref()
            .unwrap();
        assert_eq!(tod.len(), 1);
        assert_eq!(tod[0].start, "09:00");
        assert_eq!(tod[0].end, "17:00");
        assert_eq!(tod[0].timezone.as_deref(), Some("America/New_York"));
    }
}
