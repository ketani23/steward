//! Permission engine implementation.
//!
//! Declarative YAML manifest enforcement:
//! - Four tiers: AutoExecute, LogAndExecute, HumanApproval, Forbidden
//! - Wildcard action pattern matching (e.g., "email.*")
//! - Token bucket rate limiting per action
//! - Hot-reload manifest from disk
//!
//! See `docs/architecture.md` Ring 1 (Permission Engine) for specification.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use tokio::sync::RwLock;

use steward_types::actions::{ActionProposal, PermissionTier};
use steward_types::config::PermissionsConfig;
use steward_types::errors::{RateLimitExceeded, StewardError};
use steward_types::traits::PermissionEngine;

/// Token bucket for rate limiting a single action pattern.
#[derive(Debug)]
struct TokenBucket {
    /// Maximum number of tokens the bucket can hold.
    capacity: f64,
    /// Current number of available tokens.
    tokens: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last time tokens were refilled.
    last_refill: std::time::Instant,
}

impl TokenBucket {
    /// Create a new token bucket with the given capacity and refill rate.
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time and try to consume one.
    ///
    /// Returns `true` if a token was consumed, `false` if the bucket is empty.
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }

    /// Estimate seconds until the next token is available.
    fn retry_after_secs(&self) -> u64 {
        if self.refill_rate <= 0.0 {
            return u64::MAX;
        }
        let deficit = 1.0 - self.tokens;
        if deficit <= 0.0 {
            return 0;
        }
        (deficit / self.refill_rate).ceil() as u64
    }
}

/// Parse a rate limit string like "60/minute" into (capacity, refill_rate_per_second).
///
/// Supported period suffixes: "second", "minute", "hour".
fn parse_rate_limit(rate_limit: &str) -> Result<(f64, f64), StewardError> {
    let parts: Vec<&str> = rate_limit.split('/').collect();
    if parts.len() != 2 {
        return Err(StewardError::Permission(format!(
            "invalid rate limit format '{}': expected 'N/period'",
            rate_limit
        )));
    }

    let count: f64 = parts[0].trim().parse().map_err(|_| {
        StewardError::Permission(format!(
            "invalid rate limit count '{}': expected a number",
            parts[0]
        ))
    })?;

    let period_secs: f64 = match parts[1].trim() {
        "second" => 1.0,
        "minute" => 60.0,
        "hour" => 3600.0,
        other => {
            return Err(StewardError::Permission(format!(
                "invalid rate limit period '{}': expected 'second', 'minute', or 'hour'",
                other
            )));
        }
    };

    let refill_rate = count / period_secs;
    Ok((count, refill_rate))
}

/// Check if an action name matches a pattern.
///
/// - Exact match: `"calendar.read"` matches only `"calendar.read"`
/// - Wildcard: `"email.*"` matches `"email.read"`, `"email.send"`, but NOT `"email"`
fn pattern_matches(pattern: &str, action: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix(".*") {
        // Wildcard pattern: prefix must match and there must be at least one char after the dot
        if let Some(rest) = action.strip_prefix(prefix) {
            // rest must start with '.' and have at least one more character
            rest.starts_with('.') && rest.len() > 1
        } else {
            false
        }
    } else {
        // Exact match
        pattern == action
    }
}

/// A compiled list of patterns and their associated rate limit string for a single tier.
#[derive(Debug, Clone)]
struct CompiledTier {
    /// Action patterns belonging to this tier.
    patterns: Vec<String>,
    /// Rate limit string from constraints (e.g., "60/minute"), if any.
    rate_limit: Option<String>,
}

/// Pre-compiled permission manifest for fast lookups.
#[derive(Debug, Clone)]
struct CompiledManifest {
    forbidden: CompiledTier,
    human_approval: CompiledTier,
    log_and_execute: CompiledTier,
    auto_execute: CompiledTier,
}

impl CompiledManifest {
    /// Compile from a parsed `PermissionsConfig`.
    fn from_config(config: &PermissionsConfig) -> Self {
        Self {
            forbidden: CompiledTier {
                patterns: config.tiers.forbidden.actions.clone(),
                rate_limit: config
                    .tiers
                    .forbidden
                    .constraints
                    .as_ref()
                    .and_then(|c| c.rate_limit.clone()),
            },
            human_approval: CompiledTier {
                patterns: config.tiers.human_approval.actions.clone(),
                rate_limit: config
                    .tiers
                    .human_approval
                    .constraints
                    .as_ref()
                    .and_then(|c| c.rate_limit.clone()),
            },
            log_and_execute: CompiledTier {
                patterns: config.tiers.log_and_execute.actions.clone(),
                rate_limit: config
                    .tiers
                    .log_and_execute
                    .constraints
                    .as_ref()
                    .and_then(|c| c.rate_limit.clone()),
            },
            auto_execute: CompiledTier {
                patterns: config.tiers.auto_execute.actions.clone(),
                rate_limit: config
                    .tiers
                    .auto_execute
                    .constraints
                    .as_ref()
                    .and_then(|c| c.rate_limit.clone()),
            },
        }
    }

    /// Classify an action into a permission tier, checking in priority order:
    /// forbidden → human_approval → log_and_execute → auto_execute.
    ///
    /// Returns `None` if no pattern matches (caller should default to HumanApproval).
    fn classify(&self, tool_name: &str) -> Option<PermissionTier> {
        let tiers: &[(PermissionTier, &CompiledTier)] = &[
            (PermissionTier::Forbidden, &self.forbidden),
            (PermissionTier::HumanApproval, &self.human_approval),
            (PermissionTier::LogAndExecute, &self.log_and_execute),
            (PermissionTier::AutoExecute, &self.auto_execute),
        ];

        for (tier, compiled) in tiers {
            for pattern in &compiled.patterns {
                if pattern_matches(pattern, tool_name) {
                    return Some(*tier);
                }
            }
        }

        None
    }

    /// Find the matching pattern and its rate limit for a given action.
    ///
    /// Returns `(matching_pattern, rate_limit_string)` if a rate limit applies.
    fn find_rate_limit(&self, tool_name: &str) -> Option<(String, String)> {
        let tiers = [
            &self.forbidden,
            &self.human_approval,
            &self.log_and_execute,
            &self.auto_execute,
        ];

        for tier in tiers {
            if let Some(ref rate_limit) = tier.rate_limit {
                for pattern in &tier.patterns {
                    if pattern_matches(pattern, tool_name) {
                        return Some((pattern.clone(), rate_limit.clone()));
                    }
                }
            }
        }

        None
    }
}

/// Permission engine backed by a YAML manifest file.
///
/// Implements the `PermissionEngine` trait with:
/// - Wildcard and exact pattern matching for action classification
/// - Token bucket rate limiting per action pattern
/// - Hot-reload manifest without losing rate limit state
pub struct YamlPermissionEngine {
    /// Path to the YAML manifest file.
    manifest_path: PathBuf,
    /// Compiled manifest for fast lookups, behind an async RwLock for hot-reload.
    manifest: RwLock<CompiledManifest>,
    /// Rate limiter buckets keyed by action pattern, behind a std Mutex for sync access.
    rate_limiters: Mutex<HashMap<String, TokenBucket>>,
}

impl YamlPermissionEngine {
    /// Create a new permission engine by loading and parsing the YAML manifest.
    pub fn new(manifest_path: &Path) -> Result<Self, StewardError> {
        let config = Self::load_config(manifest_path)?;
        let compiled = CompiledManifest::from_config(&config);

        Ok(Self {
            manifest_path: manifest_path.to_path_buf(),
            manifest: RwLock::new(compiled),
            rate_limiters: Mutex::new(HashMap::new()),
        })
    }

    /// Load and parse the YAML config from disk.
    fn load_config(path: &Path) -> Result<PermissionsConfig, StewardError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            StewardError::Permission(format!(
                "failed to read manifest '{}': {}",
                path.display(),
                e
            ))
        })?;
        let config: PermissionsConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Get or create a token bucket for the given pattern with the specified rate limit.
    fn get_or_create_bucket(
        buckets: &mut HashMap<String, TokenBucket>,
        pattern: &str,
        rate_limit: &str,
    ) -> Result<(), StewardError> {
        if !buckets.contains_key(pattern) {
            let (capacity, refill_rate) = parse_rate_limit(rate_limit)?;
            buckets.insert(pattern.to_string(), TokenBucket::new(capacity, refill_rate));
        }
        Ok(())
    }
}

#[async_trait]
impl PermissionEngine for YamlPermissionEngine {
    /// Classify an action into a permission tier based on the manifest.
    ///
    /// Checks tiers in priority order: forbidden → human_approval → log_and_execute → auto_execute.
    /// Unknown actions default to `HumanApproval` (fail-closed).
    fn classify(&self, action: &ActionProposal) -> PermissionTier {
        // Use try_read to avoid blocking; fall back to HumanApproval if lock is poisoned
        let manifest = match self.manifest.try_read() {
            Ok(m) => m,
            Err(_) => return PermissionTier::HumanApproval,
        };

        manifest
            .classify(&action.tool_name)
            .unwrap_or(PermissionTier::HumanApproval)
    }

    /// Check rate limits for an action using token bucket algorithm.
    ///
    /// Returns `Ok(())` if within limits, `Err(RateLimitExceeded)` if exceeded.
    async fn check_rate_limit(&self, action: &ActionProposal) -> Result<(), RateLimitExceeded> {
        let manifest = self.manifest.read().await;
        let rate_info = manifest.find_rate_limit(&action.tool_name);
        drop(manifest);

        let (pattern, rate_limit_str) = match rate_info {
            Some(info) => info,
            None => return Ok(()), // No rate limit configured
        };

        let mut buckets = self.rate_limiters.lock().map_err(|_| RateLimitExceeded {
            action: action.tool_name.clone(),
            retry_after_secs: 1,
            limit: "lock error".to_string(),
        })?;

        Self::get_or_create_bucket(&mut buckets, &pattern, &rate_limit_str).map_err(|e| {
            RateLimitExceeded {
                action: action.tool_name.clone(),
                retry_after_secs: 1,
                limit: e.to_string(),
            }
        })?;

        let bucket = buckets.get_mut(&pattern).expect("bucket just created");
        if bucket.try_consume() {
            Ok(())
        } else {
            Err(RateLimitExceeded {
                action: action.tool_name.clone(),
                retry_after_secs: bucket.retry_after_secs(),
                limit: rate_limit_str,
            })
        }
    }

    /// Reload the permission manifest from disk without losing rate limit state.
    async fn reload_manifest(&mut self) -> Result<(), StewardError> {
        let config = Self::load_config(&self.manifest_path)?;
        let compiled = CompiledManifest::from_config(&config);

        let mut manifest = self.manifest.write().await;
        *manifest = compiled;

        tracing::info!(
            path = %self.manifest_path.display(),
            "permission manifest reloaded"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::io::Write;
    use uuid::Uuid;

    /// Helper to create an `ActionProposal` with the given tool name.
    fn make_proposal(tool_name: &str) -> ActionProposal {
        ActionProposal {
            id: Uuid::new_v4(),
            tool_name: tool_name.to_string(),
            parameters: serde_json::json!({}),
            reasoning: "test".to_string(),
            user_message_id: Uuid::new_v4(),
            timestamp: Utc::now(),
        }
    }

    /// Helper to write a permissions YAML to a temp file and return the path.
    fn write_temp_manifest(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    /// The default permissions.yaml content for tests.
    const DEFAULT_MANIFEST: &str = include_str!("../../../config/permissions.yaml");

    // ========================================================
    // Parsing tests
    // ========================================================

    #[test]
    fn test_parse_default_manifest() {
        let file = write_temp_manifest(DEFAULT_MANIFEST);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();
        let manifest = engine.manifest.try_read().unwrap();

        assert_eq!(manifest.auto_execute.patterns.len(), 5);
        assert_eq!(manifest.log_and_execute.patterns.len(), 4);
        assert_eq!(manifest.human_approval.patterns.len(), 8);
        assert_eq!(manifest.forbidden.patterns.len(), 5);
    }

    #[test]
    fn test_parse_rate_limit_minute() {
        let (capacity, refill_rate) = parse_rate_limit("60/minute").unwrap();
        assert!((capacity - 60.0).abs() < f64::EPSILON);
        assert!((refill_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_rate_limit_second() {
        let (capacity, refill_rate) = parse_rate_limit("10/second").unwrap();
        assert!((capacity - 10.0).abs() < f64::EPSILON);
        assert!((refill_rate - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_rate_limit_hour() {
        let (capacity, refill_rate) = parse_rate_limit("3600/hour").unwrap();
        assert!((capacity - 3600.0).abs() < f64::EPSILON);
        assert!((refill_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_rate_limit_invalid_format() {
        assert!(parse_rate_limit("invalid").is_err());
        assert!(parse_rate_limit("60/invalid").is_err());
        assert!(parse_rate_limit("abc/minute").is_err());
    }

    // ========================================================
    // Pattern matching tests
    // ========================================================

    #[test]
    fn test_wildcard_matches_subaction() {
        assert!(pattern_matches("email.*", "email.read"));
        assert!(pattern_matches("email.*", "email.send"));
    }

    #[test]
    fn test_wildcard_does_not_match_bare_prefix() {
        // "email.*" should NOT match "email" (no dot + suffix)
        assert!(!pattern_matches("email.*", "email"));
    }

    #[test]
    fn test_wildcard_does_not_match_different_prefix() {
        assert!(!pattern_matches("email.*", "calendar.read"));
    }

    #[test]
    fn test_exact_match() {
        assert!(pattern_matches("calendar.read", "calendar.read"));
        assert!(!pattern_matches("calendar.read", "calendar.write"));
        assert!(!pattern_matches("calendar.read", "calendar"));
    }

    // ========================================================
    // Classification tests
    // ========================================================

    #[test]
    fn test_classify_auto_execute() {
        let file = write_temp_manifest(DEFAULT_MANIFEST);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        assert_eq!(
            engine.classify(&make_proposal("calendar.read")),
            PermissionTier::AutoExecute
        );
        assert_eq!(
            engine.classify(&make_proposal("email.read")),
            PermissionTier::AutoExecute
        );
        assert_eq!(
            engine.classify(&make_proposal("weather.check")),
            PermissionTier::AutoExecute
        );
        assert_eq!(
            engine.classify(&make_proposal("memory.search")),
            PermissionTier::AutoExecute
        );
        assert_eq!(
            engine.classify(&make_proposal("web.search")),
            PermissionTier::AutoExecute
        );
    }

    #[test]
    fn test_classify_log_and_execute() {
        let file = write_temp_manifest(DEFAULT_MANIFEST);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        assert_eq!(
            engine.classify(&make_proposal("reminder.create")),
            PermissionTier::LogAndExecute
        );
        assert_eq!(
            engine.classify(&make_proposal("note.create")),
            PermissionTier::LogAndExecute
        );
        assert_eq!(
            engine.classify(&make_proposal("message.draft")),
            PermissionTier::LogAndExecute
        );
        assert_eq!(
            engine.classify(&make_proposal("file.read")),
            PermissionTier::LogAndExecute
        );
    }

    #[test]
    fn test_classify_human_approval() {
        let file = write_temp_manifest(DEFAULT_MANIFEST);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        assert_eq!(
            engine.classify(&make_proposal("email.send")),
            PermissionTier::HumanApproval
        );
        assert_eq!(
            engine.classify(&make_proposal("message.send")),
            PermissionTier::HumanApproval
        );
        assert_eq!(
            engine.classify(&make_proposal("file.modify")),
            PermissionTier::HumanApproval
        );
        assert_eq!(
            engine.classify(&make_proposal("shell.exec")),
            PermissionTier::HumanApproval
        );
        assert_eq!(
            engine.classify(&make_proposal("purchase.any")),
            PermissionTier::HumanApproval
        );
    }

    #[test]
    fn test_classify_forbidden() {
        let file = write_temp_manifest(DEFAULT_MANIFEST);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        assert_eq!(
            engine.classify(&make_proposal("credentials.read_raw")),
            PermissionTier::Forbidden
        );
        assert_eq!(
            engine.classify(&make_proposal("system_prompt.modify")),
            PermissionTier::Forbidden
        );
        assert_eq!(
            engine.classify(&make_proposal("permissions.modify")),
            PermissionTier::Forbidden
        );
        assert_eq!(
            engine.classify(&make_proposal("data.bulk_delete")),
            PermissionTier::Forbidden
        );
        assert_eq!(
            engine.classify(&make_proposal("agent.self_modify")),
            PermissionTier::Forbidden
        );
    }

    #[test]
    fn test_unknown_action_defaults_to_human_approval() {
        let file = write_temp_manifest(DEFAULT_MANIFEST);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        assert_eq!(
            engine.classify(&make_proposal("some.unknown.action")),
            PermissionTier::HumanApproval
        );
        assert_eq!(
            engine.classify(&make_proposal("totally_random")),
            PermissionTier::HumanApproval
        );
    }

    // ========================================================
    // Tier priority tests
    // ========================================================

    #[test]
    fn test_tier_priority_forbidden_wins() {
        // If an action appears in both forbidden and auto_execute, forbidden wins.
        let manifest = r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - secret.read
  log_and_execute:
    description: "Logged"
    actions: []
  human_approval:
    description: "Needs approval"
    actions: []
  forbidden:
    description: "Blocked"
    actions:
      - secret.read
"#;
        let file = write_temp_manifest(manifest);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        assert_eq!(
            engine.classify(&make_proposal("secret.read")),
            PermissionTier::Forbidden
        );
    }

    #[test]
    fn test_tier_priority_human_approval_over_auto() {
        // If an action appears in both human_approval and auto_execute, human_approval wins.
        let manifest = r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - email.send
  log_and_execute:
    description: "Logged"
    actions: []
  human_approval:
    description: "Needs approval"
    actions:
      - email.send
  forbidden:
    description: "Blocked"
    actions: []
"#;
        let file = write_temp_manifest(manifest);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        assert_eq!(
            engine.classify(&make_proposal("email.send")),
            PermissionTier::HumanApproval
        );
    }

    #[test]
    fn test_wildcard_tier_priority() {
        // Wildcard in forbidden vs exact in auto_execute: forbidden wins.
        let manifest = r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - data.read
  log_and_execute:
    description: "Logged"
    actions: []
  human_approval:
    description: "Needs approval"
    actions: []
  forbidden:
    description: "Blocked"
    actions:
      - data.*
"#;
        let file = write_temp_manifest(manifest);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        assert_eq!(
            engine.classify(&make_proposal("data.read")),
            PermissionTier::Forbidden
        );
    }

    // ========================================================
    // Wildcard classification tests
    // ========================================================

    #[test]
    fn test_wildcard_classification() {
        let manifest = r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - read.*
  log_and_execute:
    description: "Logged"
    actions: []
  human_approval:
    description: "Needs approval"
    actions: []
  forbidden:
    description: "Blocked"
    actions: []
"#;
        let file = write_temp_manifest(manifest);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        assert_eq!(
            engine.classify(&make_proposal("read.email")),
            PermissionTier::AutoExecute
        );
        assert_eq!(
            engine.classify(&make_proposal("read.calendar")),
            PermissionTier::AutoExecute
        );
        // "read" alone should not match "read.*"
        assert_eq!(
            engine.classify(&make_proposal("read")),
            PermissionTier::HumanApproval
        );
    }

    // ========================================================
    // Rate limiting tests
    // ========================================================

    #[tokio::test]
    async fn test_rate_limit_within_limits() {
        let file = write_temp_manifest(DEFAULT_MANIFEST);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        // auto_execute tier has rate_limit: 60/minute → 60 tokens
        let proposal = make_proposal("calendar.read");
        // First call should succeed
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limit_exceeded() {
        let manifest = r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - test.action
    constraints:
      rate_limit: 3/minute
  log_and_execute:
    description: "Logged"
    actions: []
  human_approval:
    description: "Needs approval"
    actions: []
  forbidden:
    description: "Blocked"
    actions: []
"#;
        let file = write_temp_manifest(manifest);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();
        let proposal = make_proposal("test.action");

        // Consume all 3 tokens
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
        assert!(engine.check_rate_limit(&proposal).await.is_ok());

        // 4th call should fail
        let result = engine.check_rate_limit(&proposal).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.action, "test.action");
        assert_eq!(err.limit, "3/minute");
        assert!(err.retry_after_secs > 0);
    }

    #[tokio::test]
    async fn test_rate_limit_refill() {
        let manifest = r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - fast.action
    constraints:
      rate_limit: 2/second
  log_and_execute:
    description: "Logged"
    actions: []
  human_approval:
    description: "Needs approval"
    actions: []
  forbidden:
    description: "Blocked"
    actions: []
"#;
        let file = write_temp_manifest(manifest);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();
        let proposal = make_proposal("fast.action");

        // Consume all 2 tokens
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
        assert!(engine.check_rate_limit(&proposal).await.is_err());

        // Wait for refill (2 tokens/second → need ~0.5s for 1 token)
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        // Should have at least 1 token now
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
    }

    #[tokio::test]
    async fn test_no_rate_limit_returns_ok() {
        // Forbidden tier has no rate limit in default manifest
        let file = write_temp_manifest(DEFAULT_MANIFEST);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        let proposal = make_proposal("credentials.read_raw");
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
    }

    #[tokio::test]
    async fn test_unknown_action_no_rate_limit() {
        let file = write_temp_manifest(DEFAULT_MANIFEST);
        let engine = YamlPermissionEngine::new(file.path()).unwrap();

        let proposal = make_proposal("unknown.action");
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
    }

    // ========================================================
    // Hot-reload tests
    // ========================================================

    #[tokio::test]
    async fn test_hot_reload_changes_classification() {
        let manifest_v1 = r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - email.read
  log_and_execute:
    description: "Logged"
    actions: []
  human_approval:
    description: "Needs approval"
    actions: []
  forbidden:
    description: "Blocked"
    actions: []
"#;
        let file = write_temp_manifest(manifest_v1);
        let mut engine = YamlPermissionEngine::new(file.path()).unwrap();

        assert_eq!(
            engine.classify(&make_proposal("email.read")),
            PermissionTier::AutoExecute
        );

        // Rewrite the file with email.read moved to forbidden
        let manifest_v2 = r#"
tiers:
  auto_execute:
    description: "Safe"
    actions: []
  log_and_execute:
    description: "Logged"
    actions: []
  human_approval:
    description: "Needs approval"
    actions: []
  forbidden:
    description: "Blocked"
    actions:
      - email.read
"#;
        std::fs::write(file.path(), manifest_v2).unwrap();

        // Reload
        engine.reload_manifest().await.unwrap();

        // Now email.read should be forbidden
        assert_eq!(
            engine.classify(&make_proposal("email.read")),
            PermissionTier::Forbidden
        );
    }

    #[tokio::test]
    async fn test_hot_reload_preserves_rate_limit_state() {
        let manifest = r#"
tiers:
  auto_execute:
    description: "Safe"
    actions:
      - test.action
    constraints:
      rate_limit: 5/minute
  log_and_execute:
    description: "Logged"
    actions: []
  human_approval:
    description: "Needs approval"
    actions: []
  forbidden:
    description: "Blocked"
    actions: []
"#;
        let file = write_temp_manifest(manifest);
        let mut engine = YamlPermissionEngine::new(file.path()).unwrap();
        let proposal = make_proposal("test.action");

        // Consume 3 tokens
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
        assert!(engine.check_rate_limit(&proposal).await.is_ok());

        // Reload (same content — rate limit buckets should be preserved)
        engine.reload_manifest().await.unwrap();

        // Should still have only 2 tokens left (5 - 3 = 2, minus any tiny refill)
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
        assert!(engine.check_rate_limit(&proposal).await.is_ok());
        // 6th total consumption should fail
        assert!(engine.check_rate_limit(&proposal).await.is_err());
    }

    // ========================================================
    // Token bucket unit tests
    // ========================================================

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::new(3.0, 1.0);
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_token_bucket_retry_after() {
        let mut bucket = TokenBucket::new(1.0, 1.0);
        bucket.try_consume();
        // After consuming the only token, retry_after should be >= 1
        assert!(bucket.retry_after_secs() >= 1);
    }

    // ========================================================
    // Constructor error tests
    // ========================================================

    #[test]
    fn test_new_with_nonexistent_file() {
        let result = YamlPermissionEngine::new(Path::new("/nonexistent/path.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_new_with_invalid_yaml() {
        let file = write_temp_manifest("not: valid: yaml: [[[");
        let result = YamlPermissionEngine::new(file.path());
        assert!(result.is_err());
    }
}
