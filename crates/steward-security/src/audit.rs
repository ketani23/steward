//! Audit logger implementation.
//!
//! Append-only audit logging with two backends:
//!
//! - [`InMemoryAuditLogger`]: Stores events in a `Vec<AuditEvent>` behind `Arc<RwLock>`.
//!   Useful for testing and development.
//! - [`PostgresAuditLogger`]: PostgreSQL-backed, append-only. Secrets are redacted via
//!   [`LeakDetector`](steward_types::traits::LeakDetector) before storage.
//!
//! See `docs/architecture.md` Ring 3 (Audit & Observability) for full requirements.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgPool;
use tokio::sync::RwLock;
use tracing::info;

use steward_types::actions::*;
use steward_types::errors::StewardError;
use steward_types::traits::{AuditLogger, LeakDetector};

// ============================================================
// SQL Migration
// ============================================================

/// SQL migration to create the `audit_events` table and indexes.
pub const CREATE_AUDIT_EVENTS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    action_json JSONB,
    guardian_verdict_json JSONB,
    permission_tier TEXT,
    outcome JSONB NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type_timestamp ON audit_events (event_type, timestamp);
"#;

/// Run the audit logger migrations against the given pool.
pub async fn run_migrations(pool: &PgPool) -> Result<(), StewardError> {
    sqlx::query(CREATE_AUDIT_EVENTS_TABLE)
        .execute(pool)
        .await
        .map_err(|e| StewardError::Database(format!("failed to run audit migrations: {e}")))?;
    info!("audit_events table and indexes created or already exist");
    Ok(())
}

// ============================================================
// InMemoryAuditLogger
// ============================================================

/// In-memory audit logger for testing and development.
///
/// Stores events in a `Vec<AuditEvent>` behind an `Arc<RwLock<...>>`.
/// Implements the full [`AuditLogger`] trait and is useful as a mock
/// in tests for other modules.
#[derive(Clone)]
pub struct InMemoryAuditLogger {
    events: Arc<RwLock<Vec<AuditEvent>>>,
    leak_detector: Option<Arc<dyn LeakDetector>>,
}

impl std::fmt::Debug for InMemoryAuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryAuditLogger")
            .field("events", &"<RwLock<Vec<AuditEvent>>>")
            .field("leak_detector", &self.leak_detector.is_some())
            .finish()
    }
}

impl InMemoryAuditLogger {
    /// Create a new in-memory audit logger without leak detection.
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            leak_detector: None,
        }
    }

    /// Create a new in-memory audit logger with a leak detector for secret redaction.
    pub fn with_leak_detector(leak_detector: Arc<dyn LeakDetector>) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            leak_detector: Some(leak_detector),
        }
    }

    /// Get a snapshot of all stored events.
    pub async fn all_events(&self) -> Vec<AuditEvent> {
        self.events.read().await.clone()
    }

    /// Get the count of stored events.
    pub async fn count(&self) -> usize {
        self.events.read().await.len()
    }

    /// Redact secrets from an event using the configured leak detector.
    fn redact_event(&self, mut event: AuditEvent) -> AuditEvent {
        let Some(detector) = &self.leak_detector else {
            return event;
        };

        // Redact action parameters
        if let Some(ref mut action) = event.action {
            let params_str = action.parameters.to_string();
            let redacted = detector.redact(&params_str);
            if let Ok(v) = serde_json::from_str(&redacted) {
                action.parameters = v;
            } else {
                action.parameters = serde_json::Value::String(redacted);
            }

            let reasoning_redacted = detector.redact(&action.reasoning);
            action.reasoning = reasoning_redacted;
        }

        // Redact metadata
        let meta_str = event.metadata.to_string();
        let redacted_meta = detector.redact(&meta_str);
        if let Ok(v) = serde_json::from_str(&redacted_meta) {
            event.metadata = v;
        } else {
            event.metadata = serde_json::Value::String(redacted_meta);
        }

        event
    }
}

impl Default for InMemoryAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether an event matches the given filter criteria.
fn matches_filter(event: &AuditEvent, filter: &AuditFilter) -> bool {
    // Time range
    if let Some(ref from) = filter.from {
        if event.timestamp < *from {
            return false;
        }
    }
    if let Some(ref to) = filter.to {
        if event.timestamp >= *to {
            return false;
        }
    }

    // Event type
    if let Some(ref event_type) = filter.event_type {
        if std::mem::discriminant(&event.event_type) != std::mem::discriminant(event_type) {
            return false;
        }
    }

    // Outcome (match on variant name)
    if let Some(ref outcome) = filter.outcome {
        let event_outcome_name = match &event.outcome {
            ActionOutcome::Executed => "Executed",
            ActionOutcome::Blocked { .. } => "Blocked",
            ActionOutcome::Pending => "Pending",
            ActionOutcome::Failed { .. } => "Failed",
            ActionOutcome::TimedOut => "TimedOut",
        };
        if !event_outcome_name.eq_ignore_ascii_case(outcome) {
            return false;
        }
    }

    // Tool name (check action's tool_name)
    if let Some(ref tool_name) = filter.tool_name {
        match &event.action {
            Some(action) => {
                if action.tool_name != *tool_name {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

#[async_trait]
impl AuditLogger for InMemoryAuditLogger {
    /// Log an audit event. Append-only — events are never modified or removed.
    async fn log(&self, event: AuditEvent) -> Result<(), StewardError> {
        let event = self.redact_event(event);
        self.events.write().await.push(event);
        Ok(())
    }

    /// Query audit events with filters. Returns matching events in chronological order.
    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>, StewardError> {
        let events = self.events.read().await;
        let mut results: Vec<AuditEvent> = events
            .iter()
            .filter(|e| matches_filter(e, &filter))
            .cloned()
            .collect();

        // Sort by timestamp ascending
        results.sort_by_key(|e| e.timestamp);

        // Apply limit
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        Ok(results)
    }
}

// ============================================================
// PostgresAuditLogger
// ============================================================

/// PostgreSQL-backed audit logger for production use.
///
/// Append-only: the `log` method performs INSERT only, never UPDATE or DELETE.
/// Secrets are redacted before storage via the configured [`LeakDetector`].
pub struct PostgresAuditLogger {
    pool: PgPool,
    leak_detector: Arc<dyn LeakDetector>,
}

impl PostgresAuditLogger {
    /// Create a new PostgreSQL audit logger.
    ///
    /// The caller is responsible for running [`run_migrations`] before using this logger.
    pub fn new(pool: PgPool, leak_detector: Arc<dyn LeakDetector>) -> Self {
        Self {
            pool,
            leak_detector,
        }
    }

    /// Redact secrets in action parameters and metadata before storage.
    fn redact_event(&self, mut event: AuditEvent) -> AuditEvent {
        // Redact action parameters
        if let Some(ref mut action) = event.action {
            let params_str = action.parameters.to_string();
            let redacted = self.leak_detector.redact(&params_str);
            if let Ok(v) = serde_json::from_str(&redacted) {
                action.parameters = v;
            } else {
                action.parameters = serde_json::Value::String(redacted);
            }

            let reasoning_redacted = self.leak_detector.redact(&action.reasoning);
            action.reasoning = reasoning_redacted;
        }

        // Redact metadata
        let meta_str = event.metadata.to_string();
        let redacted_meta = self.leak_detector.redact(&meta_str);
        if let Ok(v) = serde_json::from_str(&redacted_meta) {
            event.metadata = v;
        } else {
            event.metadata = serde_json::Value::String(redacted_meta);
        }

        event
    }

    /// Serialize an [`AuditEventType`] to its string representation for storage.
    fn event_type_to_string(event_type: &AuditEventType) -> String {
        match event_type {
            AuditEventType::ToolCall => "ToolCall".to_string(),
            AuditEventType::GuardianReview => "GuardianReview".to_string(),
            AuditEventType::PermissionCheck => "PermissionCheck".to_string(),
            AuditEventType::EgressBlock => "EgressBlock".to_string(),
            AuditEventType::IngressDetection => "IngressDetection".to_string(),
            AuditEventType::RateLimitHit => "RateLimitHit".to_string(),
            AuditEventType::CircuitBreakerTrip => "CircuitBreakerTrip".to_string(),
            AuditEventType::McpServerEvent => "McpServerEvent".to_string(),
            AuditEventType::UserApproval => "UserApproval".to_string(),
        }
    }

    /// Parse an [`AuditEventType`] from its string representation.
    fn event_type_from_string(s: &str) -> Result<AuditEventType, StewardError> {
        match s {
            "ToolCall" => Ok(AuditEventType::ToolCall),
            "GuardianReview" => Ok(AuditEventType::GuardianReview),
            "PermissionCheck" => Ok(AuditEventType::PermissionCheck),
            "EgressBlock" => Ok(AuditEventType::EgressBlock),
            "IngressDetection" => Ok(AuditEventType::IngressDetection),
            "RateLimitHit" => Ok(AuditEventType::RateLimitHit),
            "CircuitBreakerTrip" => Ok(AuditEventType::CircuitBreakerTrip),
            "McpServerEvent" => Ok(AuditEventType::McpServerEvent),
            "UserApproval" => Ok(AuditEventType::UserApproval),
            other => Err(StewardError::Audit(format!("unknown event type: {other}"))),
        }
    }

    /// Serialize a [`PermissionTier`] to its string representation.
    fn permission_tier_to_string(tier: &PermissionTier) -> String {
        match tier {
            PermissionTier::AutoExecute => "AutoExecute".to_string(),
            PermissionTier::LogAndExecute => "LogAndExecute".to_string(),
            PermissionTier::HumanApproval => "HumanApproval".to_string(),
            PermissionTier::Forbidden => "Forbidden".to_string(),
        }
    }

    /// Parse a [`PermissionTier`] from its string representation.
    fn permission_tier_from_string(s: &str) -> Result<PermissionTier, StewardError> {
        match s {
            "AutoExecute" => Ok(PermissionTier::AutoExecute),
            "LogAndExecute" => Ok(PermissionTier::LogAndExecute),
            "HumanApproval" => Ok(PermissionTier::HumanApproval),
            "Forbidden" => Ok(PermissionTier::Forbidden),
            other => Err(StewardError::Audit(format!(
                "unknown permission tier: {other}"
            ))),
        }
    }

    /// Reconstruct an [`AuditEvent`] from a database row.
    #[allow(clippy::too_many_arguments)]
    fn row_to_event(
        id: uuid::Uuid,
        timestamp: chrono::DateTime<chrono::Utc>,
        event_type: String,
        action_json: Option<serde_json::Value>,
        guardian_verdict_json: Option<serde_json::Value>,
        permission_tier: Option<String>,
        outcome: serde_json::Value,
        metadata: serde_json::Value,
    ) -> Result<AuditEvent, StewardError> {
        let event_type = Self::event_type_from_string(&event_type)?;
        let action: Option<ActionProposal> = action_json
            .map(|v| serde_json::from_value(v).map_err(StewardError::from))
            .transpose()?;
        let guardian_verdict: Option<GuardianVerdict> = guardian_verdict_json
            .map(|v| serde_json::from_value(v).map_err(StewardError::from))
            .transpose()?;
        let permission_tier = permission_tier
            .map(|s| Self::permission_tier_from_string(&s))
            .transpose()?;
        let outcome: ActionOutcome = serde_json::from_value(outcome).map_err(StewardError::from)?;

        Ok(AuditEvent {
            id,
            timestamp,
            event_type,
            action,
            guardian_verdict,
            permission_tier,
            outcome,
            metadata,
        })
    }
}

#[async_trait]
impl AuditLogger for PostgresAuditLogger {
    /// Log an audit event. INSERT only — never UPDATE or DELETE.
    async fn log(&self, event: AuditEvent) -> Result<(), StewardError> {
        let event = self.redact_event(event);

        let event_type_str = Self::event_type_to_string(&event.event_type);
        let action_json = event
            .action
            .as_ref()
            .map(|a| serde_json::to_value(a).unwrap_or_default());
        let guardian_json = event
            .guardian_verdict
            .as_ref()
            .map(|g| serde_json::to_value(g).unwrap_or_default());
        let permission_str = event
            .permission_tier
            .as_ref()
            .map(Self::permission_tier_to_string);
        let outcome_json = serde_json::to_value(&event.outcome).map_err(StewardError::from)?;

        sqlx::query(
            r#"INSERT INTO audit_events (id, timestamp, event_type, action_json, guardian_verdict_json, permission_tier, outcome, metadata)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(event.id)
        .bind(event.timestamp)
        .bind(event_type_str)
        .bind(action_json)
        .bind(guardian_json)
        .bind(permission_str)
        .bind(outcome_json)
        .bind(&event.metadata)
        .execute(&self.pool)
        .await
        .map_err(|e| StewardError::Database(format!("failed to insert audit event: {e}")))?;

        Ok(())
    }

    /// Query audit events with filters.
    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>, StewardError> {
        // Build a dynamic query with optional WHERE clauses.
        // sqlx doesn't support optional binds easily, so we build the query string
        // and use a QueryBuilder-style approach.
        let mut conditions: Vec<String> = Vec::new();
        let mut param_index: usize = 1;

        // We'll collect parameter values to bind later. Since sqlx needs typed binds,
        // we use separate optional holders and bind them conditionally.
        if filter.from.is_some() {
            conditions.push(format!("timestamp >= ${param_index}"));
            param_index += 1;
        }
        if filter.to.is_some() {
            conditions.push(format!("timestamp < ${param_index}"));
            param_index += 1;
        }
        if filter.event_type.is_some() {
            conditions.push(format!("event_type = ${param_index}"));
            param_index += 1;
        }
        if filter.outcome.is_some() {
            // Match on the JSON variant tag. ActionOutcome serializes as e.g. "Executed" or {"Blocked": {...}}
            // We use a text cast and ILIKE for simple variant matching.
            conditions.push(format!("outcome::text ILIKE '%' || ${param_index} || '%'"));
            param_index += 1;
        }
        if filter.tool_name.is_some() {
            conditions.push(format!("action_json->>'tool_name' = ${param_index}"));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit_clause = if let Some(limit) = filter.limit {
            format!("LIMIT {limit}")
        } else {
            String::new()
        };

        let query_str = format!(
            "SELECT id, timestamp, event_type, action_json, guardian_verdict_json, permission_tier, outcome, metadata FROM audit_events {where_clause} ORDER BY timestamp ASC {limit_clause}"
        );

        // Now we need to bind parameters in order. We use sqlx::query_as or raw query.
        let mut query = sqlx::query_as::<
            _,
            (
                uuid::Uuid,
                chrono::DateTime<chrono::Utc>,
                String,
                Option<serde_json::Value>,
                Option<serde_json::Value>,
                Option<String>,
                serde_json::Value,
                serde_json::Value,
            ),
        >(&query_str);

        if let Some(ref from) = filter.from {
            query = query.bind(from);
        }
        if let Some(ref to) = filter.to {
            query = query.bind(to);
        }
        if let Some(ref event_type) = filter.event_type {
            query = query.bind(Self::event_type_to_string(event_type));
        }
        if let Some(ref outcome) = filter.outcome {
            query = query.bind(outcome);
        }
        if let Some(ref tool_name) = filter.tool_name {
            query = query.bind(tool_name);
        }

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StewardError::Database(format!("failed to query audit events: {e}")))?;

        let mut events = Vec::with_capacity(rows.len());
        for (id, timestamp, event_type, action_json, guardian_json, perm_tier, outcome, metadata) in
            rows
        {
            let event = Self::row_to_event(
                id,
                timestamp,
                event_type,
                action_json,
                guardian_json,
                perm_tier,
                outcome,
                metadata,
            )?;
            events.push(event);
        }

        Ok(events)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    // ----------------------------------------------------------
    // Mock LeakDetector
    // ----------------------------------------------------------

    /// A mock leak detector that redacts any occurrence of "SECRET_KEY_123" and "my-api-token".
    struct MockLeakDetector;

    impl LeakDetector for MockLeakDetector {
        fn scan(&self, content: &str) -> Vec<LeakDetection> {
            let mut detections = Vec::new();
            for pattern in &["SECRET_KEY_123", "my-api-token"] {
                if let Some(offset) = content.find(pattern) {
                    detections.push(LeakDetection {
                        pattern_name: "test_secret".to_string(),
                        offset,
                        length: pattern.len(),
                        confidence: 1.0,
                    });
                }
            }
            detections
        }

        fn redact(&self, content: &str) -> String {
            content
                .replace("SECRET_KEY_123", "[REDACTED:test_secret]")
                .replace("my-api-token", "[REDACTED:test_secret]")
        }
    }

    /// A no-op leak detector that doesn't redact anything.
    struct NoopLeakDetector;

    impl LeakDetector for NoopLeakDetector {
        fn scan(&self, _content: &str) -> Vec<LeakDetection> {
            vec![]
        }
        fn redact(&self, content: &str) -> String {
            content.to_string()
        }
    }

    // ----------------------------------------------------------
    // Test helpers
    // ----------------------------------------------------------

    fn make_event(event_type: AuditEventType, tool_name: Option<&str>) -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            action: tool_name.map(|name| ActionProposal {
                id: Uuid::new_v4(),
                tool_name: name.to_string(),
                parameters: serde_json::json!({"key": "value"}),
                reasoning: "test reasoning".to_string(),
                user_message_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            }),
            guardian_verdict: None,
            permission_tier: Some(PermissionTier::AutoExecute),
            outcome: ActionOutcome::Executed,
            metadata: serde_json::json!({}),
        }
    }

    fn make_event_at(
        event_type: AuditEventType,
        tool_name: Option<&str>,
        timestamp: chrono::DateTime<Utc>,
    ) -> AuditEvent {
        let mut event = make_event(event_type, tool_name);
        event.timestamp = timestamp;
        event
    }

    // ----------------------------------------------------------
    // InMemoryAuditLogger: basic tests
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_inmemory_log_and_query() {
        let logger = InMemoryAuditLogger::new();
        let event = make_event(AuditEventType::ToolCall, Some("gmail.send"));

        logger.log(event.clone()).await.unwrap();

        let all = logger.all_events().await;
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, event.id);
    }

    #[tokio::test]
    async fn test_inmemory_append_only() {
        let logger = InMemoryAuditLogger::new();

        let e1 = make_event(AuditEventType::ToolCall, Some("a"));
        let e2 = make_event(AuditEventType::GuardianReview, Some("b"));
        let e3 = make_event(AuditEventType::PermissionCheck, Some("c"));

        logger.log(e1.clone()).await.unwrap();
        logger.log(e2.clone()).await.unwrap();
        logger.log(e3.clone()).await.unwrap();

        let all = logger.all_events().await;
        assert_eq!(all.len(), 3);
        // Verify insertion order is preserved
        assert_eq!(all[0].id, e1.id);
        assert_eq!(all[1].id, e2.id);
        assert_eq!(all[2].id, e3.id);
    }

    #[tokio::test]
    async fn test_inmemory_multiple_events_in_order() {
        let logger = InMemoryAuditLogger::new();
        let now = Utc::now();

        for i in 0..10 {
            let event = make_event_at(
                AuditEventType::ToolCall,
                Some("tool"),
                now + Duration::seconds(i),
            );
            logger.log(event).await.unwrap();
        }

        assert_eq!(logger.count().await, 10);

        let results = logger.query(AuditFilter::default()).await.unwrap();
        assert_eq!(results.len(), 10);
        // Results should be sorted by timestamp
        for i in 1..results.len() {
            assert!(results[i].timestamp >= results[i - 1].timestamp);
        }
    }

    // ----------------------------------------------------------
    // InMemoryAuditLogger: filter tests
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_inmemory_filter_by_event_type() {
        let logger = InMemoryAuditLogger::new();

        logger
            .log(make_event(AuditEventType::ToolCall, Some("a")))
            .await
            .unwrap();
        logger
            .log(make_event(AuditEventType::GuardianReview, Some("b")))
            .await
            .unwrap();
        logger
            .log(make_event(AuditEventType::ToolCall, Some("c")))
            .await
            .unwrap();

        let filter = AuditFilter {
            event_type: Some(AuditEventType::ToolCall),
            ..Default::default()
        };
        let results = logger.query(filter).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_inmemory_filter_by_time_range() {
        let logger = InMemoryAuditLogger::new();
        let now = Utc::now();

        let e1 = make_event_at(
            AuditEventType::ToolCall,
            Some("a"),
            now - Duration::hours(2),
        );
        let e2 = make_event_at(
            AuditEventType::ToolCall,
            Some("b"),
            now - Duration::hours(1),
        );
        let e3 = make_event_at(AuditEventType::ToolCall, Some("c"), now);

        logger.log(e1).await.unwrap();
        logger.log(e2.clone()).await.unwrap();
        logger.log(e3).await.unwrap();

        let filter = AuditFilter {
            from: Some(now - Duration::minutes(90)),
            to: Some(now - Duration::minutes(30)),
            ..Default::default()
        };
        let results = logger.query(filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, e2.id);
    }

    #[tokio::test]
    async fn test_inmemory_filter_by_tool_name() {
        let logger = InMemoryAuditLogger::new();

        logger
            .log(make_event(AuditEventType::ToolCall, Some("gmail.send")))
            .await
            .unwrap();
        logger
            .log(make_event(AuditEventType::ToolCall, Some("shell.exec")))
            .await
            .unwrap();
        logger
            .log(make_event(AuditEventType::ToolCall, Some("gmail.send")))
            .await
            .unwrap();

        let filter = AuditFilter {
            tool_name: Some("gmail.send".to_string()),
            ..Default::default()
        };
        let results = logger.query(filter).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_inmemory_filter_by_outcome() {
        let logger = InMemoryAuditLogger::new();

        let mut blocked_event = make_event(AuditEventType::ToolCall, Some("a"));
        blocked_event.outcome = ActionOutcome::Blocked {
            reason: "test block".to_string(),
        };

        logger
            .log(make_event(AuditEventType::ToolCall, Some("b")))
            .await
            .unwrap();
        logger.log(blocked_event).await.unwrap();

        let filter = AuditFilter {
            outcome: Some("Blocked".to_string()),
            ..Default::default()
        };
        let results = logger.query(filter).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_inmemory_filter_with_limit() {
        let logger = InMemoryAuditLogger::new();

        for _ in 0..5 {
            logger
                .log(make_event(AuditEventType::ToolCall, Some("a")))
                .await
                .unwrap();
        }

        let filter = AuditFilter {
            limit: Some(3),
            ..Default::default()
        };
        let results = logger.query(filter).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_inmemory_filter_no_action_with_tool_name_filter() {
        let logger = InMemoryAuditLogger::new();

        // Event with no action
        let mut event = make_event(AuditEventType::RateLimitHit, None);
        event.action = None;
        logger.log(event).await.unwrap();

        let filter = AuditFilter {
            tool_name: Some("gmail.send".to_string()),
            ..Default::default()
        };
        let results = logger.query(filter).await.unwrap();
        assert_eq!(results.len(), 0);
    }

    // ----------------------------------------------------------
    // Serialization tests
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_audit_event_serialization_roundtrip() {
        let event = make_event(AuditEventType::ToolCall, Some("gmail.send"));
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event.id, deserialized.id);
        assert_eq!(
            std::mem::discriminant(&event.event_type),
            std::mem::discriminant(&deserialized.event_type)
        );
    }

    #[tokio::test]
    async fn test_audit_event_serialization_all_outcomes() {
        let outcomes = vec![
            ActionOutcome::Executed,
            ActionOutcome::Blocked {
                reason: "test".to_string(),
            },
            ActionOutcome::Pending,
            ActionOutcome::Failed {
                error: "oops".to_string(),
            },
            ActionOutcome::TimedOut,
        ];

        for outcome in outcomes {
            let json = serde_json::to_string(&outcome).unwrap();
            let deserialized: ActionOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(
                std::mem::discriminant(&outcome),
                std::mem::discriminant(&deserialized)
            );
        }
    }

    #[tokio::test]
    async fn test_audit_event_with_guardian_verdict_serialization() {
        let mut event = make_event(AuditEventType::GuardianReview, Some("shell.exec"));
        event.guardian_verdict = Some(GuardianVerdict {
            decision: GuardianDecision::Allow,
            reasoning: "looks safe".to_string(),
            confidence: 0.95,
            injection_indicators: vec![],
            timestamp: Utc::now(),
        });

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
        assert!(deserialized.guardian_verdict.is_some());
        assert_eq!(
            deserialized.guardian_verdict.unwrap().decision,
            GuardianDecision::Allow
        );
    }

    // ----------------------------------------------------------
    // Leak detector integration tests
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_inmemory_with_leak_detector_redacts_parameters() {
        let detector = Arc::new(MockLeakDetector);
        let logger = InMemoryAuditLogger::with_leak_detector(detector);

        let mut event = make_event(AuditEventType::ToolCall, Some("gmail.send"));
        if let Some(ref mut action) = event.action {
            action.parameters = serde_json::json!({"api_key": "SECRET_KEY_123"});
        }

        logger.log(event).await.unwrap();

        let all = logger.all_events().await;
        assert_eq!(all.len(), 1);
        let stored_params = all[0].action.as_ref().unwrap().parameters.to_string();
        assert!(
            !stored_params.contains("SECRET_KEY_123"),
            "secret should be redacted"
        );
        assert!(
            stored_params.contains("[REDACTED:test_secret]"),
            "redaction marker should be present"
        );
    }

    #[tokio::test]
    async fn test_inmemory_with_leak_detector_redacts_reasoning() {
        let detector = Arc::new(MockLeakDetector);
        let logger = InMemoryAuditLogger::with_leak_detector(detector);

        let mut event = make_event(AuditEventType::ToolCall, Some("shell.exec"));
        if let Some(ref mut action) = event.action {
            action.reasoning = "Using my-api-token to authenticate".to_string();
        }

        logger.log(event).await.unwrap();

        let all = logger.all_events().await;
        let stored_reasoning = &all[0].action.as_ref().unwrap().reasoning;
        assert!(
            !stored_reasoning.contains("my-api-token"),
            "secret should be redacted from reasoning"
        );
        assert!(stored_reasoning.contains("[REDACTED:test_secret]"));
    }

    #[tokio::test]
    async fn test_inmemory_with_leak_detector_redacts_metadata() {
        let detector = Arc::new(MockLeakDetector);
        let logger = InMemoryAuditLogger::with_leak_detector(detector);

        let mut event = make_event(AuditEventType::ToolCall, Some("tool"));
        event.metadata = serde_json::json!({"debug_info": "token=SECRET_KEY_123"});

        logger.log(event).await.unwrap();

        let all = logger.all_events().await;
        let meta_str = all[0].metadata.to_string();
        assert!(!meta_str.contains("SECRET_KEY_123"));
        assert!(meta_str.contains("[REDACTED:test_secret]"));
    }

    #[tokio::test]
    async fn test_inmemory_without_leak_detector_no_redaction() {
        let logger = InMemoryAuditLogger::new();

        let mut event = make_event(AuditEventType::ToolCall, Some("tool"));
        if let Some(ref mut action) = event.action {
            action.parameters = serde_json::json!({"api_key": "SECRET_KEY_123"});
        }

        logger.log(event).await.unwrap();

        let all = logger.all_events().await;
        let stored_params = all[0].action.as_ref().unwrap().parameters.to_string();
        assert!(
            stored_params.contains("SECRET_KEY_123"),
            "without leak detector, secret should not be redacted"
        );
    }

    // ----------------------------------------------------------
    // Clone / concurrent access test
    // ----------------------------------------------------------

    #[tokio::test]
    async fn test_inmemory_clone_shares_state() {
        let logger = InMemoryAuditLogger::new();
        let logger_clone = logger.clone();

        logger
            .log(make_event(AuditEventType::ToolCall, Some("a")))
            .await
            .unwrap();
        logger_clone
            .log(make_event(AuditEventType::ToolCall, Some("b")))
            .await
            .unwrap();

        assert_eq!(logger.count().await, 2);
        assert_eq!(logger_clone.count().await, 2);
    }

    #[tokio::test]
    async fn test_inmemory_concurrent_logging() {
        let logger = InMemoryAuditLogger::new();
        let mut handles = Vec::new();

        for i in 0..20 {
            let l = logger.clone();
            handles.push(tokio::spawn(async move {
                let event = make_event(AuditEventType::ToolCall, Some(&format!("tool.{i}")));
                l.log(event).await.unwrap();
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(logger.count().await, 20);
    }

    #[tokio::test]
    async fn test_inmemory_empty_query_returns_empty() {
        let logger = InMemoryAuditLogger::new();
        let results = logger.query(AuditFilter::default()).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_inmemory_combined_filters() {
        let logger = InMemoryAuditLogger::new();
        let now = Utc::now();

        // Event matching: ToolCall + gmail.send + recent
        let e1 = make_event_at(
            AuditEventType::ToolCall,
            Some("gmail.send"),
            now - Duration::minutes(5),
        );
        // Event NOT matching: GuardianReview
        let e2 = make_event_at(
            AuditEventType::GuardianReview,
            Some("gmail.send"),
            now - Duration::minutes(4),
        );
        // Event NOT matching: different tool
        let e3 = make_event_at(
            AuditEventType::ToolCall,
            Some("shell.exec"),
            now - Duration::minutes(3),
        );
        // Event NOT matching: outside time range
        let e4 = make_event_at(
            AuditEventType::ToolCall,
            Some("gmail.send"),
            now - Duration::hours(2),
        );

        logger.log(e1.clone()).await.unwrap();
        logger.log(e2).await.unwrap();
        logger.log(e3).await.unwrap();
        logger.log(e4).await.unwrap();

        let filter = AuditFilter {
            from: Some(now - Duration::minutes(10)),
            to: Some(now),
            event_type: Some(AuditEventType::ToolCall),
            tool_name: Some("gmail.send".to_string()),
            ..Default::default()
        };
        let results = logger.query(filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, e1.id);
    }

    // ----------------------------------------------------------
    // PostgresAuditLogger integration tests (gated)
    // ----------------------------------------------------------

    /// These tests require a running PostgreSQL instance. Set DATABASE_URL to run them.
    /// Example: DATABASE_URL="postgresql://user:pass@localhost/steward_test" cargo test -p steward-security -- --ignored
    #[cfg(test)]
    mod integration {
        use super::*;
        use tracing::warn;

        async fn setup_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL").ok()?;
            let pool = PgPool::connect(&url).await.ok()?;
            run_migrations(&pool).await.ok()?;
            // Clean up previous test data
            sqlx::query("DELETE FROM audit_events")
                .execute(&pool)
                .await
                .ok()?;
            Some(pool)
        }

        #[tokio::test]
        #[ignore]
        async fn test_postgres_insert_and_query() {
            let pool = match setup_pool().await {
                Some(p) => p,
                None => {
                    warn!("DATABASE_URL not set, skipping integration test");
                    return;
                }
            };

            let detector: Arc<dyn LeakDetector> = Arc::new(NoopLeakDetector);
            let logger = PostgresAuditLogger::new(pool, detector);

            let event = make_event(AuditEventType::ToolCall, Some("gmail.send"));
            let event_id = event.id;

            logger.log(event).await.unwrap();

            let results = logger.query(AuditFilter::default()).await.unwrap();
            assert!(!results.is_empty());
            assert!(results.iter().any(|e| e.id == event_id));
        }

        #[tokio::test]
        #[ignore]
        async fn test_postgres_redaction_before_storage() {
            let pool = match setup_pool().await {
                Some(p) => p,
                None => return,
            };

            let detector: Arc<dyn LeakDetector> = Arc::new(MockLeakDetector);
            let logger = PostgresAuditLogger::new(pool, detector);

            let mut event = make_event(AuditEventType::ToolCall, Some("tool"));
            if let Some(ref mut action) = event.action {
                action.parameters = serde_json::json!({"token": "SECRET_KEY_123"});
            }

            logger.log(event).await.unwrap();

            let results = logger.query(AuditFilter::default()).await.unwrap();
            assert_eq!(results.len(), 1);
            let stored = results[0].action.as_ref().unwrap().parameters.to_string();
            assert!(!stored.contains("SECRET_KEY_123"));
            assert!(stored.contains("[REDACTED:test_secret]"));
        }

        #[tokio::test]
        #[ignore]
        async fn test_postgres_query_filters() {
            let pool = match setup_pool().await {
                Some(p) => p,
                None => return,
            };

            let detector: Arc<dyn LeakDetector> = Arc::new(NoopLeakDetector);
            let logger = PostgresAuditLogger::new(pool, detector);

            let now = Utc::now();

            let e1 = make_event_at(
                AuditEventType::ToolCall,
                Some("gmail.send"),
                now - Duration::minutes(5),
            );
            let e2 = make_event_at(
                AuditEventType::GuardianReview,
                Some("shell.exec"),
                now - Duration::minutes(3),
            );
            let e3 = make_event_at(
                AuditEventType::ToolCall,
                Some("gmail.read"),
                now - Duration::minutes(1),
            );

            logger.log(e1).await.unwrap();
            logger.log(e2).await.unwrap();
            logger.log(e3).await.unwrap();

            // Filter by event type
            let filter = AuditFilter {
                event_type: Some(AuditEventType::ToolCall),
                ..Default::default()
            };
            let results = logger.query(filter).await.unwrap();
            assert_eq!(results.len(), 2);

            // Filter by tool name
            let filter = AuditFilter {
                tool_name: Some("gmail.send".to_string()),
                ..Default::default()
            };
            let results = logger.query(filter).await.unwrap();
            assert_eq!(results.len(), 1);
        }

        #[tokio::test]
        #[ignore]
        async fn test_postgres_concurrent_logging() {
            let pool = match setup_pool().await {
                Some(p) => p,
                None => return,
            };

            let detector: Arc<dyn LeakDetector> = Arc::new(NoopLeakDetector);
            let logger = Arc::new(PostgresAuditLogger::new(pool, detector));

            let mut handles = Vec::new();
            for i in 0..20 {
                let l = logger.clone();
                handles.push(tokio::spawn(async move {
                    let event = make_event(AuditEventType::ToolCall, Some(&format!("tool.{i}")));
                    l.log(event).await.unwrap();
                }));
            }

            for handle in handles {
                handle.await.unwrap();
            }

            let results = logger.query(AuditFilter::default()).await.unwrap();
            assert_eq!(results.len(), 20);
        }
    }
}
