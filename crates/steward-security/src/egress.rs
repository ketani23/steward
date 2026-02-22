//! Egress filter implementation.
//!
//! Last line of defense — scans ALL outbound content before it leaves the system:
//! - PII detection (SSNs, credit cards, emails, phone numbers, addresses, health terms)
//! - Secret pattern matching (delegated to [`LeakDetector`])
//! - Recipient validation against a configurable known-contacts allowlist
//! - Volume anomaly detection via sliding window counter
//! - Content policy enforcement (detects data-dump-like content in communication actions)
//!
//! See `docs/architecture.md` section 5.5 for full requirements.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use tokio::sync::Mutex;
use tracing::warn;

use steward_types::actions::{EgressDecision, OutboundContent, PatternSeverity, SensitivePattern};
use steward_types::errors::StewardError;
use steward_types::traits::{EgressFilter, LeakDetector};

// ============================================================
// Configuration
// ============================================================

/// Configuration for the egress filter.
#[derive(Debug, Clone)]
pub struct EgressFilterConfig {
    /// Known contacts allowlist. Recipients matching any of these patterns are allowed.
    /// Supports exact strings and simple glob-style matching (e.g., `*@example.com`).
    pub allowed_contacts: Vec<String>,
    /// Maximum number of outbound messages allowed in a sliding window.
    pub volume_threshold: u64,
    /// Duration of the sliding window in seconds.
    pub volume_window_secs: u64,
    /// Entropy threshold above which content is flagged as a potential data dump.
    /// Shannon entropy is measured per-byte; typical English text is ~4.0–4.5.
    pub entropy_threshold: f64,
}

impl Default for EgressFilterConfig {
    fn default() -> Self {
        Self {
            allowed_contacts: Vec::new(),
            volume_threshold: 20,
            volume_window_secs: 60,
            entropy_threshold: 5.0,
        }
    }
}

// ============================================================
// Compiled PII pattern
// ============================================================

/// A compiled pattern with its metadata.
struct CompiledPattern {
    name: String,
    regex: Regex,
    severity: PatternSeverity,
}

// ============================================================
// EgressFilterImpl
// ============================================================

/// Production implementation of the [`EgressFilter`] trait.
///
/// Accepts a [`LeakDetector`] for secret scanning and is configured via
/// [`EgressFilterConfig`] for recipient validation and volume limits.
pub struct EgressFilterImpl {
    leak_detector: Arc<dyn LeakDetector>,
    config: EgressFilterConfig,
    /// Built-in and user-registered PII patterns (compiled).
    patterns: Vec<CompiledPattern>,
    /// Sliding window timestamps for volume anomaly detection.
    send_timestamps: Arc<Mutex<Vec<DateTime<Utc>>>>,
}

impl EgressFilterImpl {
    /// Create a new egress filter with the default PII patterns.
    pub fn new(
        leak_detector: Arc<dyn LeakDetector>,
        config: EgressFilterConfig,
    ) -> Result<Self, StewardError> {
        let mut filter = Self {
            leak_detector,
            config,
            patterns: Vec::new(),
            send_timestamps: Arc::new(Mutex::new(Vec::new())),
        };
        filter.register_builtin_patterns()?;
        Ok(filter)
    }

    /// Register all built-in PII patterns.
    fn register_builtin_patterns(&mut self) -> Result<(), StewardError> {
        let builtins: Vec<(&str, &str, PatternSeverity)> = vec![
            // SSN: XXX-XX-XXXX
            ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", PatternSeverity::Critical),
            // Credit card: 13–19 digits, optionally separated by spaces or dashes
            (
                "credit_card",
                r"\b(?:\d[ -]*?){13,19}\b",
                PatternSeverity::Critical,
            ),
            // Email address
            (
                "email_address",
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                PatternSeverity::Low,
            ),
            // US phone numbers: various formats
            (
                "phone_number",
                r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                PatternSeverity::Medium,
            ),
            // US street address (best effort): number + street name + suffix
            (
                "physical_address",
                r"\b\d{1,5}\s+[A-Za-z0-9\s.]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Road|Rd|Court|Ct|Way|Place|Pl)\b",
                PatternSeverity::Medium,
            ),
            // ICD-10 codes: letter followed by digits, optional dot + more digits
            (
                "icd_code",
                r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b",
                PatternSeverity::High,
            ),
            // Common medication names (sample list — extensible via register_pattern)
            (
                "medication_name",
                r"(?i)\b(?:metformin|lisinopril|atorvastatin|levothyroxine|amlodipine|omeprazole|simvastatin|losartan|gabapentin|hydrochlorothiazide|sertraline|metoprolol|alprazolam|tramadol|oxycodone|hydrocodone|amoxicillin|azithromycin|prednisone|insulin)\b",
                PatternSeverity::High,
            ),
        ];

        for (name, pattern, severity) in builtins {
            let regex = Regex::new(pattern).map_err(|e| {
                StewardError::Egress(format!("failed to compile built-in pattern '{name}': {e}"))
            })?;
            self.patterns.push(CompiledPattern {
                name: name.to_string(),
                regex,
                severity,
            });
        }

        Ok(())
    }

    /// Check if a recipient is in the known-contacts allowlist.
    fn is_recipient_allowed(&self, recipient: &str) -> bool {
        self.config.allowed_contacts.iter().any(|pattern| {
            if let Some(suffix) = pattern.strip_prefix('*') {
                recipient.ends_with(suffix)
            } else {
                pattern == recipient
            }
        })
    }

    /// Check volume anomaly: are we sending too many messages in the window?
    async fn check_volume(&self) -> Result<bool, StewardError> {
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(self.config.volume_window_secs as i64);

        let mut timestamps = self.send_timestamps.lock().await;
        // Prune old entries outside the window.
        timestamps.retain(|ts| *ts >= window_start);
        // Record this send.
        timestamps.push(now);

        Ok(timestamps.len() as u64 > self.config.volume_threshold)
    }

    /// Luhn algorithm to validate a potential credit card number.
    fn luhn_check(digits: &str) -> bool {
        let digits: Vec<u32> = digits
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();

        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }

        let checksum: u32 = digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &d)| {
                if i % 2 == 1 {
                    let doubled = d * 2;
                    if doubled > 9 {
                        doubled - 9
                    } else {
                        doubled
                    }
                } else {
                    d
                }
            })
            .sum();

        checksum.is_multiple_of(10)
    }

    /// Calculate Shannon entropy of content (bits per character).
    fn shannon_entropy(content: &str) -> f64 {
        if content.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        let len = content.len() as f64;
        for byte in content.bytes() {
            freq[byte as usize] += 1;
        }

        freq.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Detect if content looks like a structured data dump.
    fn looks_like_data_dump(content: &str) -> bool {
        // Check for JSON array pattern (can be single-line).
        let trimmed = content.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.contains('{') {
            return true;
        }

        // Heuristics for multi-line structured data.
        let lines: Vec<&str> = content.lines().collect();
        if lines.len() < 5 {
            return false;
        }

        // Check for CSV-like structure: consistent comma/tab counts per line.
        let comma_counts: Vec<usize> = lines.iter().map(|l| l.matches(',').count()).collect();
        if comma_counts.iter().all(|&c| c > 2) && comma_counts.windows(2).all(|w| w[0] == w[1]) {
            return true;
        }

        false
    }

    /// Run PII pattern scans and collect findings.
    fn scan_pii(&self, content: &str) -> Vec<(String, PatternSeverity)> {
        let mut findings = Vec::new();

        for pat in &self.patterns {
            for m in pat.regex.find_iter(content) {
                // Special case: credit card numbers require Luhn validation.
                if pat.name == "credit_card" {
                    if Self::luhn_check(m.as_str()) {
                        findings.push((pat.name.clone(), pat.severity));
                    }
                } else {
                    findings.push((pat.name.clone(), pat.severity));
                }
            }
        }

        findings
    }
}

#[async_trait]
impl EgressFilter for EgressFilterImpl {
    async fn filter(&self, content: &OutboundContent) -> Result<EgressDecision, StewardError> {
        let mut block_reasons: Vec<String> = Vec::new();
        let mut block_patterns: Vec<String> = Vec::new();
        let mut warn_reasons: Vec<String> = Vec::new();

        // --- 1. PII Detection ---
        let pii_findings = self.scan_pii(&content.text);
        for (pattern_name, severity) in &pii_findings {
            match severity {
                PatternSeverity::High | PatternSeverity::Critical => {
                    block_patterns.push(pattern_name.clone());
                    block_reasons
                        .push(format!("detected {severity:?} PII pattern: {pattern_name}"));
                }
                PatternSeverity::Medium => {
                    warn_reasons.push(format!("detected {severity:?} PII pattern: {pattern_name}"));
                }
                PatternSeverity::Low => {
                    // Low-severity: log but don't warn or block.
                }
            }
        }

        // --- 2. Secret Scanning (delegate to LeakDetector) ---
        let leaks = self.leak_detector.scan(&content.text);
        if !leaks.is_empty() {
            for leak in &leaks {
                block_patterns.push(leak.pattern_name.clone());
            }
            block_reasons.push(format!(
                "detected {} secret leak(s): {}",
                leaks.len(),
                leaks
                    .iter()
                    .map(|l| l.pattern_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        // --- 3. Recipient Validation ---
        let is_communication_action =
            content.action_type == "email.send" || content.action_type == "message.send";

        if is_communication_action {
            if let Some(ref recipient) = content.recipient {
                if !self.config.allowed_contacts.is_empty() && !self.is_recipient_allowed(recipient)
                {
                    warn_reasons.push(format!(
                        "unknown recipient '{recipient}' not in contacts allowlist"
                    ));
                }
            }
        }

        // --- 4. Volume Anomaly Detection ---
        if is_communication_action {
            let over_threshold = self.check_volume().await?;
            if over_threshold {
                block_reasons.push(format!(
                    "volume anomaly: exceeded {} messages in {} seconds",
                    self.config.volume_threshold, self.config.volume_window_secs
                ));
                block_patterns.push("volume_anomaly".to_string());
            }
        }

        // --- 5. Content Policy Check ---
        if is_communication_action {
            let entropy = Self::shannon_entropy(&content.text);
            let is_data_dump = Self::looks_like_data_dump(&content.text);

            if entropy > self.config.entropy_threshold && is_data_dump {
                warn_reasons.push(format!(
                    "content looks like a data dump (entropy: {entropy:.2}, structured data detected)"
                ));
            } else if is_data_dump {
                warn_reasons.push(
                    "content has structured data patterns resembling a data dump".to_string(),
                );
            }
        }

        // --- Decision ---
        if !block_reasons.is_empty() {
            let deduped: Vec<String> = block_patterns
                .into_iter()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            warn!(
                action_type = %content.action_type,
                patterns = ?deduped,
                "egress filter BLOCKED outbound content"
            );

            Ok(EgressDecision::Block {
                reason: block_reasons.join("; "),
                patterns_found: deduped,
            })
        } else if !warn_reasons.is_empty() {
            warn!(
                action_type = %content.action_type,
                warnings = ?warn_reasons,
                "egress filter WARNING on outbound content"
            );

            Ok(EgressDecision::Warn {
                reason: warn_reasons.join("; "),
            })
        } else {
            Ok(EgressDecision::Pass)
        }
    }

    fn register_pattern(&mut self, pattern: SensitivePattern) {
        match Regex::new(&pattern.pattern) {
            Ok(regex) => {
                self.patterns.push(CompiledPattern {
                    name: pattern.name,
                    regex,
                    severity: pattern.severity,
                });
            }
            Err(e) => {
                warn!(
                    pattern_name = %pattern.name,
                    error = %e,
                    "failed to compile custom egress pattern"
                );
            }
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use steward_types::actions::LeakDetection;

    // --- Mock LeakDetector ---

    /// A mock leak detector that finds nothing.
    struct NoopLeakDetector;

    impl LeakDetector for NoopLeakDetector {
        fn scan(&self, _content: &str) -> Vec<LeakDetection> {
            vec![]
        }
        fn redact(&self, content: &str) -> String {
            content.to_string()
        }
    }

    /// A mock leak detector that always finds an AWS key.
    struct AlwaysLeakDetector;

    impl LeakDetector for AlwaysLeakDetector {
        fn scan(&self, _content: &str) -> Vec<LeakDetection> {
            vec![LeakDetection {
                pattern_name: "aws_access_key".to_string(),
                offset: 0,
                length: 20,
                confidence: 0.95,
            }]
        }
        fn redact(&self, _content: &str) -> String {
            "[REDACTED:aws_access_key]".to_string()
        }
    }

    fn default_config() -> EgressFilterConfig {
        EgressFilterConfig::default()
    }

    fn make_content(text: &str, action_type: &str) -> OutboundContent {
        OutboundContent {
            text: text.to_string(),
            action_type: action_type.to_string(),
            recipient: None,
            metadata: serde_json::Value::Null,
        }
    }

    fn make_email(text: &str, recipient: &str) -> OutboundContent {
        OutboundContent {
            text: text.to_string(),
            action_type: "email.send".to_string(),
            recipient: Some(recipient.to_string()),
            metadata: serde_json::Value::Null,
        }
    }

    // ============================================================
    // PII Detection Tests
    // ============================================================

    #[tokio::test]
    async fn test_ssn_detected_and_blocked() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let content = make_content("My SSN is 123-45-6789", "file.write");

        let decision = filter.filter(&content).await.unwrap();
        match decision {
            EgressDecision::Block { patterns_found, .. } => {
                assert!(patterns_found.contains(&"ssn".to_string()));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_credit_card_with_luhn_blocked() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        // Visa test number that passes Luhn.
        let content = make_content("Card: 4111111111111111", "file.write");

        let decision = filter.filter(&content).await.unwrap();
        match decision {
            EgressDecision::Block { patterns_found, .. } => {
                assert!(patterns_found.contains(&"credit_card".to_string()));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_credit_card_without_luhn_passes() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        // Random digits that fail Luhn.
        let content = make_content("Number: 1234567890123456", "file.write");

        let decision = filter.filter(&content).await.unwrap();
        // Should not block on credit_card (Luhn fails). May warn on phone_number
        // match in the digits — that's acceptable. Just verify it doesn't Block.
        assert!(
            !matches!(
                &decision,
                EgressDecision::Block { patterns_found, .. }
                    if patterns_found.contains(&"credit_card".to_string())
            ),
            "should not block on invalid credit card number"
        );
    }

    #[tokio::test]
    async fn test_email_address_detected_low_severity() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let content = make_content("Contact me at user@example.com", "file.write");

        let decision = filter.filter(&content).await.unwrap();
        // Low severity = no warn, no block — just pass.
        assert!(
            matches!(decision, EgressDecision::Pass),
            "email (low severity) should pass: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_phone_number_detected_warns() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let content = make_content("Call me at (555) 123-4567", "file.write");

        let decision = filter.filter(&content).await.unwrap();
        assert!(
            matches!(decision, EgressDecision::Warn { .. }),
            "phone number (medium severity) should warn: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_physical_address_detected_warns() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let content = make_content("I live at 123 Main Street", "file.write");

        let decision = filter.filter(&content).await.unwrap();
        assert!(
            matches!(decision, EgressDecision::Warn { .. }),
            "physical address (medium severity) should warn: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_icd_code_detected_blocks() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let content = make_content(
            "Diagnosis: E11.65 (type 2 diabetes with hyperglycemia)",
            "file.write",
        );

        let decision = filter.filter(&content).await.unwrap();
        match decision {
            EgressDecision::Block { patterns_found, .. } => {
                assert!(patterns_found.contains(&"icd_code".to_string()));
            }
            other => panic!("expected Block for ICD code, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_medication_name_detected_blocks() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let content = make_content("Patient is on metformin 500mg twice daily", "file.write");

        let decision = filter.filter(&content).await.unwrap();
        match decision {
            EgressDecision::Block { patterns_found, .. } => {
                assert!(patterns_found.contains(&"medication_name".to_string()));
            }
            other => panic!("expected Block for medication, got {other:?}"),
        }
    }

    // ============================================================
    // False Positive Tests
    // ============================================================

    #[tokio::test]
    async fn test_normal_content_passes() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let content = make_content(
            "Hey, just wanted to check if the meeting is still on for tomorrow at noon.",
            "message.send",
        );

        let decision = filter.filter(&content).await.unwrap();
        // Normal text should pass (volume is 1, well within threshold).
        assert!(
            matches!(decision, EgressDecision::Pass | EgressDecision::Warn { .. }),
            "normal content should pass or at most warn: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_normal_text_no_false_positives() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let content = make_content(
            "The quarterly report looks great. Revenue is up and customer satisfaction scores improved.",
            "file.write",
        );

        let decision = filter.filter(&content).await.unwrap();
        assert!(
            matches!(decision, EgressDecision::Pass),
            "normal business text should pass: {decision:?}"
        );
    }

    // ============================================================
    // Secret Scanning Tests (LeakDetector delegation)
    // ============================================================

    #[tokio::test]
    async fn test_secret_leak_blocks() {
        let filter = EgressFilterImpl::new(Arc::new(AlwaysLeakDetector), default_config()).unwrap();
        let content = make_content("AKIAIOSFODNN7EXAMPLE", "file.write");

        let decision = filter.filter(&content).await.unwrap();
        match decision {
            EgressDecision::Block { patterns_found, .. } => {
                assert!(patterns_found.contains(&"aws_access_key".to_string()));
            }
            other => panic!("expected Block for secret leak, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_secret_leak_passes() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let content = make_content("Just some normal text", "file.write");

        let decision = filter.filter(&content).await.unwrap();
        assert!(matches!(decision, EgressDecision::Pass));
    }

    // ============================================================
    // Recipient Validation Tests
    // ============================================================

    #[tokio::test]
    async fn test_allowed_recipient_passes() {
        let config = EgressFilterConfig {
            allowed_contacts: vec!["alice@example.com".to_string(), "*@trusted.org".to_string()],
            ..default_config()
        };
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), config).unwrap();

        let content = make_email("Hello Alice", "alice@example.com");
        let decision = filter.filter(&content).await.unwrap();
        assert!(
            matches!(decision, EgressDecision::Pass),
            "allowed recipient should pass: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_wildcard_recipient_passes() {
        let config = EgressFilterConfig {
            allowed_contacts: vec!["*@trusted.org".to_string()],
            ..default_config()
        };
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), config).unwrap();

        let content = make_email("Hello Bob", "bob@trusted.org");
        let decision = filter.filter(&content).await.unwrap();
        assert!(
            matches!(decision, EgressDecision::Pass),
            "wildcard recipient should pass: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_unknown_recipient_warns() {
        let config = EgressFilterConfig {
            allowed_contacts: vec!["alice@example.com".to_string()],
            ..default_config()
        };
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), config).unwrap();

        let content = make_email("Hello stranger", "stranger@unknown.com");
        let decision = filter.filter(&content).await.unwrap();
        match decision {
            EgressDecision::Warn { reason } => {
                assert!(
                    reason.contains("unknown recipient"),
                    "warning should mention unknown recipient: {reason}"
                );
            }
            other => panic!("expected Warn for unknown recipient, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_empty_allowlist_skips_validation() {
        let config = EgressFilterConfig {
            allowed_contacts: vec![],
            ..default_config()
        };
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), config).unwrap();

        let content = make_email("Hello anyone", "anyone@anywhere.com");
        let decision = filter.filter(&content).await.unwrap();
        assert!(
            matches!(decision, EgressDecision::Pass),
            "empty allowlist should skip validation: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_non_communication_action_skips_recipient_check() {
        let config = EgressFilterConfig {
            allowed_contacts: vec!["alice@example.com".to_string()],
            ..default_config()
        };
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), config).unwrap();

        let content = OutboundContent {
            text: "Some data".to_string(),
            action_type: "file.write".to_string(),
            recipient: Some("stranger@unknown.com".to_string()),
            metadata: serde_json::Value::Null,
        };
        let decision = filter.filter(&content).await.unwrap();
        assert!(
            matches!(decision, EgressDecision::Pass),
            "file.write should skip recipient validation: {decision:?}"
        );
    }

    // ============================================================
    // Volume Anomaly Detection Tests
    // ============================================================

    #[tokio::test]
    async fn test_volume_anomaly_blocks() {
        let config = EgressFilterConfig {
            volume_threshold: 3,
            volume_window_secs: 60,
            ..default_config()
        };
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), config).unwrap();

        // Send 3 messages — should be at threshold, then the 4th triggers block.
        for _ in 0..3 {
            let content = make_content("hello", "email.send");
            let decision = filter.filter(&content).await.unwrap();
            assert!(
                matches!(decision, EgressDecision::Pass),
                "should pass within threshold"
            );
        }

        let content = make_content("one more", "email.send");
        let decision = filter.filter(&content).await.unwrap();
        match decision {
            EgressDecision::Block {
                patterns_found,
                reason,
            } => {
                assert!(patterns_found.contains(&"volume_anomaly".to_string()));
                assert!(reason.contains("volume anomaly"));
            }
            other => panic!("expected Block for volume anomaly, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_volume_not_tracked_for_non_communication() {
        let config = EgressFilterConfig {
            volume_threshold: 1,
            volume_window_secs: 60,
            ..default_config()
        };
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), config).unwrap();

        // file.write shouldn't count toward volume.
        for _ in 0..5 {
            let content = make_content("data", "file.write");
            let decision = filter.filter(&content).await.unwrap();
            assert!(
                matches!(decision, EgressDecision::Pass),
                "file.write should not trigger volume anomaly"
            );
        }
    }

    // ============================================================
    // Content Policy / Data Dump Heuristic Tests
    // ============================================================

    #[tokio::test]
    async fn test_csv_data_dump_warns() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let csv = "name,email,phone,address,city\n\
                   Alice,a@b.com,555-1234,123 St,NY\n\
                   Bob,b@c.com,555-5678,456 Ave,LA\n\
                   Carol,c@d.com,555-9012,789 Rd,SF\n\
                   Dave,d@e.com,555-3456,101 Dr,CH\n\
                   Eve,e@f.com,555-7890,202 Ln,SE";
        let content = make_content(csv, "email.send");

        let decision = filter.filter(&content).await.unwrap();
        // May be Block or Warn depending on what PII is found in the CSV.
        // The key point is that it's NOT Pass.
        assert!(
            !matches!(decision, EgressDecision::Pass),
            "CSV data dump in email should not pass: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_json_data_dump_warns() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let json =
            r#"[{"name": "x", "val": "a"}, {"name": "y", "val": "b"}, {"name": "z", "val": "c"}]"#;
        let content = make_content(json, "email.send");

        let decision = filter.filter(&content).await.unwrap();
        // JSON array looks like a data dump — should at least warn.
        assert!(
            matches!(
                decision,
                EgressDecision::Warn { .. } | EgressDecision::Block { .. }
            ),
            "JSON data dump in email should warn or block: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_normal_email_content_passes() {
        let filter = EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();
        let content = make_content(
            "Hi team,\n\nJust a reminder about tomorrow's standup at 10am.\n\nBest,\nBot",
            "email.send",
        );

        let decision = filter.filter(&content).await.unwrap();
        assert!(
            matches!(decision, EgressDecision::Pass),
            "normal email should pass: {decision:?}"
        );
    }

    // ============================================================
    // EgressDecision Serialization Tests
    // ============================================================

    #[tokio::test]
    async fn test_egress_decision_pass_serializes() {
        let decision = EgressDecision::Pass;
        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: EgressDecision = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, EgressDecision::Pass));
    }

    #[tokio::test]
    async fn test_egress_decision_block_serializes() {
        let decision = EgressDecision::Block {
            reason: "found SSN".to_string(),
            patterns_found: vec!["ssn".to_string()],
        };
        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: EgressDecision = serde_json::from_str(&json).unwrap();
        match deserialized {
            EgressDecision::Block {
                reason,
                patterns_found,
            } => {
                assert_eq!(reason, "found SSN");
                assert_eq!(patterns_found, vec!["ssn"]);
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_egress_decision_warn_serializes() {
        let decision = EgressDecision::Warn {
            reason: "unknown recipient".to_string(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: EgressDecision = serde_json::from_str(&json).unwrap();
        match deserialized {
            EgressDecision::Warn { reason } => {
                assert_eq!(reason, "unknown recipient");
            }
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    // ============================================================
    // register_pattern Tests
    // ============================================================

    #[tokio::test]
    async fn test_register_custom_pattern() {
        let mut filter =
            EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();

        filter.register_pattern(SensitivePattern {
            name: "custom_id".to_string(),
            pattern: r"\bCUST-\d{6}\b".to_string(),
            severity: PatternSeverity::High,
        });

        let content = make_content("Customer ID: CUST-123456", "file.write");
        let decision = filter.filter(&content).await.unwrap();
        match decision {
            EgressDecision::Block { patterns_found, .. } => {
                assert!(patterns_found.contains(&"custom_id".to_string()));
            }
            other => panic!("expected Block for custom pattern, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_register_invalid_pattern_does_not_crash() {
        let mut filter =
            EgressFilterImpl::new(Arc::new(NoopLeakDetector), default_config()).unwrap();

        // Invalid regex — should be silently ignored (logged via tracing).
        filter.register_pattern(SensitivePattern {
            name: "bad_pattern".to_string(),
            pattern: r"[invalid".to_string(),
            severity: PatternSeverity::High,
        });

        // Should still work fine.
        let content = make_content("normal text", "file.write");
        let decision = filter.filter(&content).await.unwrap();
        assert!(matches!(decision, EgressDecision::Pass));
    }

    // ============================================================
    // Luhn Algorithm Unit Tests
    // ============================================================

    #[test]
    fn test_luhn_valid_visa() {
        assert!(EgressFilterImpl::luhn_check("4111111111111111"));
    }

    #[test]
    fn test_luhn_valid_mastercard() {
        assert!(EgressFilterImpl::luhn_check("5500000000000004"));
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!EgressFilterImpl::luhn_check("1234567890123456"));
    }

    #[test]
    fn test_luhn_with_spaces() {
        assert!(EgressFilterImpl::luhn_check("4111 1111 1111 1111"));
    }

    #[test]
    fn test_luhn_too_short() {
        assert!(!EgressFilterImpl::luhn_check("1234"));
    }

    // ============================================================
    // Shannon Entropy Unit Tests
    // ============================================================

    #[test]
    fn test_entropy_empty() {
        assert_eq!(EgressFilterImpl::shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_low_for_repetitive() {
        let entropy = EgressFilterImpl::shannon_entropy("aaaaaaaaaa");
        assert!(
            entropy < 1.0,
            "repetitive text should have low entropy: {entropy}"
        );
    }

    #[test]
    fn test_entropy_higher_for_varied() {
        let low = EgressFilterImpl::shannon_entropy("aaaaaaaaaa");
        let high = EgressFilterImpl::shannon_entropy("abcdefghij");
        assert!(
            high > low,
            "varied text should have higher entropy: {high} vs {low}"
        );
    }

    // ============================================================
    // Combined Scenario Tests
    // ============================================================

    #[tokio::test]
    async fn test_multiple_findings_all_reported() {
        let filter = EgressFilterImpl::new(Arc::new(AlwaysLeakDetector), default_config()).unwrap();
        // Content with SSN + secret (from AlwaysLeakDetector).
        let content = make_content("SSN: 123-45-6789 and a secret", "file.write");

        let decision = filter.filter(&content).await.unwrap();
        match decision {
            EgressDecision::Block {
                patterns_found,
                reason,
            } => {
                assert!(patterns_found.contains(&"ssn".to_string()));
                assert!(patterns_found.contains(&"aws_access_key".to_string()));
                assert!(reason.contains("PII") || reason.contains("ssn"));
                assert!(reason.contains("secret leak"));
            }
            other => panic!("expected Block with multiple patterns, got {other:?}"),
        }
    }
}
