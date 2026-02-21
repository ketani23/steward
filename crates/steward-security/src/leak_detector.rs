//! Leak detector implementation.
//!
//! Scans I/O for credential patterns in both directions:
//! - API keys (AWS, GCP, GitHub, Anthropic, OpenAI)
//! - OAuth tokens and JWTs
//! - Private keys (RSA, EC, Ed25519)
//! - Passwords in URLs
//! - Credit card numbers (with Luhn check)
//! - SSNs and common secret formats
//!
//! See `docs/architecture.md` sections 5.2 and 5.5 for context.

use regex::Regex;
use steward_types::actions::LeakDetection;
use steward_types::traits::LeakDetector;
use tracing::debug;

/// A credential pattern definition with its compiled regex.
struct CredentialPattern {
    /// Human-readable name for this pattern (e.g., "aws_access_key").
    name: &'static str,
    /// Compiled regex for matching.
    regex: Regex,
    /// Base confidence score for matches (0.0 to 1.0).
    confidence: f64,
    /// Optional post-match validator for reducing false positives.
    validator: Option<fn(&str) -> bool>,
}

/// Pattern-based leak detector that scans content for credential patterns.
///
/// Compiles all regex patterns once at construction time for performance.
/// This detector is designed to run on every I/O crossing a security boundary,
/// so pattern compilation is amortized across all scans.
pub struct PatternLeakDetector {
    patterns: Vec<CredentialPattern>,
}

impl PatternLeakDetector {
    /// Create a new `PatternLeakDetector` with all built-in credential patterns.
    ///
    /// Patterns are compiled once here and reused for every scan.
    pub fn new() -> Self {
        let patterns = vec![
            // AWS access keys: AKIA followed by 16 uppercase alphanumeric characters
            CredentialPattern {
                name: "aws_access_key",
                regex: compile_regex(r"AKIA[0-9A-Z]{16}"),
                confidence: 0.95,
                validator: None,
            },
            // AWS secret keys: 40-character base64 string after known prefixes
            CredentialPattern {
                name: "aws_secret_key",
                regex: compile_regex(
                    r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)\s*[=:]\s*[A-Za-z0-9/+=]{40}",
                ),
                confidence: 0.90,
                validator: None,
            },
            // GCP API keys: AIza followed by 35 alphanumeric/dash/underscore characters
            CredentialPattern {
                name: "gcp_api_key",
                regex: compile_regex(r"AIza[0-9A-Za-z_\-]{35}"),
                confidence: 0.95,
                validator: None,
            },
            // GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_ followed by 36 alphanumeric characters
            CredentialPattern {
                name: "github_token",
                regex: compile_regex(r"gh[pousr]_[0-9a-zA-Z]{36}"),
                confidence: 0.95,
                validator: None,
            },
            // Anthropic API keys: sk-ant- followed by 80+ alphanumeric/dash characters
            CredentialPattern {
                name: "anthropic_api_key",
                regex: compile_regex(r"sk-ant-[0-9a-zA-Z\-]{80,}"),
                confidence: 0.95,
                validator: None,
            },
            // OpenAI API keys: sk- followed by 40+ alphanumeric characters
            // Validator rejects sk-ant- prefix to avoid matching Anthropic keys
            CredentialPattern {
                name: "openai_api_key",
                regex: compile_regex(r"sk-[0-9a-zA-Z]{40,}"),
                confidence: 0.90,
                validator: Some(|s: &str| !s.starts_with("sk-ant-")),
            },
            // Generic OAuth bearer tokens (case-insensitive prefix)
            CredentialPattern {
                name: "bearer_token",
                regex: compile_regex(r"(?i)bearer\s+[a-zA-Z0-9_\-]+"),
                confidence: 0.80,
                validator: None,
            },
            // JWTs: three base64url-encoded segments separated by dots, starting with eyJ
            CredentialPattern {
                name: "jwt",
                regex: compile_regex(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
                confidence: 0.90,
                validator: None,
            },
            // RSA/EC/Ed25519 private keys
            CredentialPattern {
                name: "private_key",
                regex: compile_regex(r"-----BEGIN[A-Z \n]*PRIVATE KEY-----"),
                confidence: 0.99,
                validator: None,
            },
            // Passwords in URLs: ://user:password@host
            CredentialPattern {
                name: "password_in_url",
                regex: compile_regex(r"://[^:/@\s]+:[^@/\s]+@"),
                confidence: 0.85,
                validator: None,
            },
            // Credit card numbers: 13-19 digit sequences (optionally separated by spaces/dashes)
            CredentialPattern {
                name: "credit_card",
                regex: compile_regex(r"\b(?:\d[ \-]?){12,18}\d\b"),
                confidence: 0.70,
                validator: Some(luhn_check),
            },
            // US Social Security Numbers: XXX-XX-XXXX
            CredentialPattern {
                name: "ssn",
                regex: compile_regex(r"\b\d{3}-\d{2}-\d{4}\b"),
                confidence: 0.85,
                validator: Some(ssn_validate),
            },
        ];

        Self { patterns }
    }
}

impl Default for PatternLeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LeakDetector for PatternLeakDetector {
    fn scan(&self, content: &str) -> Vec<LeakDetection> {
        let mut detections = Vec::new();

        for pattern in &self.patterns {
            for mat in pattern.regex.find_iter(content) {
                let matched_text = mat.as_str();

                // Run the optional post-match validator
                if let Some(validator) = pattern.validator {
                    if !validator(matched_text) {
                        continue;
                    }
                }

                debug!(
                    pattern = pattern.name,
                    offset = mat.start(),
                    length = mat.len(),
                    "leak detected"
                );

                detections.push(LeakDetection {
                    pattern_name: pattern.name.to_string(),
                    offset: mat.start(),
                    length: mat.len(),
                    confidence: pattern.confidence,
                });
            }
        }

        // Sort by offset for deterministic output
        detections.sort_by_key(|d| d.offset);
        detections
    }

    fn redact(&self, content: &str) -> String {
        let detections = self.scan(content);
        if detections.is_empty() {
            return content.to_string();
        }

        let mut result = String::with_capacity(content.len());
        let mut last_end = 0;

        for detection in &detections {
            // Skip overlapping detections (already covered by a previous one)
            if detection.offset < last_end {
                continue;
            }

            // Append the non-secret content before this detection
            result.push_str(&content[last_end..detection.offset]);

            // Replace the secret with a redaction marker
            result.push_str(&format!("[REDACTED:{}]", detection.pattern_name));

            last_end = detection.offset + detection.length;
        }

        // Append any remaining content after the last detection
        result.push_str(&content[last_end..]);

        result
    }
}

/// Compile a regex pattern, panicking on invalid patterns.
///
/// This is only called during `PatternLeakDetector::new()`, so a panic here
/// indicates a bug in the pattern definitions (a programming error, not a runtime failure).
fn compile_regex(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("invalid leak detector regex '{pattern}': {e}"))
}

/// Validate a credit card number using the Luhn algorithm.
///
/// Strips spaces and dashes before validation. Returns `true` if the
/// digit sequence passes the Luhn check and has between 13 and 19 digits.
fn luhn_check(input: &str) -> bool {
    let digits: Vec<u32> = input
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum: u32 = 0;
    let len = digits.len();
    for (i, &digit) in digits.iter().rev().enumerate() {
        if i % 2 == 1 {
            let doubled = digit * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += digit;
        }
    }

    // Avoid false positives on trivially simple sequences
    if len >= 13 && digits.iter().all(|&d| d == digits[0]) {
        return false;
    }

    sum.is_multiple_of(10)
}

/// Validate an SSN to reduce false positives.
///
/// Rejects SSNs with area number 000, 666, or 900-999 (invalid per SSA rules),
/// and rejects group number 00 or serial number 0000.
fn ssn_validate(input: &str) -> bool {
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() != 3 {
        return false;
    }

    let area: u32 = match parts[0].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let group: u32 = match parts[1].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let serial: u32 = match parts[2].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };

    // SSA rules: area cannot be 000, 666, or 900-999
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    if group == 0 {
        return false;
    }
    if serial == 0 {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> PatternLeakDetector {
        PatternLeakDetector::new()
    }

    // ==========================================
    // AWS access key tests
    // ==========================================

    #[test]
    fn test_aws_access_key() {
        let d = detector();
        let content = "my key is AKIAIOSFODNN7EXAMPLE";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "aws_access_key");
        assert_eq!(detections[0].length, 20);
    }

    #[test]
    fn test_aws_secret_key() {
        let d = detector();
        let content = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "aws_secret_key");
    }

    // ==========================================
    // GCP API key tests
    // ==========================================

    #[test]
    fn test_gcp_api_key() {
        let d = detector();
        let content = "key=AIzaSyD-9tSrke72PouQMnMX-a7eFblGlIkFm30";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "gcp_api_key");
    }

    // ==========================================
    // GitHub token tests
    // ==========================================

    #[test]
    fn test_github_personal_access_token() {
        let d = detector();
        let content = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "github_token");
    }

    #[test]
    fn test_github_oauth_token() {
        let d = detector();
        let content = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "github_token");
    }

    #[test]
    fn test_github_user_token() {
        let d = detector();
        let content = "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "github_token");
    }

    #[test]
    fn test_github_server_token() {
        let d = detector();
        let content = "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "github_token");
    }

    #[test]
    fn test_github_refresh_token() {
        let d = detector();
        let content = "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "github_token");
    }

    // ==========================================
    // Anthropic API key tests
    // ==========================================

    #[test]
    fn test_anthropic_api_key() {
        let d = detector();
        // 93-character key body (>= 80)
        let key = format!("sk-ant-{}", "a".repeat(93));
        let content = format!("ANTHROPIC_API_KEY={key}");
        let detections = d.scan(&content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "anthropic_api_key");
    }

    // ==========================================
    // OpenAI API key tests
    // ==========================================

    #[test]
    fn test_openai_api_key() {
        let d = detector();
        let key = format!("sk-{}", "A1b2C3d4E5f6G7h8I9j0".repeat(3));
        let content = format!("OPENAI_API_KEY={key}");
        let detections = d.scan(&content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "openai_api_key");
    }

    #[test]
    fn test_openai_does_not_match_anthropic() {
        let d = detector();
        let key = format!("sk-ant-{}", "a".repeat(93));
        let detections = d.scan(&key);
        // Should match anthropic, not openai
        assert!(detections
            .iter()
            .all(|d| d.pattern_name != "openai_api_key"));
        assert!(detections
            .iter()
            .any(|d| d.pattern_name == "anthropic_api_key"));
    }

    // ==========================================
    // Bearer token tests
    // ==========================================

    #[test]
    fn test_bearer_token() {
        let d = detector();
        let content = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9";
        let detections = d.scan(content);
        // Should match bearer_token (and possibly jwt depending on the full content)
        assert!(detections.iter().any(|d| d.pattern_name == "bearer_token"));
    }

    #[test]
    fn test_bearer_token_case_insensitive() {
        let d = detector();
        let content = "BEARER abc123_token-value";
        let detections = d.scan(content);
        assert!(detections.iter().any(|d| d.pattern_name == "bearer_token"));
    }

    // ==========================================
    // JWT tests
    // ==========================================

    #[test]
    fn test_jwt() {
        let d = detector();
        let content = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let detections = d.scan(content);
        assert!(detections.iter().any(|d| d.pattern_name == "jwt"));
    }

    // ==========================================
    // Private key tests
    // ==========================================

    #[test]
    fn test_rsa_private_key() {
        let d = detector();
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "private_key");
    }

    #[test]
    fn test_ec_private_key() {
        let d = detector();
        let content = "-----BEGIN EC PRIVATE KEY-----";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "private_key");
    }

    #[test]
    fn test_ed25519_private_key() {
        let d = detector();
        let content = "-----BEGIN PRIVATE KEY-----";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "private_key");
    }

    // ==========================================
    // Password in URL tests
    // ==========================================

    #[test]
    fn test_password_in_url() {
        let d = detector();
        let content = "postgres://admin:s3cret@db.example.com:5432/mydb";
        let detections = d.scan(content);
        assert!(detections
            .iter()
            .any(|d| d.pattern_name == "password_in_url"));
    }

    #[test]
    fn test_no_false_positive_on_url_without_password() {
        let d = detector();
        let content = "https://example.com/path?key=value";
        let detections = d.scan(content);
        assert!(detections
            .iter()
            .all(|d| d.pattern_name != "password_in_url"));
    }

    // ==========================================
    // Credit card tests
    // ==========================================

    #[test]
    fn test_valid_visa_card() {
        let d = detector();
        // 4111111111111111 is a well-known test Visa number that passes Luhn
        let content = "card: 4111111111111111";
        let detections = d.scan(content);
        assert!(detections.iter().any(|d| d.pattern_name == "credit_card"));
    }

    #[test]
    fn test_valid_card_with_spaces() {
        let d = detector();
        let content = "card: 4111 1111 1111 1111";
        let detections = d.scan(content);
        assert!(detections.iter().any(|d| d.pattern_name == "credit_card"));
    }

    #[test]
    fn test_valid_card_with_dashes() {
        let d = detector();
        let content = "card: 4111-1111-1111-1111";
        let detections = d.scan(content);
        assert!(detections.iter().any(|d| d.pattern_name == "credit_card"));
    }

    #[test]
    fn test_invalid_card_fails_luhn() {
        let d = detector();
        // This number does not pass the Luhn check
        let content = "card: 4111111111111112";
        let detections = d.scan(content);
        assert!(detections.iter().all(|d| d.pattern_name != "credit_card"));
    }

    #[test]
    fn test_luhn_check_valid() {
        assert!(luhn_check("4111111111111111"));
        assert!(luhn_check("5500000000000004")); // Mastercard test
        assert!(luhn_check("340000000000009")); // Amex test (15 digits)
    }

    #[test]
    fn test_luhn_check_invalid() {
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234567890")); // too short
        assert!(!luhn_check("12345678901234567890")); // too long
    }

    #[test]
    fn test_luhn_rejects_uniform_sequences() {
        // All same digits (e.g., 0000000000000) are rejected even if Luhn passes
        assert!(!luhn_check("0000000000000"));
    }

    // ==========================================
    // SSN tests
    // ==========================================

    #[test]
    fn test_valid_ssn() {
        let d = detector();
        let content = "SSN: 123-45-6789";
        let detections = d.scan(content);
        assert!(detections.iter().any(|d| d.pattern_name == "ssn"));
    }

    #[test]
    fn test_invalid_ssn_area_000() {
        let d = detector();
        let content = "000-12-3456";
        let detections = d.scan(content);
        assert!(detections.iter().all(|d| d.pattern_name != "ssn"));
    }

    #[test]
    fn test_invalid_ssn_area_666() {
        let d = detector();
        let content = "666-12-3456";
        let detections = d.scan(content);
        assert!(detections.iter().all(|d| d.pattern_name != "ssn"));
    }

    #[test]
    fn test_invalid_ssn_area_900_plus() {
        let d = detector();
        let content = "901-12-3456";
        let detections = d.scan(content);
        assert!(detections.iter().all(|d| d.pattern_name != "ssn"));
    }

    #[test]
    fn test_invalid_ssn_group_00() {
        let d = detector();
        let content = "123-00-6789";
        let detections = d.scan(content);
        assert!(detections.iter().all(|d| d.pattern_name != "ssn"));
    }

    #[test]
    fn test_invalid_ssn_serial_0000() {
        let d = detector();
        let content = "123-45-0000";
        let detections = d.scan(content);
        assert!(detections.iter().all(|d| d.pattern_name != "ssn"));
    }

    // ==========================================
    // False positive tests
    // ==========================================

    #[test]
    fn test_uuid_no_false_positive() {
        let d = detector();
        let content = "id: 550e8400-e29b-41d4-a716-446655440000";
        let detections = d.scan(content);
        // UUIDs should not match any credential pattern
        assert!(
            detections.is_empty(),
            "UUID triggered false positive: {detections:?}"
        );
    }

    #[test]
    fn test_hex_string_no_false_positive() {
        let d = detector();
        let content = "hash: abcdef1234567890abcdef1234567890";
        let detections = d.scan(content);
        assert!(
            detections.is_empty(),
            "hex string triggered false positive: {detections:?}"
        );
    }

    #[test]
    fn test_base64_data_no_false_positive() {
        let d = detector();
        let content = "data: SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0";
        let detections = d.scan(content);
        assert!(
            detections.is_empty(),
            "base64 data triggered false positive: {detections:?}"
        );
    }

    #[test]
    fn test_normal_url_no_false_positive() {
        let d = detector();
        let content = "Visit https://www.example.com/path/to/page?q=hello";
        let detections = d.scan(content);
        assert!(
            detections.is_empty(),
            "normal URL triggered false positive: {detections:?}"
        );
    }

    // ==========================================
    // Redaction tests
    // ==========================================

    #[test]
    fn test_redaction_preserves_non_secret_content() {
        let d = detector();
        let content = "Hello world, my key is AKIAIOSFODNN7EXAMPLE and that's it.";
        let redacted = d.redact(content);
        assert!(redacted.contains("Hello world, my key is "));
        assert!(redacted.contains("[REDACTED:aws_access_key]"));
        assert!(redacted.contains(" and that's it."));
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_redaction_multiple_secrets() {
        let d = detector();
        let content = "AWS key: AKIAIOSFODNN7EXAMPLE and SSN: 123-45-6789";
        let redacted = d.redact(content);
        assert!(redacted.contains("[REDACTED:aws_access_key]"));
        assert!(redacted.contains("[REDACTED:ssn]"));
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!redacted.contains("123-45-6789"));
    }

    #[test]
    fn test_redaction_no_secrets() {
        let d = detector();
        let content = "This is perfectly safe content with no secrets.";
        let redacted = d.redact(content);
        assert_eq!(redacted, content);
    }

    // ==========================================
    // Edge case tests
    // ==========================================

    #[test]
    fn test_empty_input() {
        let d = detector();
        assert!(d.scan("").is_empty());
        assert_eq!(d.redact(""), "");
    }

    #[test]
    fn test_very_long_input() {
        let d = detector();
        // 1MB of safe content with a secret buried in the middle
        let padding = "a".repeat(500_000);
        let content = format!("{padding}AKIAIOSFODNN7EXAMPLE{padding}");
        let detections = d.scan(&content);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].pattern_name, "aws_access_key");
        assert_eq!(detections[0].offset, 500_000);
    }

    #[test]
    fn test_multiple_patterns_in_content() {
        let d = detector();
        let content = concat!(
            "AWS: AKIAIOSFODNN7EXAMPLE\n",
            "GCP: AIzaSyD-9tSrke72PouQMnMX-a7eFblGlIkFm30\n",
            "GitHub: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234\n",
            "SSN: 123-45-6789\n",
            "URL: postgres://user:pass@host/db\n",
            "Key: -----BEGIN RSA PRIVATE KEY-----\n",
        );
        let detections = d.scan(content);

        let names: Vec<&str> = detections.iter().map(|d| d.pattern_name.as_str()).collect();
        assert!(names.contains(&"aws_access_key"));
        assert!(names.contains(&"gcp_api_key"));
        assert!(names.contains(&"github_token"));
        assert!(names.contains(&"ssn"));
        assert!(names.contains(&"password_in_url"));
        assert!(names.contains(&"private_key"));
    }

    #[test]
    fn test_detections_sorted_by_offset() {
        let d = detector();
        let content = "SSN: 123-45-6789 and key: AKIAIOSFODNN7EXAMPLE";
        let detections = d.scan(content);
        assert!(detections.len() >= 2);
        for window in detections.windows(2) {
            assert!(window[0].offset <= window[1].offset);
        }
    }

    #[test]
    fn test_detection_fields_populated() {
        let d = detector();
        let content = "key: AKIAIOSFODNN7EXAMPLE";
        let detections = d.scan(content);
        assert_eq!(detections.len(), 1);
        let det = &detections[0];
        assert_eq!(det.pattern_name, "aws_access_key");
        assert_eq!(det.offset, 5); // "key: " is 5 bytes
        assert_eq!(det.length, 20); // AKIA + 16 chars
        assert!(det.confidence > 0.0 && det.confidence <= 1.0);
    }
}
