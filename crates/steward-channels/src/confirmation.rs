//! Human-in-the-loop approval UX.
//!
//! Manages the approval flow for high-risk actions:
//! - Formats action details for human review
//! - Sends approval request through the originating channel
//! - Waits for user response with configurable timeout
//! - Returns structured approval/rejection decision
//!
//! See `docs/architecture.md` section 10 for confirmation requirements.

use steward_types::actions::{ApprovalRequest, GuardianDecision, PermissionTier};

/// Format an [`ApprovalRequest`] into a human-readable message for the approval UX.
///
/// The message includes:
/// - The tool/action being proposed
/// - The agent's reasoning
/// - Guardian verdict summary
/// - Permission tier context
pub fn format_approval_message(request: &ApprovalRequest) -> String {
    let proposal = &request.proposal;
    let verdict = &request.guardian_verdict;

    let guardian_status = match verdict.decision {
        GuardianDecision::Allow => "ALLOW",
        GuardianDecision::Block => "BLOCK",
        GuardianDecision::EscalateToHuman => "NEEDS REVIEW",
    };

    let tier_label = match request.permission_tier {
        PermissionTier::AutoExecute => "Auto-execute",
        PermissionTier::LogAndExecute => "Log & Execute",
        PermissionTier::HumanApproval => "Requires Approval",
        PermissionTier::Forbidden => "Forbidden",
    };

    let params_summary = summarize_params(&proposal.parameters);

    format!(
        "ACTION APPROVAL REQUEST\n\
         \n\
         Tool: {tool}\n\
         {params}\
         Reasoning: {reasoning}\n\
         \n\
         Guardian: {guardian} ({confidence:.0}%)\n\
         Tier: {tier}\n\
         \n\
         Approve or Reject?",
        tool = proposal.tool_name,
        params = params_summary,
        reasoning = proposal.reasoning,
        guardian = guardian_status,
        confidence = verdict.confidence * 100.0,
        tier = tier_label,
    )
}

/// Produce a concise summary of action parameters for display.
///
/// Omits overly long values and sensitive-looking fields.
fn summarize_params(params: &serde_json::Value) -> String {
    match params {
        serde_json::Value::Object(map) if !map.is_empty() => {
            let lines: Vec<String> = map
                .iter()
                .filter(|(key, _)| {
                    // Skip internal/sensitive-looking keys
                    !key.starts_with('_')
                        && !key.contains("secret")
                        && !key.contains("token")
                        && !key.contains("password")
                })
                .map(|(key, value)| {
                    let display = match value {
                        serde_json::Value::String(s) if s.len() > 100 => {
                            format!("{}...", &s[..100])
                        }
                        serde_json::Value::String(s) => s.clone(),
                        other => {
                            let s = other.to_string();
                            if s.len() > 100 {
                                format!("{}...", &s[..100])
                            } else {
                                s
                            }
                        }
                    };
                    format!("  {key}: {display}\n")
                })
                .collect();
            if lines.is_empty() {
                String::new()
            } else {
                format!("Parameters:\n{}", lines.join(""))
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use steward_types::actions::*;
    use uuid::Uuid;

    fn sample_request(
        tool: &str,
        params: serde_json::Value,
        decision: GuardianDecision,
        tier: PermissionTier,
    ) -> ApprovalRequest {
        ApprovalRequest {
            proposal: ActionProposal {
                id: Uuid::new_v4(),
                tool_name: tool.to_string(),
                parameters: params,
                reasoning: "User requested this action".to_string(),
                user_message_id: Uuid::new_v4(),
                timestamp: Utc::now(),
            },
            guardian_verdict: GuardianVerdict {
                decision,
                reasoning: "Looks safe".to_string(),
                confidence: 0.95,
                injection_indicators: vec![],
                timestamp: Utc::now(),
            },
            permission_tier: tier,
            channel: ChannelType::WhatsApp,
            timeout_secs: 300,
        }
    }

    #[test]
    fn test_format_approval_text_message() {
        let request = sample_request(
            "email.send",
            serde_json::json!({"to": "alice@example.com", "subject": "Hello"}),
            GuardianDecision::EscalateToHuman,
            PermissionTier::HumanApproval,
        );

        let msg = format_approval_message(&request);
        assert!(msg.contains("email.send"));
        assert!(msg.contains("alice@example.com"));
        assert!(msg.contains("Hello"));
        assert!(msg.contains("NEEDS REVIEW"));
        assert!(msg.contains("Requires Approval"));
        assert!(msg.contains("Approve or Reject?"));
    }

    #[test]
    fn test_format_filters_sensitive_params() {
        let request = sample_request(
            "api.call",
            serde_json::json!({
                "url": "https://example.com",
                "secret_key": "should_be_hidden",
                "_internal": "should_be_hidden",
                "token_value": "should_be_hidden"
            }),
            GuardianDecision::Allow,
            PermissionTier::LogAndExecute,
        );

        let msg = format_approval_message(&request);
        assert!(msg.contains("https://example.com"));
        assert!(!msg.contains("should_be_hidden"));
    }

    #[test]
    fn test_format_truncates_long_params() {
        let long_value = "x".repeat(200);
        let request = sample_request(
            "file.write",
            serde_json::json!({"content": long_value}),
            GuardianDecision::Allow,
            PermissionTier::HumanApproval,
        );

        let msg = format_approval_message(&request);
        assert!(msg.contains("xxx..."));
        assert!(!msg.contains(&long_value));
    }

    #[test]
    fn test_format_empty_params() {
        let request = sample_request(
            "system.status",
            serde_json::json!({}),
            GuardianDecision::Allow,
            PermissionTier::AutoExecute,
        );

        let msg = format_approval_message(&request);
        assert!(msg.contains("system.status"));
        assert!(!msg.contains("Parameters:"));
    }

    #[test]
    fn test_format_guardian_decisions() {
        let allow = sample_request(
            "test",
            serde_json::json!({}),
            GuardianDecision::Allow,
            PermissionTier::AutoExecute,
        );
        assert!(format_approval_message(&allow).contains("ALLOW"));

        let block = sample_request(
            "test",
            serde_json::json!({}),
            GuardianDecision::Block,
            PermissionTier::Forbidden,
        );
        assert!(format_approval_message(&block).contains("BLOCK"));

        let escalate = sample_request(
            "test",
            serde_json::json!({}),
            GuardianDecision::EscalateToHuman,
            PermissionTier::HumanApproval,
        );
        assert!(format_approval_message(&escalate).contains("NEEDS REVIEW"));
    }

    #[test]
    fn test_format_permission_tiers() {
        let tiers = [
            (PermissionTier::AutoExecute, "Auto-execute"),
            (PermissionTier::LogAndExecute, "Log & Execute"),
            (PermissionTier::HumanApproval, "Requires Approval"),
            (PermissionTier::Forbidden, "Forbidden"),
        ];

        for (tier, expected_label) in tiers {
            let request =
                sample_request("test", serde_json::json!({}), GuardianDecision::Allow, tier);
            let msg = format_approval_message(&request);
            assert!(
                msg.contains(expected_label),
                "Missing label: {expected_label}"
            );
        }
    }

    #[test]
    fn test_summarize_params_with_password_field() {
        let params = serde_json::json!({
            "username": "alice",
            "password": "secret123"
        });
        let summary = summarize_params(&params);
        assert!(summary.contains("alice"));
        assert!(!summary.contains("secret123"));
    }

    #[test]
    fn test_summarize_params_non_object() {
        let params = serde_json::json!("just a string");
        let summary = summarize_params(&params);
        assert!(summary.is_empty());
    }
}
