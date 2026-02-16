/// Security subsystem for the Steward agent framework.
///
/// This crate implements the security layers that protect the system:
/// - **Ingress sanitizer**: Preprocesses external content, detects prompt injection
/// - **Egress filter**: Scans outbound content for PII, secrets, policy violations
/// - **Secret broker**: Encrypted credential storage with scoped token provisioning
/// - **Leak detector**: Bidirectional credential pattern scanning on all I/O
/// - **Audit logger**: Append-only event logging for all system actions
pub mod audit;
pub mod egress;
pub mod ingress;
pub mod leak_detector;
pub mod secret_broker;
