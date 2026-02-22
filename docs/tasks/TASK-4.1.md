Read docs/architecture.md section 5.2 (Secret Broker).
Read crates/steward-types/src/traits.rs for the SecretBroker trait.

Implement the secret broker in crates/steward-security/src/secret_broker.rs.

Requirements:
- Implement the SecretBroker trait from steward-types
- AES-256-GCM encryption for credential storage using the `aes-gcm` crate
- Master key derivation from system keychain or env var (for dev/testing)
  using HKDF (via `hkdf` crate)
- store(): encrypt credential with AES-256-GCM, store in-memory (use a HashMap
  wrapped in RwLock for thread safety). Include encrypted_data, nonce, key_id,
  created_at, expires_at fields.
- provision_token(): create a scoped, time-limited wrapper around a stored
  credential. The ScopedToken includes: the credential reference (not the raw
  value), allowed scope (which tool, which endpoint), expiry time, single-use flag
- inject_credentials(): given a ToolRequest and a credential key, inject the
  actual credential value into the request at the transport boundary. The
  credential is decrypted only at this point and only exists in memory briefly.
- Credentials must never appear in logs — use the LeakDetector to verify
  that injected credentials don't leak into parameter logging
- Support credential rotation: update a stored credential without downtime

Write tests:
- Test encrypt/decrypt round trip
- Test that stored credentials are not readable without the master key
- Test scoped token creation with expiry
- Test credential injection into a mock tool request
- Test that expired tokens are rejected
- Test credential rotation

When done:
- Run `cargo fmt --all`
- Run `cargo clippy --all-targets --all-features -- -D warnings` and fix any warnings
- Run `cargo test -p steward-security` and ensure all tests pass
- Stage and commit: `git add -A && git commit -m "feat(security): implement secret broker with AES-256-GCM encryption and scoped tokens"`
- Push and create PR: `git push origin HEAD && gh pr create --title "feat(security): implement secret broker" --body "Implements SecretBroker trait with AES-256-GCM encryption, HKDF key derivation, scoped time-limited tokens, credential injection, and rotation support." --base main`
