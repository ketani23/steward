//! Secret broker implementation.
//!
//! Manages encrypted credential storage and scoped token provisioning:
//! - AES-256-GCM encrypted vault with HKDF-SHA256 derived master key
//! - Short-lived, scoped token provisioning
//! - Credential injection at call boundaries
//! - Leak detection on all credential operations
//!
//! See `docs/architecture.md` section 5.2 for full requirements.

use std::collections::HashMap;
use std::sync::Arc;

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use chrono::{Duration, Utc};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use uuid::Uuid;

use steward_types::actions::{EncryptedCredential, ScopedToken, TokenScope, ToolRequest};
use steward_types::errors::StewardError;
use steward_types::traits::{LeakDetector, SecretBroker};

/// AES-256-GCM nonce size in bytes (96 bits).
const NONCE_SIZE: usize = 12;

/// Default salt for HKDF key derivation.
const DEFAULT_SALT: &[u8] = b"steward-secret-broker-v1";

/// Info string for HKDF key derivation.
const HKDF_INFO: &[u8] = b"steward-aes-256-gcm-master-key";

/// Configuration for the vault secret broker.
#[derive(Debug, Clone)]
pub struct SecretBrokerConfig {
    /// Master key material (raw bytes from keychain or env var).
    pub master_key_material: Vec<u8>,
    /// Optional salt for HKDF derivation (defaults to a built-in value).
    pub salt: Option<Vec<u8>>,
    /// Identifier for the derived encryption key.
    pub key_id: String,
}

/// In-memory encrypted credential vault with AES-256-GCM encryption
/// and scoped token provisioning.
///
/// The broker derives its encryption key from master key material using HKDF-SHA256.
/// Credentials are stored encrypted in memory and only decrypted at the transport
/// boundary during injection. The agent never sees raw credential values.
///
/// `Debug` is implemented manually to avoid exposing the cipher state.
pub struct VaultSecretBroker {
    /// AES-256-GCM cipher initialized with the HKDF-derived key.
    cipher: Aes256Gcm,
    /// Identifier for the current encryption key.
    key_id: String,
    /// Encrypted credentials keyed by name.
    vault: RwLock<HashMap<String, EncryptedCredential>>,
    /// Active scoped tokens keyed by token ID.
    tokens: RwLock<HashMap<Uuid, ScopedToken>>,
    /// Leak detector for verifying credentials don't leak into parameter logs.
    leak_detector: Arc<dyn LeakDetector>,
}

impl std::fmt::Debug for VaultSecretBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSecretBroker")
            .field("key_id", &self.key_id)
            .field("vault", &"<encrypted>")
            .field("tokens", &"<tokens>")
            .finish()
    }
}

impl VaultSecretBroker {
    /// Create a new `VaultSecretBroker` with the given configuration and leak detector.
    ///
    /// Derives the AES-256 encryption key from `config.master_key_material` using
    /// HKDF-SHA256 with a configurable salt.
    pub fn new(
        config: SecretBrokerConfig,
        leak_detector: Arc<dyn LeakDetector>,
    ) -> Result<Self, StewardError> {
        let salt = config.salt.as_deref().unwrap_or(DEFAULT_SALT);
        let hk = Hkdf::<Sha256>::new(Some(salt), &config.master_key_material);
        let mut key_bytes = [0u8; 32];
        hk.expand(HKDF_INFO, &mut key_bytes)
            .map_err(|e| StewardError::SecretBroker(format!("HKDF key derivation failed: {e}")))?;

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        debug!(key_id = %config.key_id, "secret broker initialized with HKDF-derived key");

        Ok(Self {
            cipher,
            key_id: config.key_id,
            vault: RwLock::new(HashMap::new()),
            tokens: RwLock::new(HashMap::new()),
            leak_detector,
        })
    }

    /// Create a broker from an environment variable containing the master key.
    ///
    /// Reads the specified environment variable and uses its value as the HKDF
    /// input key material.
    pub fn from_env(
        env_var: &str,
        leak_detector: Arc<dyn LeakDetector>,
    ) -> Result<Self, StewardError> {
        let master_key = std::env::var(env_var).map_err(|_| {
            StewardError::SecretBroker(format!(
                "master key environment variable '{env_var}' not set"
            ))
        })?;

        let config = SecretBrokerConfig {
            master_key_material: master_key.into_bytes(),
            salt: None,
            key_id: format!("env:{env_var}"),
        };

        Self::new(config, leak_detector)
    }

    /// Encrypt raw plaintext bytes into an [`EncryptedCredential`].
    ///
    /// Generates a random 96-bit nonce for each encryption. The caller should
    /// pass the result to [`SecretBroker::store`] to persist the credential.
    pub fn encrypt_credential(
        &self,
        plaintext: &[u8],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<EncryptedCredential, StewardError> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| StewardError::SecretBroker(format!("encryption failed: {e}")))?;

        Ok(EncryptedCredential {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            key_id: self.key_id.clone(),
            created_at: Utc::now(),
            expires_at,
        })
    }

    /// Decrypt an [`EncryptedCredential`] back to plaintext bytes.
    ///
    /// Validates the key ID matches, the credential hasn't expired, and the
    /// nonce length is correct before attempting decryption.
    fn decrypt_credential(
        &self,
        credential: &EncryptedCredential,
    ) -> Result<Vec<u8>, StewardError> {
        if credential.key_id != self.key_id {
            return Err(StewardError::SecretBroker(format!(
                "key mismatch: credential encrypted with '{}', broker uses '{}'",
                credential.key_id, self.key_id
            )));
        }

        if let Some(expires_at) = credential.expires_at {
            if Utc::now() > expires_at {
                return Err(StewardError::SecretBroker(
                    "credential has expired".to_string(),
                ));
            }
        }

        if credential.nonce.len() != NONCE_SIZE {
            return Err(StewardError::SecretBroker(format!(
                "invalid nonce length: expected {NONCE_SIZE}, got {}",
                credential.nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(&credential.nonce);
        self.cipher
            .decrypt(nonce, credential.ciphertext.as_ref())
            .map_err(|e| StewardError::SecretBroker(format!("decryption failed: {e}")))
    }

    /// Rotate a stored credential by atomically replacing it.
    ///
    /// The old credential is replaced with the new one in a single write lock,
    /// ensuring no downtime during rotation.
    pub async fn rotate(
        &self,
        key: &str,
        new_credential: &EncryptedCredential,
    ) -> Result<(), StewardError> {
        let mut vault = self.vault.write().await;
        if !vault.contains_key(key) {
            return Err(StewardError::SecretBroker(format!(
                "cannot rotate: credential '{key}' not found"
            )));
        }

        debug!(key = %key, "rotating credential");
        vault.insert(key.to_string(), new_credential.clone());
        Ok(())
    }

    /// Remove expired tokens from the token store.
    async fn cleanup_expired_tokens(&self) {
        let now = Utc::now();
        let mut tokens = self.tokens.write().await;
        tokens.retain(|_, token| token.expires_at > now);
    }
}

#[async_trait::async_trait]
impl SecretBroker for VaultSecretBroker {
    async fn store(&self, key: &str, credential: &EncryptedCredential) -> Result<(), StewardError> {
        if credential.nonce.len() != NONCE_SIZE {
            return Err(StewardError::SecretBroker(format!(
                "invalid nonce length: expected {NONCE_SIZE}, got {}",
                credential.nonce.len()
            )));
        }

        debug!(key = %key, key_id = %credential.key_id, "storing encrypted credential");

        let mut vault = self.vault.write().await;
        vault.insert(key.to_string(), credential.clone());
        Ok(())
    }

    async fn provision_token(
        &self,
        key: &str,
        scope: &TokenScope,
    ) -> Result<ScopedToken, StewardError> {
        {
            let vault = self.vault.read().await;
            if !vault.contains_key(key) {
                return Err(StewardError::SecretBroker(format!(
                    "credential '{key}' not found"
                )));
            }
        }

        self.cleanup_expired_tokens().await;

        let now = Utc::now();
        let expires_at = now + Duration::seconds(scope.ttl_secs as i64);

        let token = ScopedToken {
            token_id: Uuid::new_v4(),
            credential_key: key.to_string(),
            scope: scope.clone(),
            expires_at,
            used: false,
        };

        debug!(
            token_id = %token.token_id,
            credential_key = %key,
            tool = %scope.tool_name,
            ttl_secs = scope.ttl_secs,
            single_use = scope.single_use,
            "provisioned scoped token"
        );

        let mut tokens = self.tokens.write().await;
        tokens.insert(token.token_id, token.clone());

        Ok(token)
    }

    async fn inject_credentials(
        &self,
        request: &mut ToolRequest,
        key: &str,
    ) -> Result<(), StewardError> {
        let credential = {
            let vault = self.vault.read().await;
            vault
                .get(key)
                .ok_or_else(|| StewardError::SecretBroker(format!("credential '{key}' not found")))?
                .clone()
        };

        // Decrypt at the transport boundary
        let plaintext = self.decrypt_credential(&credential)?;
        let credential_value = String::from_utf8(plaintext).map_err(|e| {
            StewardError::SecretBroker(format!("credential is not valid UTF-8: {e}"))
        })?;

        // Verify the credential value doesn't already appear in request parameters
        // (which would mean it gets logged)
        let params_str = serde_json::to_string(&request.parameters).unwrap_or_default();
        if !credential_value.is_empty() && params_str.contains(&credential_value) {
            warn!(
                key = %key,
                tool = %request.tool_name,
                "credential value found in request parameters — blocking to prevent leak"
            );
            return Err(StewardError::SecretBroker(
                "credential value detected in request parameters — would leak into logs"
                    .to_string(),
            ));
        }

        // Run the leak detector on parameters as an additional safety check
        let leaks = self.leak_detector.scan(&params_str);
        if !leaks.is_empty() {
            warn!(
                key = %key,
                tool = %request.tool_name,
                leak_count = leaks.len(),
                "leak detector found potential secrets in request parameters"
            );
        }

        // Inject at the transport boundary via headers
        request.headers.insert(
            "Authorization".to_string(),
            format!("Bearer {credential_value}"),
        );

        debug!(
            key = %key,
            tool = %request.tool_name,
            "injected credential at transport boundary"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use steward_types::actions::LeakDetection;

    /// Mock leak detector that finds no leaks.
    struct NoopLeakDetector;

    impl LeakDetector for NoopLeakDetector {
        fn scan(&self, _content: &str) -> Vec<LeakDetection> {
            vec![]
        }

        fn redact(&self, content: &str) -> String {
            content.to_string()
        }
    }

    fn test_config() -> SecretBrokerConfig {
        SecretBrokerConfig {
            master_key_material: b"test-master-key-material-at-least-32-bytes-long".to_vec(),
            salt: None,
            key_id: "test-key-v1".to_string(),
        }
    }

    fn test_broker() -> VaultSecretBroker {
        VaultSecretBroker::new(test_config(), Arc::new(NoopLeakDetector)).unwrap()
    }

    // ==========================================
    // Encrypt/decrypt round trip
    // ==========================================

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let broker = test_broker();
        let plaintext = b"super-secret-api-key-12345";

        let encrypted = broker.encrypt_credential(plaintext, None).unwrap();

        assert_ne!(encrypted.ciphertext, plaintext);
        assert_eq!(encrypted.nonce.len(), NONCE_SIZE);
        assert_eq!(encrypted.key_id, "test-key-v1");

        let decrypted = broker.decrypt_credential(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_long_value() {
        let broker = test_broker();
        let plaintext = b"a-very-long-credential-value--".repeat(100);

        let encrypted = broker.encrypt_credential(&plaintext, None).unwrap();
        let decrypted = broker.decrypt_credential(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let broker = test_broker();
        let plaintext = b"";

        let encrypted = broker.encrypt_credential(plaintext, None).unwrap();
        let decrypted = broker.decrypt_credential(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_each_encryption_uses_unique_nonce() {
        let broker = test_broker();
        let plaintext = b"same-data";

        let enc1 = broker.encrypt_credential(plaintext, None).unwrap();
        let enc2 = broker.encrypt_credential(plaintext, None).unwrap();

        assert_ne!(enc1.nonce, enc2.nonce);
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
    }

    // ==========================================
    // Credentials not readable without master key
    // ==========================================

    #[test]
    fn test_wrong_master_key_fails_decryption() {
        let broker1 = test_broker();
        let plaintext = b"my-secret";
        let encrypted = broker1.encrypt_credential(plaintext, None).unwrap();

        // Second broker with a different master key but same key_id
        let config2 = SecretBrokerConfig {
            master_key_material: b"completely-different-master-key-material!!".to_vec(),
            salt: None,
            key_id: "test-key-v1".to_string(),
        };
        let broker2 = VaultSecretBroker::new(config2, Arc::new(NoopLeakDetector)).unwrap();

        let result = broker2.decrypt_credential(&encrypted);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("decryption failed"));
    }

    #[test]
    fn test_key_id_mismatch_rejected() {
        let broker = test_broker();
        let plaintext = b"my-secret";
        let mut encrypted = broker.encrypt_credential(plaintext, None).unwrap();
        encrypted.key_id = "wrong-key-id".to_string();

        let result = broker.decrypt_credential(&encrypted);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key mismatch"));
    }

    #[test]
    fn test_tampered_ciphertext_fails_decryption() {
        let broker = test_broker();
        let plaintext = b"my-secret";
        let mut encrypted = broker.encrypt_credential(plaintext, None).unwrap();

        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        let result = broker.decrypt_credential(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_nonce_fails_decryption() {
        let broker = test_broker();
        let plaintext = b"my-secret";
        let mut encrypted = broker.encrypt_credential(plaintext, None).unwrap();
        encrypted.nonce[0] ^= 0xFF;

        let result = broker.decrypt_credential(&encrypted);
        assert!(result.is_err());
    }

    // ==========================================
    // Scoped token creation with expiry
    // ==========================================

    #[tokio::test]
    async fn test_provision_token_basic() {
        let broker = test_broker();
        let encrypted = broker.encrypt_credential(b"api-key", None).unwrap();
        broker.store("gmail_oauth", &encrypted).await.unwrap();

        let scope = TokenScope {
            tool_name: "gmail.send".to_string(),
            endpoint: Some("https://gmail.googleapis.com".to_string()),
            ttl_secs: 300,
            single_use: false,
        };

        let token = broker.provision_token("gmail_oauth", &scope).await.unwrap();

        assert_eq!(token.credential_key, "gmail_oauth");
        assert_eq!(token.scope.tool_name, "gmail.send");
        assert_eq!(token.scope.ttl_secs, 300);
        assert!(!token.used);
        assert!(token.expires_at > Utc::now());
    }

    #[tokio::test]
    async fn test_provision_token_single_use() {
        let broker = test_broker();
        let encrypted = broker.encrypt_credential(b"api-key", None).unwrap();
        broker.store("temp_key", &encrypted).await.unwrap();

        let scope = TokenScope {
            tool_name: "shell.exec".to_string(),
            endpoint: None,
            ttl_secs: 60,
            single_use: true,
        };

        let token = broker.provision_token("temp_key", &scope).await.unwrap();
        assert!(token.scope.single_use);
        assert!(!token.used);
    }

    #[tokio::test]
    async fn test_provision_token_nonexistent_credential() {
        let broker = test_broker();

        let scope = TokenScope {
            tool_name: "gmail.send".to_string(),
            endpoint: None,
            ttl_secs: 300,
            single_use: false,
        };

        let result = broker.provision_token("nonexistent", &scope).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_token_has_correct_expiry() {
        let broker = test_broker();
        let encrypted = broker.encrypt_credential(b"key", None).unwrap();
        broker.store("test", &encrypted).await.unwrap();

        let before = Utc::now();
        let scope = TokenScope {
            tool_name: "test.tool".to_string(),
            endpoint: None,
            ttl_secs: 600,
            single_use: false,
        };
        let token = broker.provision_token("test", &scope).await.unwrap();
        let after = Utc::now();

        let expected_min = before + Duration::seconds(600);
        let expected_max = after + Duration::seconds(600);
        assert!(token.expires_at >= expected_min);
        assert!(token.expires_at <= expected_max);
    }

    // ==========================================
    // Credential injection
    // ==========================================

    #[tokio::test]
    async fn test_inject_credentials_basic() {
        let broker = test_broker();
        let encrypted = broker
            .encrypt_credential(b"my-oauth-token-12345", None)
            .unwrap();
        broker.store("gmail_oauth", &encrypted).await.unwrap();

        let mut request = ToolRequest {
            tool_name: "gmail.send".to_string(),
            parameters: serde_json::json!({"to": "user@example.com", "subject": "Hello"}),
            headers: HashMap::new(),
        };

        broker
            .inject_credentials(&mut request, "gmail_oauth")
            .await
            .unwrap();

        assert_eq!(
            request.headers.get("Authorization").unwrap(),
            "Bearer my-oauth-token-12345"
        );
    }

    #[tokio::test]
    async fn test_inject_credentials_nonexistent_key() {
        let broker = test_broker();

        let mut request = ToolRequest {
            tool_name: "gmail.send".to_string(),
            parameters: serde_json::json!({}),
            headers: HashMap::new(),
        };

        let result = broker.inject_credentials(&mut request, "nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_inject_blocks_when_credential_in_params() {
        let broker = test_broker();
        let secret = "my-leaked-secret-value";
        let encrypted = broker.encrypt_credential(secret.as_bytes(), None).unwrap();
        broker.store("leaky_key", &encrypted).await.unwrap();

        let mut request = ToolRequest {
            tool_name: "some.tool".to_string(),
            parameters: serde_json::json!({"data": "contains my-leaked-secret-value here"}),
            headers: HashMap::new(),
        };

        let result = broker.inject_credentials(&mut request, "leaky_key").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("would leak"));
    }

    #[tokio::test]
    async fn test_inject_multiple_credentials() {
        let broker = test_broker();
        let cred1 = broker.encrypt_credential(b"gmail-token", None).unwrap();
        let cred2 = broker.encrypt_credential(b"slack-token", None).unwrap();
        let cred3 = broker.encrypt_credential(b"github-pat", None).unwrap();

        broker.store("gmail", &cred1).await.unwrap();
        broker.store("slack", &cred2).await.unwrap();
        broker.store("github", &cred3).await.unwrap();

        let mut req1 = ToolRequest {
            tool_name: "gmail.send".to_string(),
            parameters: serde_json::json!({}),
            headers: HashMap::new(),
        };
        broker.inject_credentials(&mut req1, "gmail").await.unwrap();
        assert!(req1.headers["Authorization"].contains("gmail-token"));

        let mut req2 = ToolRequest {
            tool_name: "slack.post".to_string(),
            parameters: serde_json::json!({}),
            headers: HashMap::new(),
        };
        broker.inject_credentials(&mut req2, "slack").await.unwrap();
        assert!(req2.headers["Authorization"].contains("slack-token"));

        let mut req3 = ToolRequest {
            tool_name: "github.create_issue".to_string(),
            parameters: serde_json::json!({}),
            headers: HashMap::new(),
        };
        broker
            .inject_credentials(&mut req3, "github")
            .await
            .unwrap();
        assert!(req3.headers["Authorization"].contains("github-pat"));
    }

    // ==========================================
    // Expired credentials/tokens rejected
    // ==========================================

    #[tokio::test]
    async fn test_expired_credential_rejected_on_inject() {
        let broker = test_broker();

        // Encrypt with an already-expired expiry
        let expired_at = Utc::now() - Duration::hours(1);
        let encrypted = broker
            .encrypt_credential(b"old-secret", Some(expired_at))
            .unwrap();
        broker.store("expired_key", &encrypted).await.unwrap();

        let mut request = ToolRequest {
            tool_name: "test.tool".to_string(),
            parameters: serde_json::json!({}),
            headers: HashMap::new(),
        };

        let result = broker.inject_credentials(&mut request, "expired_key").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[tokio::test]
    async fn test_expired_tokens_cleaned_up() {
        let broker = test_broker();
        let encrypted = broker.encrypt_credential(b"key", None).unwrap();
        broker.store("test", &encrypted).await.unwrap();

        // Create a token that expires immediately (ttl=0)
        let scope = TokenScope {
            tool_name: "test.tool".to_string(),
            endpoint: None,
            ttl_secs: 0,
            single_use: false,
        };
        let expired_token = broker.provision_token("test", &scope).await.unwrap();

        // Wait to ensure expiry
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Provisioning another token triggers cleanup
        let scope2 = TokenScope {
            tool_name: "test.tool".to_string(),
            endpoint: None,
            ttl_secs: 300,
            single_use: false,
        };
        let _ = broker.provision_token("test", &scope2).await.unwrap();

        let tokens = broker.tokens.read().await;
        assert!(!tokens.contains_key(&expired_token.token_id));
    }

    // ==========================================
    // Credential rotation
    // ==========================================

    #[tokio::test]
    async fn test_rotate_credential() {
        let broker = test_broker();

        let original = broker.encrypt_credential(b"old-api-key", None).unwrap();
        broker.store("api_key", &original).await.unwrap();

        // Verify original works
        let mut request = ToolRequest {
            tool_name: "test.tool".to_string(),
            parameters: serde_json::json!({}),
            headers: HashMap::new(),
        };
        broker
            .inject_credentials(&mut request, "api_key")
            .await
            .unwrap();
        assert!(request.headers["Authorization"].contains("old-api-key"));

        // Rotate to new credential
        let rotated = broker.encrypt_credential(b"new-api-key", None).unwrap();
        broker.rotate("api_key", &rotated).await.unwrap();

        // Verify rotated credential is now used
        let mut request2 = ToolRequest {
            tool_name: "test.tool".to_string(),
            parameters: serde_json::json!({}),
            headers: HashMap::new(),
        };
        broker
            .inject_credentials(&mut request2, "api_key")
            .await
            .unwrap();
        assert!(request2.headers["Authorization"].contains("new-api-key"));
    }

    #[tokio::test]
    async fn test_rotate_nonexistent_credential_fails() {
        let broker = test_broker();
        let new_cred = broker.encrypt_credential(b"value", None).unwrap();

        let result = broker.rotate("nonexistent", &new_cred).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // ==========================================
    // Store validation
    // ==========================================

    #[tokio::test]
    async fn test_store_rejects_invalid_nonce_length() {
        let broker = test_broker();
        let bad = EncryptedCredential {
            ciphertext: vec![0; 32],
            nonce: vec![0; 8], // Wrong length — must be 12
            key_id: "test".to_string(),
            created_at: Utc::now(),
            expires_at: None,
        };

        let result = broker.store("bad_key", &bad).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce length"));
    }

    #[tokio::test]
    async fn test_store_overwrites_existing_key() {
        let broker = test_broker();
        let cred1 = broker.encrypt_credential(b"first-value", None).unwrap();
        let cred2 = broker.encrypt_credential(b"second-value", None).unwrap();

        broker.store("key", &cred1).await.unwrap();
        broker.store("key", &cred2).await.unwrap();

        let mut request = ToolRequest {
            tool_name: "test.tool".to_string(),
            parameters: serde_json::json!({}),
            headers: HashMap::new(),
        };
        broker
            .inject_credentials(&mut request, "key")
            .await
            .unwrap();
        assert!(request.headers["Authorization"].contains("second-value"));
    }

    // ==========================================
    // HKDF key derivation
    // ==========================================

    #[test]
    fn test_different_salts_produce_different_keys() {
        let config1 = SecretBrokerConfig {
            master_key_material: b"same-master-key".to_vec(),
            salt: Some(b"salt-one".to_vec()),
            key_id: "k1".to_string(),
        };
        let config2 = SecretBrokerConfig {
            master_key_material: b"same-master-key".to_vec(),
            salt: Some(b"salt-two".to_vec()),
            key_id: "k1".to_string(),
        };

        let broker1 = VaultSecretBroker::new(config1, Arc::new(NoopLeakDetector)).unwrap();
        let broker2 = VaultSecretBroker::new(config2, Arc::new(NoopLeakDetector)).unwrap();

        let plaintext = b"test-data";
        let encrypted = broker1.encrypt_credential(plaintext, None).unwrap();

        // Different derived key due to different salt — decryption should fail
        let result = broker2.decrypt_credential(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_master_keys_produce_different_keys() {
        let config1 = SecretBrokerConfig {
            master_key_material: b"master-key-alpha".to_vec(),
            salt: None,
            key_id: "k1".to_string(),
        };
        let config2 = SecretBrokerConfig {
            master_key_material: b"master-key-bravo".to_vec(),
            salt: None,
            key_id: "k1".to_string(),
        };

        let broker1 = VaultSecretBroker::new(config1, Arc::new(NoopLeakDetector)).unwrap();
        let broker2 = VaultSecretBroker::new(config2, Arc::new(NoopLeakDetector)).unwrap();

        let plaintext = b"test-data";
        let encrypted = broker1.encrypt_credential(plaintext, None).unwrap();

        let result = broker2.decrypt_credential(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_env_missing_var() {
        let result = VaultSecretBroker::from_env(
            "STEWARD_DEFINITELY_NOT_SET_12345",
            Arc::new(NoopLeakDetector),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not set"));
    }

    // ==========================================
    // Invalid nonce length on decrypt
    // ==========================================

    #[test]
    fn test_decrypt_rejects_invalid_nonce_length() {
        let broker = test_broker();
        let bad = EncryptedCredential {
            ciphertext: vec![0; 32],
            nonce: vec![0; 8],
            key_id: broker.key_id.clone(),
            created_at: Utc::now(),
            expires_at: None,
        };

        let result = broker.decrypt_credential(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce length"));
    }
}
