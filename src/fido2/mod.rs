//! FIDO2/WebAuthn authentication for Vaultic
//!
//! Supports hardware security keys (YubiKey, etc.) for vault unlock.
//! Uses HMAC-Secret extension for deriving encryption keys.
//!
//! Note: Full FIDO2 implementation requires hardware for testing.
//! This is a stub that provides the interface for future implementation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::MasterKey;

/// FIDO2 authentication errors
#[derive(Debug, Error)]
pub enum Fido2Error {
    #[error("No FIDO2 device found")]
    NoDeviceFound,

    #[error("Multiple FIDO2 devices found, please specify which one")]
    MultipleDevicesFound,

    #[error("Device error: {0}")]
    DeviceError(String),

    #[error("User verification failed")]
    VerificationFailed,

    #[error("Credential not found")]
    CredentialNotFound,

    #[error("Registration failed: {0}")]
    RegistrationFailed(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("HMAC-Secret extension not supported")]
    HmacSecretNotSupported,

    #[error("User cancelled operation")]
    UserCancelled,

    #[error("FIDO2 not available (stub implementation)")]
    NotAvailable,
}

pub type Fido2Result<T> = Result<T, Fido2Error>;

/// Relying party configuration
const RP_ID: &str = "vaultic.local";
const _RP_NAME: &str = "Vaultic Password Manager";

/// Stored credential information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub user_id: Vec<u8>,
    pub device_name: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    /// Counter to detect cloned authenticators
    pub counter: u32,
    /// Whether this credential supports HMAC-Secret
    pub supports_hmac_secret: bool,
}

/// FIDO2 device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub path: String,
    pub manufacturer: String,
    pub product: String,
    pub serial: Option<String>,
}

/// FIDO2 authentication manager
pub struct Fido2Auth {
    /// Salt used with HMAC-Secret extension
    salt: [u8; 32],
}

impl Fido2Auth {
    /// Create a new FIDO2 auth manager
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        let mut rng = rand::thread_rng();
        rand::RngCore::fill_bytes(&mut rng, &mut salt);

        Self { salt }
    }

    /// Create with existing salt (for vault unlock)
    pub fn with_salt(salt: [u8; 32]) -> Self {
        Self { salt }
    }

    /// Generate salt for a new vault
    pub fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        let mut rng = rand::thread_rng();
        rand::RngCore::fill_bytes(&mut rng, &mut salt);
        salt
    }

    /// Get the salt (to store with vault)
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// List available FIDO2 devices
    /// Note: Stub implementation - returns empty list
    pub fn list_devices() -> Fido2Result<Vec<DeviceInfo>> {
        // TODO: Implement with ctap-hid-fido2 when hardware is available
        Ok(vec![])
    }

    /// Register a new credential (setup flow)
    /// Note: Stub implementation
    pub fn register(&self, _user_name: &str) -> Fido2Result<StoredCredential> {
        Err(Fido2Error::NotAvailable)
    }

    /// Authenticate with a stored credential
    /// Note: Stub implementation
    pub fn authenticate(&self, _credential: &StoredCredential) -> Fido2Result<MasterKey> {
        Err(Fido2Error::NotAvailable)
    }

    /// Quick check if a device is present
    /// Note: Stub implementation - always returns false
    pub fn device_present() -> bool {
        false
    }

    /// Create a challenge for FIDO2 operations
    fn _create_challenge(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.salt);
        hasher.update(Uuid::new_v4().as_bytes());
        hasher.finalize().to_vec()
    }

    /// Derive master key from FIDO2 response
    pub fn derive_master_key(&self, credential_id: &[u8], auth_data: &[u8]) -> MasterKey {
        use hkdf::Hkdf;

        // Combine credential ID, auth data, and salt
        let mut ikm = Vec::new();
        ikm.extend_from_slice(credential_id);
        ikm.extend_from_slice(auth_data);
        ikm.extend_from_slice(&self.salt);

        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"vaultic-fido2-master-key-v1", &mut okm)
            .expect("HKDF expansion failed");

        MasterKey::from_bytes(okm)
    }
}

impl Default for Fido2Auth {
    fn default() -> Self {
        Self::new()
    }
}

/// Passkey (platform authenticator) support
/// For biometric/PIN unlock on supported platforms
pub struct PasskeyAuth;

impl PasskeyAuth {
    /// Check if platform authenticator is available
    pub fn is_available() -> bool {
        // Check for platform authenticator support
        // This would use platform-specific APIs
        #[cfg(target_os = "macos")]
        {
            // Touch ID / Secure Enclave - could be supported
            false // Stub for now
        }
        #[cfg(target_os = "windows")]
        {
            // Windows Hello
            false // Stub for now
        }
        #[cfg(target_os = "linux")]
        {
            // Usually not available, but could use TPM
            false
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            false
        }
    }
}

/// Combined auth that tries FIDO2 first, falls back to password
pub struct HybridAuth {
    fido2: Option<Fido2Auth>,
    credential: Option<StoredCredential>,
}

impl HybridAuth {
    pub fn new() -> Self {
        Self {
            fido2: None,
            credential: None,
        }
    }

    pub fn with_fido2(mut self, salt: [u8; 32], credential: StoredCredential) -> Self {
        self.fido2 = Some(Fido2Auth::with_salt(salt));
        self.credential = Some(credential);
        self
    }

    /// Attempt authentication
    /// Returns (master_key, method_used)
    pub fn authenticate(&self) -> Fido2Result<(MasterKey, AuthMethod)> {
        // Try FIDO2 first if configured and device present
        if let (Some(fido2), Some(credential)) = (&self.fido2, &self.credential) {
            if Fido2Auth::device_present() {
                match fido2.authenticate(credential) {
                    Ok(key) => return Ok((key, AuthMethod::Fido2)),
                    Err(e) => {
                        eprintln!("FIDO2 auth failed: {}, falling back to password", e);
                    }
                }
            }
        }

        Err(Fido2Error::NoDeviceFound)
    }
}

impl Default for HybridAuth {
    fn default() -> Self {
        Self::new()
    }
}

/// Authentication method used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Fido2,
    Password,
    Passkey,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fido2 => write!(f, "FIDO2 Security Key"),
            Self::Password => write!(f, "Master Password"),
            Self::Passkey => write!(f, "Passkey"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fido2_auth_creation() {
        let auth = Fido2Auth::new();
        assert_eq!(auth.salt().len(), 32);
    }

    #[test]
    fn test_salt_persistence() {
        let original_salt = Fido2Auth::generate_salt();
        let auth = Fido2Auth::with_salt(original_salt);
        assert_eq!(auth.salt(), &original_salt);
    }

    #[test]
    fn test_device_not_present() {
        assert!(!Fido2Auth::device_present());
    }

    #[test]
    fn test_list_devices_empty() {
        let devices = Fido2Auth::list_devices().unwrap();
        assert!(devices.is_empty());
    }
}
