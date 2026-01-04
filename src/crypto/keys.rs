//! Key types for Vaultic's multi-method unlock system
//!
//! This module implements the key hierarchy:
//! - VaultKey: Random 256-bit key, generated once, encrypts all entries
//! - KeyEncryptionKey (KEK): Derived from unlock method, wraps VaultKey
//! - EncryptedVaultKey: VaultKey encrypted with a specific KEK
//! - VaultKeyring: Collection of all unlock methods for a vault

use chrono::{DateTime, Utc};
use rand::RngCore;
use chacha20poly1305::aead::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::CryptoError;
use crate::models::KdfParams;

/// Master vault key - generated once at vault creation, never changes.
/// All vault entries are encrypted with keys derived from this.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; 32]);

impl VaultKey {
    /// Generate a new random vault key using a CSPRNG
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Create from raw bytes (for recovery/migration)
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw key bytes for encryption operations
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get key bytes as a slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Key Encryption Key - derived from an unlock method (password, recovery key, etc.)
/// Used to wrap/unwrap the VaultKey
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey([u8; 32]);

impl KeyEncryptionKey {
    /// Create a KEK from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw key bytes
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get key bytes as a slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for KeyEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEncryptionKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Supported unlock methods for a vault
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UnlockMethod {
    /// Master password with Argon2id KDF
    Password,
    /// BIP39 24-word recovery key
    RecoveryKey,
    /// YubiKey HMAC-SHA1 challenge-response
    YubiKey {
        /// YubiKey serial number
        serial: u32,
        /// Slot used (1 or 2)
        slot: u8,
    },
    /// FIDO2/WebAuthn passkey
    Passkey {
        /// Credential ID from registration
        credential_id: Vec<u8>,
    },
    /// GPG/OpenPGP key
    GpgKey {
        /// GPG key ID (long format)
        key_id: String,
    },
}

impl std::fmt::Display for UnlockMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnlockMethod::Password => write!(f, "Password"),
            UnlockMethod::RecoveryKey => write!(f, "Recovery Key"),
            UnlockMethod::YubiKey { serial, slot } => {
                write!(f, "YubiKey {} (slot {})", serial, slot)
            }
            UnlockMethod::Passkey { .. } => write!(f, "Passkey"),
            UnlockMethod::GpgKey { key_id } => write!(f, "GPG Key {}", &key_id[..8.min(key_id.len())]),
        }
    }
}

/// Method-specific data needed for key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MethodData {
    /// Password method: Argon2id parameters (salt is already in params)
    Password {
        /// KDF parameters including salt
        params: KdfParams,
    },
    /// Recovery key method: salt for HKDF
    Recovery {
        salt: Vec<u8>,
        /// First 4 words hash for identification without exposing full key
        fingerprint: String,
    },
    /// YubiKey method: challenge for HMAC
    YubiKey {
        serial: u32,
        slot: u8,
        challenge: Vec<u8>,
    },
    /// Passkey method: credential data
    Passkey {
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        rp_id: String,
    },
    /// GPG method: key identification
    Gpg {
        key_id: String,
        fingerprint: String,
    },
}

/// Encrypted vault key with metadata about the encryption method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedVaultKey {
    /// Unique identifier for this unlock method instance
    pub id: Uuid,
    /// The unlock method type
    pub method: UnlockMethod,
    /// Encrypted VaultKey (32 bytes VK + 16 bytes Poly1305 tag)
    pub ciphertext: Vec<u8>,
    /// XChaCha20-Poly1305 nonce
    pub nonce: [u8; 24],
    /// Method-specific data needed for key derivation
    pub method_data: MethodData,
    /// When this unlock method was added
    pub created_at: DateTime<Utc>,
    /// Last time this method was used to unlock
    pub last_used: Option<DateTime<Utc>>,
    /// User-friendly label for this unlock method
    pub label: Option<String>,
}

impl EncryptedVaultKey {
    /// Create a new encrypted vault key
    pub fn new(
        method: UnlockMethod,
        ciphertext: Vec<u8>,
        nonce: [u8; 24],
        method_data: MethodData,
        label: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            method,
            ciphertext,
            nonce,
            method_data,
            created_at: Utc::now(),
            last_used: None,
            label,
        }
    }

    /// Update the last used timestamp
    pub fn mark_used(&mut self) {
        self.last_used = Some(Utc::now());
    }

    /// Get a display name for this unlock method
    pub fn display_name(&self) -> String {
        if let Some(ref label) = self.label {
            label.clone()
        } else {
            self.method.to_string()
        }
    }
}

/// Collection of all unlock methods for a vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeyring {
    /// Vault identifier
    pub vault_id: Uuid,
    /// Keyring format version (2 for new key hierarchy)
    pub version: u32,
    /// All encrypted vault keys (one per unlock method)
    pub keys: Vec<EncryptedVaultKey>,
    /// When the keyring was created
    pub created_at: DateTime<Utc>,
    /// Last modification time
    pub modified_at: DateTime<Utc>,
}

impl VaultKeyring {
    /// Current keyring format version
    pub const VERSION: u32 = 2;

    /// Create a new empty keyring
    pub fn new(vault_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            vault_id,
            version: Self::VERSION,
            keys: Vec::new(),
            created_at: now,
            modified_at: now,
        }
    }

    /// Add a new unlock method
    pub fn add_key(&mut self, encrypted_key: EncryptedVaultKey) {
        self.keys.push(encrypted_key);
        self.modified_at = Utc::now();
    }

    /// Remove an unlock method by its ID
    pub fn remove_key(&mut self, id: &Uuid) -> Result<EncryptedVaultKey, CryptoError> {
        let pos = self.keys.iter().position(|k| &k.id == id);
        match pos {
            Some(idx) => {
                self.modified_at = Utc::now();
                Ok(self.keys.remove(idx))
            }
            None => Err(CryptoError::KeyDerivationFailed(format!(
                "Unlock method {} not found",
                id
            ))),
        }
    }

    /// Find an encrypted key by unlock method type
    pub fn find_by_method(&self, method: &UnlockMethod) -> Option<&EncryptedVaultKey> {
        self.keys.iter().find(|k| &k.method == method)
    }

    /// Find an encrypted key by unlock method type (mutable)
    pub fn find_by_method_mut(&mut self, method: &UnlockMethod) -> Option<&mut EncryptedVaultKey> {
        self.keys.iter_mut().find(|k| &k.method == method)
    }

    /// Find an encrypted key by ID
    pub fn find_by_id(&self, id: &Uuid) -> Option<&EncryptedVaultKey> {
        self.keys.iter().find(|k| &k.id == id)
    }

    /// Check if password method is configured
    pub fn has_password(&self) -> bool {
        self.keys.iter().any(|k| matches!(k.method, UnlockMethod::Password))
    }

    /// Check if recovery key is configured
    pub fn has_recovery(&self) -> bool {
        self.keys.iter().any(|k| matches!(k.method, UnlockMethod::RecoveryKey))
    }

    /// Check if any hardware key is configured
    pub fn has_hardware_key(&self) -> bool {
        self.keys.iter().any(|k| {
            matches!(k.method, UnlockMethod::YubiKey { .. } | UnlockMethod::Passkey { .. })
        })
    }

    /// Get the number of configured unlock methods
    pub fn method_count(&self) -> usize {
        self.keys.len()
    }

    /// List all configured unlock methods
    pub fn list_methods(&self) -> Vec<&EncryptedVaultKey> {
        self.keys.iter().collect()
    }

    /// Check if this is a valid keyring (has at least one unlock method)
    pub fn is_valid(&self) -> bool {
        !self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_key_generation() {
        let vk1 = VaultKey::generate();
        let vk2 = VaultKey::generate();

        // Keys should be different
        assert_ne!(vk1.expose(), vk2.expose());
        // Key should be 32 bytes
        assert_eq!(vk1.expose().len(), 32);
    }

    #[test]
    fn test_vault_key_from_bytes() {
        let bytes = [42u8; 32];
        let vk = VaultKey::from_bytes(bytes);
        assert_eq!(vk.expose(), &bytes);
    }

    #[test]
    fn test_kek_from_bytes() {
        let bytes = [0xAB; 32];
        let kek = KeyEncryptionKey::from_bytes(bytes);
        assert_eq!(kek.expose(), &bytes);
    }

    #[test]
    fn test_unlock_method_display() {
        assert_eq!(UnlockMethod::Password.to_string(), "Password");
        assert_eq!(UnlockMethod::RecoveryKey.to_string(), "Recovery Key");
        assert_eq!(
            UnlockMethod::YubiKey { serial: 12345678, slot: 2 }.to_string(),
            "YubiKey 12345678 (slot 2)"
        );
    }

    #[test]
    fn test_keyring_operations() {
        let mut keyring = VaultKeyring::new(Uuid::new_v4());
        assert!(!keyring.is_valid());
        assert_eq!(keyring.method_count(), 0);
        assert!(!keyring.has_password());
        assert!(!keyring.has_recovery());

        // Add a password method
        let encrypted = EncryptedVaultKey::new(
            UnlockMethod::Password,
            vec![0; 48],
            [0; 24],
            MethodData::Password {
                params: KdfParams::default(),
            },
            Some("Main Password".to_string()),
        );
        keyring.add_key(encrypted);

        assert!(keyring.is_valid());
        assert_eq!(keyring.method_count(), 1);
        assert!(keyring.has_password());
        assert!(!keyring.has_recovery());

        // Add recovery key
        let recovery = EncryptedVaultKey::new(
            UnlockMethod::RecoveryKey,
            vec![0; 48],
            [0; 24],
            MethodData::Recovery {
                salt: vec![0; 32],
                fingerprint: "abandon ability...".to_string(),
            },
            None,
        );
        let recovery_id = recovery.id;
        keyring.add_key(recovery);

        assert_eq!(keyring.method_count(), 2);
        assert!(keyring.has_recovery());

        // Find by method
        assert!(keyring.find_by_method(&UnlockMethod::Password).is_some());
        assert!(keyring.find_by_method(&UnlockMethod::RecoveryKey).is_some());

        // Remove recovery key
        keyring.remove_key(&recovery_id).unwrap();
        assert_eq!(keyring.method_count(), 1);
        assert!(!keyring.has_recovery());
    }

    #[test]
    fn test_encrypted_vault_key_display_name() {
        let with_label = EncryptedVaultKey::new(
            UnlockMethod::Password,
            vec![0; 48],
            [0; 24],
            MethodData::Password {
                params: KdfParams::default(),
            },
            Some("Work Laptop".to_string()),
        );
        assert_eq!(with_label.display_name(), "Work Laptop");

        let without_label = EncryptedVaultKey::new(
            UnlockMethod::Password,
            vec![0; 48],
            [0; 24],
            MethodData::Password {
                params: KdfParams::default(),
            },
            None,
        );
        assert_eq!(without_label.display_name(), "Password");
    }
}
