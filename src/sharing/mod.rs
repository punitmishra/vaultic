//! Secure password sharing functionality
//!
//! Uses asymmetric encryption (X25519 + XChaCha20-Poly1305) for
//! end-to-end encrypted sharing between users.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::{Cipher, CryptoError, IdentityKeyPair, KeyExchange};
use crate::models::{SharedSecret, UserIdentity, VaultEntry};

/// Sharing errors
#[derive(Debug, Error)]
pub enum SharingError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("Recipient not found: {0}")]
    RecipientNotFound(String),

    #[error("Share expired")]
    ShareExpired,

    #[error("Share access limit reached")]
    AccessLimitReached,

    #[error("Invalid share data")]
    InvalidShareData,

    #[error("Not authorized to access this share")]
    NotAuthorized,
}

pub type SharingResult<T> = Result<T, SharingError>;

/// Manages secure sharing of vault entries
pub struct SharingManager {
    own_keypair: IdentityKeyPair,
    own_identity: UserIdentity,
}

impl SharingManager {
    /// Create a new sharing manager with an identity keypair
    pub fn new(keypair: IdentityKeyPair, name: String) -> Self {
        let fingerprint = keypair.fingerprint();
        let identity = UserIdentity {
            id: Uuid::new_v4(),
            name,
            email: None,
            public_key: keypair.exchange_public_key().as_bytes().to_vec(),
            signing_key: keypair.signing_public_key().as_bytes().to_vec(),
            fingerprint: fingerprint.clone(),
            created_at: Utc::now(),
            trusted: true,
        };

        Self {
            own_keypair: keypair,
            own_identity: identity,
        }
    }

    /// Get own identity for sharing
    pub fn own_identity(&self) -> &UserIdentity {
        &self.own_identity
    }

    /// Get own fingerprint
    pub fn fingerprint(&self) -> &str {
        &self.own_identity.fingerprint
    }

    /// Create a share for a recipient
    pub fn create_share(
        &self,
        entry: &VaultEntry,
        recipient: &UserIdentity,
        one_time: bool,
        expires_hours: Option<u32>,
        max_access_count: Option<u32>,
    ) -> SharingResult<SharedSecret> {
        // Parse recipient's public key
        let recipient_public = self.parse_public_key(&recipient.public_key)?;

        // Create shared secret using key exchange
        let (symmetric_key, ephemeral_public) =
            KeyExchange::create_shared_secret(&self.own_keypair, &recipient_public);

        // Serialize entry (without sensitive metadata)
        let share_data = ShareData {
            entry_id: entry.id,
            name: entry.name.clone(),
            entry_type: entry.entry_type.clone(),
            username: entry.username.clone(),
            password: entry.password.as_ref().map(|p| p.expose().to_string()),
            url: entry.url.clone(),
            notes: entry.notes.as_ref().map(|n| n.expose().to_string()),
            custom_fields: entry
                .custom_fields
                .iter()
                .map(|f| (f.name.clone(), f.value.expose().to_string(), f.is_hidden))
                .collect(),
            totp_secret: entry.totp_secret.as_ref().map(|t| t.expose().to_string()),
            shared_at: Utc::now(),
            sender_name: self.own_identity.name.clone(),
        };

        let serialized = bincode::serialize(&share_data)?;

        // Encrypt with shared symmetric key
        let cipher = Cipher::new(&symmetric_key);
        let encrypted_data = cipher.encrypt(&serialized)?;

        // Calculate expiration
        let expires_at = expires_hours.map(|h| Utc::now() + Duration::hours(h as i64));

        Ok(SharedSecret {
            id: Uuid::new_v4(),
            entry_id: entry.id,
            encrypted_data,
            encrypted_key: ephemeral_public,
            sender_fingerprint: self.own_identity.fingerprint.clone(),
            recipient_fingerprint: recipient.fingerprint.clone(),
            created_at: Utc::now(),
            expires_at,
            one_time,
            access_count: 0,
            max_access_count,
        })
    }

    /// Open a received share
    pub fn open_share(&self, share: &SharedSecret) -> SharingResult<ShareData> {
        // Check authorization
        if share.recipient_fingerprint != self.own_identity.fingerprint {
            return Err(SharingError::NotAuthorized);
        }

        // Check expiration
        if let Some(expires) = share.expires_at {
            if Utc::now() > expires {
                return Err(SharingError::ShareExpired);
            }
        }

        // Check access count
        if let Some(max) = share.max_access_count {
            if share.access_count >= max {
                return Err(SharingError::AccessLimitReached);
            }
        }

        // Recover symmetric key
        let symmetric_key =
            KeyExchange::recover_shared_secret(&self.own_keypair, &share.encrypted_key)?;

        // Decrypt
        let cipher = Cipher::new(&symmetric_key);
        let decrypted = cipher.decrypt(&share.encrypted_data)?;

        // Deserialize
        let data: ShareData = bincode::deserialize(&decrypted)?;

        Ok(data)
    }

    /// Create an import-ready entry from share data
    pub fn import_from_share(&self, data: &ShareData) -> VaultEntry {
        use crate::models::{CustomField, SensitiveString};

        let mut entry = VaultEntry::new(data.name.clone(), data.entry_type.clone());
        entry.username = data.username.clone();
        entry.password = data.password.as_ref().map(SensitiveString::new);
        entry.url = data.url.clone();
        entry.notes = data.notes.as_ref().map(SensitiveString::new);
        entry.custom_fields = data
            .custom_fields
            .iter()
            .map(|(name, value, hidden)| CustomField {
                name: name.clone(),
                value: SensitiveString::new(value),
                is_hidden: *hidden,
            })
            .collect();
        entry.totp_secret = data.totp_secret.as_ref().map(SensitiveString::new);

        // Add import metadata
        entry.tags.push("imported".to_string());
        entry.tags.push(format!("from:{}", data.sender_name));

        entry
    }

    /// Parse X25519 public key from bytes
    fn parse_public_key(&self, bytes: &[u8]) -> SharingResult<x25519_dalek::PublicKey> {
        if bytes.len() != 32 {
            return Err(SharingError::InvalidShareData);
        }
        let array: [u8; 32] = bytes.try_into().unwrap();
        Ok(x25519_dalek::PublicKey::from(array))
    }

    /// Export identity for sharing (base64 encoded)
    pub fn export_identity(&self) -> String {
        let data = ExportedIdentity {
            name: self.own_identity.name.clone(),
            public_key: self.own_identity.public_key.clone(),
            signing_key: self.own_identity.signing_key.clone(),
            fingerprint: self.own_identity.fingerprint.clone(),
        };

        let json = serde_json::to_string(&data).unwrap();
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json)
    }

    /// Import identity from exported format
    pub fn import_identity(encoded: &str) -> SharingResult<UserIdentity> {
        let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|_| SharingError::InvalidShareData)?;

        let data: ExportedIdentity =
            serde_json::from_slice(&json).map_err(|_| SharingError::InvalidShareData)?;

        Ok(UserIdentity {
            id: Uuid::new_v4(),
            name: data.name,
            email: None,
            public_key: data.public_key,
            signing_key: data.signing_key,
            fingerprint: data.fingerprint,
            created_at: Utc::now(),
            trusted: false, // Not trusted until verified
        })
    }

    /// Create a shareable link (for one-time shares)
    pub fn create_share_link(&self, share: &SharedSecret) -> String {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            share.id.as_bytes(),
        );
        format!("vaultic://share/{}", encoded)
    }

    /// Generate a QR code for sharing
    pub fn generate_share_qr(&self, share: &SharedSecret) -> SharingResult<Vec<u8>> {
        use image::ImageEncoder;
        use image::Luma;
        use qrcode::QrCode;

        let link = self.create_share_link(share);
        let code = QrCode::new(link.as_bytes()).map_err(|_| SharingError::InvalidShareData)?;

        let image = code.render::<Luma<u8>>().build();

        let mut png_bytes = Vec::new();
        let encoder = image::codecs::png::PngEncoder::new(&mut png_bytes);
        encoder
            .write_image(
                image.as_raw(),
                image.width(),
                image.height(),
                image::ExtendedColorType::L8,
            )
            .map_err(|_| SharingError::InvalidShareData)?;

        Ok(png_bytes)
    }
}

/// Data included in a share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareData {
    pub entry_id: Uuid,
    pub name: String,
    pub entry_type: crate::models::EntryType,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub custom_fields: Vec<(String, String, bool)>,
    pub totp_secret: Option<String>,
    pub shared_at: DateTime<Utc>,
    pub sender_name: String,
}

/// Exported identity format
#[derive(Debug, Serialize, Deserialize)]
struct ExportedIdentity {
    name: String,
    public_key: Vec<u8>,
    signing_key: Vec<u8>,
    fingerprint: String,
}

/// Share invitation (for UI display)
#[derive(Debug, Clone)]
pub struct ShareInvitation {
    pub share_id: Uuid,
    pub sender_name: String,
    pub sender_fingerprint: String,
    pub entry_name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub one_time: bool,
}

impl ShareInvitation {
    /// Check if invitation is still valid
    pub fn is_valid(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() <= expires
        } else {
            true
        }
    }

    /// Get human-readable expiration
    pub fn expiration_text(&self) -> String {
        match self.expires_at {
            None => "Never".to_string(),
            Some(expires) => {
                let remaining = expires - Utc::now();
                if remaining.num_days() > 0 {
                    format!("{} days", remaining.num_days())
                } else if remaining.num_hours() > 0 {
                    format!("{} hours", remaining.num_hours())
                } else if remaining.num_minutes() > 0 {
                    format!("{} minutes", remaining.num_minutes())
                } else {
                    "Expired".to_string()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EntryType;

    #[test]
    fn test_share_roundtrip() {
        // Create two identities
        let alice_keypair = IdentityKeyPair::generate();
        let bob_keypair = IdentityKeyPair::generate();

        let alice = SharingManager::new(alice_keypair, "Alice".to_string());
        let bob = SharingManager::new(bob_keypair, "Bob".to_string());

        // Alice creates an entry
        let entry = VaultEntry::new("GitHub", EntryType::Password)
            .with_username("alice@github.com")
            .with_password("super_secret_password");

        // Alice shares with Bob
        let share = alice
            .create_share(&entry, bob.own_identity(), false, Some(24), None)
            .unwrap();

        // Bob opens the share
        let data = bob.open_share(&share).unwrap();

        assert_eq!(data.name, "GitHub");
        assert_eq!(data.username, Some("alice@github.com".to_string()));
        assert_eq!(data.password, Some("super_secret_password".to_string()));
        assert_eq!(data.sender_name, "Alice");
    }

    #[test]
    fn test_share_expiration() {
        let alice_keypair = IdentityKeyPair::generate();
        let bob_keypair = IdentityKeyPair::generate();

        let alice = SharingManager::new(alice_keypair, "Alice".to_string());
        let bob = SharingManager::new(bob_keypair, "Bob".to_string());

        let entry = VaultEntry::new("Test", EntryType::Password);

        // Create already-expired share
        let mut share = alice
            .create_share(&entry, bob.own_identity(), false, Some(0), None)
            .unwrap();
        share.expires_at = Some(Utc::now() - Duration::hours(1));

        // Should fail to open
        let result = bob.open_share(&share);
        assert!(matches!(result, Err(SharingError::ShareExpired)));
    }

    #[test]
    fn test_identity_export_import() {
        let keypair = IdentityKeyPair::generate();
        let manager = SharingManager::new(keypair, "Test".to_string());

        let exported = manager.export_identity();
        let imported = SharingManager::import_identity(&exported).unwrap();

        assert_eq!(imported.name, "Test");
        assert_eq!(imported.fingerprint, manager.own_identity().fingerprint);
    }
}
