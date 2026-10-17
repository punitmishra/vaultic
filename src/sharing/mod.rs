//! Secure password sharing functionality
//!
//! Uses asymmetric encryption (X25519 + XChaCha20-Poly1305) for
//! end-to-end encrypted sharing between users.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::crypto::{
    fingerprint_from_public_keys, Cipher, CryptoError, IdentityKeyPair, KeyExchange,
    SignatureVerifier,
};
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

    #[error("Sender verification failed: share is forged, tampered, or the sender key does not match its fingerprint")]
    SenderVerificationFailed,
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

        // Authenticate the share: sign a transcript binding the ephemeral DH
        // public key, the recipient's fingerprint, and the ciphertext with the
        // sender's Ed25519 identity key. Without this, anyone holding the
        // recipient's public key could forge a share claiming any sender.
        let transcript =
            build_share_transcript(&ephemeral_public, &recipient.fingerprint, &encrypted_data);
        let signature = self.own_keypair.sign(&transcript);

        // Calculate expiration
        let expires_at = expires_hours.map(|h| Utc::now() + Duration::hours(h as i64));

        Ok(SharedSecret {
            id: Uuid::new_v4(),
            entry_id: entry.id,
            encrypted_data,
            encrypted_key: ephemeral_public,
            sender_fingerprint: self.own_identity.fingerprint.clone(),
            recipient_fingerprint: recipient.fingerprint.clone(),
            sender_signing_key: self.own_keypair.signing_public_key().as_bytes().to_vec(),
            sender_exchange_key: self.own_keypair.exchange_public_key().as_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
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

        // Verify sender authenticity before doing any decryption work.
        // TOFU / self-verifying: the share carries the sender's public keys,
        // and we (a) confirm they recompute to the claimed `sender_fingerprint`
        // and (b) verify the signature over the transcript with them. This
        // rejects a forged sender, a substituted key, and a tampered ciphertext
        // without requiring the sender be pre-added to a trust store.
        self.verify_sender(share)?;

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

    /// Verify that `share` was authored by the holder of the private key behind
    /// `share.sender_fingerprint`.
    ///
    /// Two independent bindings must both hold, or the share is rejected with
    /// [`SharingError::SenderVerificationFailed`]:
    /// 1. The carried public keys recompute to `share.sender_fingerprint`
    ///    (binds the keys to the claimed identity).
    /// 2. The signature verifies against the carried signing key over the
    ///    transcript `ephemeral_public ‖ recipient_fingerprint ‖ ciphertext`
    ///    (binds the sender to *this* share, recipient, and ciphertext).
    fn verify_sender(&self, share: &SharedSecret) -> SharingResult<()> {
        // Parse the carried Ed25519 verifying key (32 bytes).
        let signing_bytes: [u8; 32] = share
            .sender_signing_key
            .as_slice()
            .try_into()
            .map_err(|_| SharingError::SenderVerificationFailed)?;
        let verifying_key = VerifyingKey::from_bytes(&signing_bytes)
            .map_err(|_| SharingError::SenderVerificationFailed)?;

        // The exchange key must be 32 bytes to recompute the fingerprint.
        if share.sender_exchange_key.len() != 32 {
            return Err(SharingError::SenderVerificationFailed);
        }

        // (1) Bind the carried keys to the claimed identity fingerprint.
        let recomputed =
            fingerprint_from_public_keys(&share.sender_signing_key, &share.sender_exchange_key);
        if recomputed != share.sender_fingerprint {
            return Err(SharingError::SenderVerificationFailed);
        }

        // Parse the signature (64 bytes).
        let sig_bytes: [u8; 64] = share
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| SharingError::SenderVerificationFailed)?;
        let signature = Signature::from_bytes(&sig_bytes);

        // (2) Verify the signature over the exact transcript the sender signed.
        let transcript = build_share_transcript(
            &share.encrypted_key,
            &share.recipient_fingerprint,
            &share.encrypted_data,
        );
        SignatureVerifier::verify(&verifying_key, &transcript, &signature)
            .map_err(|_| SharingError::SenderVerificationFailed)?;

        Ok(())
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

/// Build the signed transcript that binds a share to its sender, recipient,
/// and ciphertext: a domain separator followed by the length-prefixed
/// `ephemeral_public`, `recipient_fingerprint`, and `ciphertext`.
///
/// Length-prefixing makes the encoding unambiguous, so no combination of
/// component values can collide with a different one — a defensive property
/// even though only the trailing ciphertext is currently variable-length.
fn build_share_transcript(
    ephemeral_public: &[u8],
    recipient_fingerprint: &str,
    ciphertext: &[u8],
) -> Vec<u8> {
    let fp = recipient_fingerprint.as_bytes();
    let mut transcript =
        Vec::with_capacity(16 + 24 + ephemeral_public.len() + fp.len() + ciphertext.len());
    transcript.extend_from_slice(b"vaultic-share-v1");
    transcript.extend_from_slice(&(ephemeral_public.len() as u64).to_le_bytes());
    transcript.extend_from_slice(ephemeral_public);
    transcript.extend_from_slice(&(fp.len() as u64).to_le_bytes());
    transcript.extend_from_slice(fp);
    transcript.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    transcript.extend_from_slice(ciphertext);
    transcript
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

    #[test]
    fn test_share_carries_and_verifies_sender_authenticity() {
        // A clean roundtrip carries real signing/exchange keys and a 64-byte
        // signature, the claimed fingerprint is the sender's, and open_share
        // accepts it (authenticity verified end to end).
        let alice = SharingManager::new(IdentityKeyPair::generate(), "Alice".to_string());
        let bob = SharingManager::new(IdentityKeyPair::generate(), "Bob".to_string());

        let entry = VaultEntry::new("GitHub", EntryType::Password).with_password("s3cret");

        let share = alice
            .create_share(&entry, bob.own_identity(), false, None, None)
            .unwrap();

        assert_eq!(share.sender_signing_key.len(), 32);
        assert_eq!(share.sender_exchange_key.len(), 32);
        assert_eq!(share.signature.len(), 64);
        assert_eq!(share.sender_fingerprint, alice.fingerprint());

        assert!(bob.open_share(&share).is_ok());
    }

    #[test]
    fn test_forged_signature_rejected() {
        let alice = SharingManager::new(IdentityKeyPair::generate(), "Alice".to_string());
        let bob = SharingManager::new(IdentityKeyPair::generate(), "Bob".to_string());
        let entry = VaultEntry::new("Test", EntryType::Password).with_password("pw");

        let mut share = alice
            .create_share(&entry, bob.own_identity(), false, None, None)
            .unwrap();

        // Flip a signature byte: keys still match the fingerprint, but the
        // signature no longer verifies over the transcript.
        share.signature[0] ^= 0xFF;

        assert!(matches!(
            bob.open_share(&share),
            Err(SharingError::SenderVerificationFailed)
        ));
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let alice = SharingManager::new(IdentityKeyPair::generate(), "Alice".to_string());
        let bob = SharingManager::new(IdentityKeyPair::generate(), "Bob".to_string());
        let entry = VaultEntry::new("Test", EntryType::Password).with_password("pw");

        let mut share = alice
            .create_share(&entry, bob.own_identity(), false, None, None)
            .unwrap();

        // Tampering with the ciphertext breaks the signed transcript, so the
        // forgery is caught before decryption is attempted.
        share.encrypted_data[0] ^= 0xFF;

        assert!(matches!(
            bob.open_share(&share),
            Err(SharingError::SenderVerificationFailed)
        ));
    }

    #[test]
    fn test_substituted_sender_key_rejected() {
        // An attacker swaps in a different signing key but leaves the claimed
        // fingerprint alone. The carried keys no longer recompute to that
        // fingerprint, so the key↔identity binding fails.
        let alice = SharingManager::new(IdentityKeyPair::generate(), "Alice".to_string());
        let bob = SharingManager::new(IdentityKeyPair::generate(), "Bob".to_string());
        let mallory = SharingManager::new(IdentityKeyPair::generate(), "Mallory".to_string());
        let entry = VaultEntry::new("Test", EntryType::Password).with_password("pw");

        let mut share = alice
            .create_share(&entry, bob.own_identity(), false, None, None)
            .unwrap();

        share.sender_signing_key = mallory.own_identity().signing_key.clone();

        assert!(matches!(
            bob.open_share(&share),
            Err(SharingError::SenderVerificationFailed)
        ));
    }

    #[test]
    fn test_forged_sender_identity_rejected() {
        // Mallory creates a correctly-signed share of her own, then rewrites
        // the claimed sender fingerprint to impersonate Alice. Her carried keys
        // recompute to *her* fingerprint, not Alice's, so it is rejected.
        let bob = SharingManager::new(IdentityKeyPair::generate(), "Bob".to_string());
        let mallory = SharingManager::new(IdentityKeyPair::generate(), "Mallory".to_string());
        let alice = SharingManager::new(IdentityKeyPair::generate(), "Alice".to_string());
        let entry = VaultEntry::new("Test", EntryType::Password).with_password("pw");

        let mut share = mallory
            .create_share(&entry, bob.own_identity(), false, None, None)
            .unwrap();
        share.sender_fingerprint = alice.fingerprint().to_string();

        assert!(matches!(
            bob.open_share(&share),
            Err(SharingError::SenderVerificationFailed)
        ));
    }
}
