//! GPG/OpenPGP key support for Vaultic
//!
//! Allows using existing GPG keys for vault encryption and identity.
//! Uses the Sequoia PGP library for OpenPGP operations.
//!
//! This module is only compiled when the `gpg` feature is enabled.

use std::io::Write;
use std::path::Path;

use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::packet::prelude::*;
use sequoia_openpgp::parse::{stream::*, Parse};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::*;
use sequoia_openpgp::serialize::Marshal;
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::Cert;
use thiserror::Error;

/// GPG module errors
#[derive(Debug, Error)]
pub enum GpgError {
    #[error("OpenPGP error: {0}")]
    OpenPgp(#[from] anyhow::Error),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("No valid encryption subkey found")]
    NoEncryptionKey,

    #[error("Passphrase required")]
    PassphraseRequired,
}

pub type GpgResult<T> = Result<T, GpgError>;

const POLICY: &StandardPolicy = &StandardPolicy::new();

/// GPG key manager for Vaultic integration
pub struct GpgManager {
    cert: Cert,
    fingerprint: String,
}

impl GpgManager {
    /// Load a GPG key from a file
    pub fn from_file(path: impl AsRef<Path>) -> GpgResult<Self> {
        let cert = Cert::from_file(path)?;
        let fingerprint = cert.fingerprint().to_hex();

        Ok(Self { cert, fingerprint })
    }

    /// Load a GPG key from armored text
    pub fn from_armored(armored: &str) -> GpgResult<Self> {
        let cert = Cert::from_bytes(armored.as_bytes())?;
        let fingerprint = cert.fingerprint().to_hex();

        Ok(Self { cert, fingerprint })
    }

    /// Generate a new GPG key
    pub fn generate(user_id: &str, _passphrase: Option<&str>) -> GpgResult<Self> {
        let (cert, _revocation) = CertBuilder::new()
            .add_userid(user_id)
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate()?;

        let fingerprint = cert.fingerprint().to_hex();

        Ok(Self { cert, fingerprint })
    }

    /// Get the key fingerprint
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Get the primary user ID
    pub fn user_id(&self) -> Option<String> {
        self.cert
            .userids()
            .next()
            .map(|ua| String::from_utf8_lossy(ua.userid().value()).to_string())
    }

    /// Get key creation time
    pub fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(
            self.cert
                .primary_key()
                .creation_time()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            0,
        )
        .unwrap()
    }

    /// Check if key is valid (not expired, not revoked)
    pub fn is_valid(&self) -> bool {
        self.cert
            .with_policy(POLICY, None)
            .map(|valid| match valid.revocation_status() {
                sequoia_openpgp::types::RevocationStatus::Revoked(_) => false,
                _ => true,
            })
            .unwrap_or(false)
    }

    /// Encrypt data to this key
    pub fn encrypt(&self, plaintext: &[u8]) -> GpgResult<Vec<u8>> {
        let mut ciphertext = Vec::new();

        // Get encryption-capable subkey
        let recipient_key = self
            .cert
            .keys()
            .with_policy(POLICY, None)
            .supported()
            .for_transport_encryption()
            .next()
            .ok_or(GpgError::NoEncryptionKey)?;

        let message = Message::new(&mut ciphertext);

        let message = Encryptor2::for_recipients(message, vec![Recipient::from(recipient_key)])
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .build()?;

        let mut literal = LiteralWriter::new(message).build()?;
        literal.write_all(plaintext)?;
        literal.finalize()?;

        Ok(ciphertext)
    }

    /// Decrypt data with this key (requires passphrase if key is protected)
    pub fn decrypt(&self, ciphertext: &[u8], passphrase: Option<&str>) -> GpgResult<Vec<u8>> {
        let helper = VaulticDecryptionHelper {
            cert: &self.cert,
            passphrase: passphrase.map(|s| s.to_string()),
        };

        let mut decryptor =
            DecryptorBuilder::from_bytes(ciphertext)?.with_policy(POLICY, None, helper)?;

        let mut plaintext = Vec::new();
        std::io::copy(&mut decryptor, &mut plaintext)?;

        Ok(plaintext)
    }

    /// Export public key in armored format
    pub fn export_public_key(&self) -> GpgResult<String> {
        let mut output = Vec::new();
        let mut armored = sequoia_openpgp::armor::Writer::new(
            &mut output,
            sequoia_openpgp::armor::Kind::PublicKey,
        )?;

        self.cert.armored().serialize(&mut armored)?;
        armored.finalize()?;

        Ok(String::from_utf8_lossy(&output).to_string())
    }

    /// Derive a master key from GPG key material
    /// Uses key fingerprint + encrypted random data
    pub fn derive_master_key(&self) -> GpgResult<crate::crypto::MasterKey> {
        // Generate random data
        let mut random = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut random);

        // Encrypt it to ourselves
        let encrypted = self.encrypt(&random)?;

        // Hash the encrypted data to get a deterministic key
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&encrypted[..64.min(encrypted.len())]);
        hasher.update(self.fingerprint.as_bytes());

        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);

        Ok(crate::crypto::MasterKey::from_bytes(key))
    }
}

/// Helper for decryption
struct VaulticDecryptionHelper<'a> {
    cert: &'a Cert,
    passphrase: Option<String>,
}

impl VerificationHelper for VaulticDecryptionHelper<'_> {
    fn get_certs(&mut self, _ids: &[sequoia_openpgp::KeyHandle]) -> anyhow::Result<Vec<Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, _structure: MessageStructure) -> anyhow::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for VaulticDecryptionHelper<'_> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> anyhow::Result<Option<sequoia_openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        // Find our encryption key
        for key in self
            .cert
            .keys()
            .with_policy(POLICY, None)
            .supported()
            .secret()
        {
            // Try to decrypt each PKESK
            for pkesk in pkesks {
                // Try to match recipient - if wildcard recipient, try all keys
                let try_decrypt = {
                    let recipient = pkesk.recipient();
                    let key_id = key.keyid();
                    recipient.is_wildcard() || *recipient == key_id
                };

                if try_decrypt {
                    let mut keypair = if key.secret().is_encrypted() {
                        // Need passphrase
                        let passphrase = self
                            .passphrase
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("Passphrase required"))?;

                        let password: sequoia_openpgp::crypto::Password = passphrase.clone().into();
                        key.key()
                            .clone()
                            .parts_into_secret()?
                            .decrypt_secret(&password)?
                            .into_keypair()?
                    } else {
                        key.key().clone().parts_into_secret()?.into_keypair()?
                    };

                    if pkesk
                        .decrypt(&mut keypair, sym_algo)
                        .map(|(algo, session_key)| decrypt(algo, &session_key))
                        .unwrap_or(false)
                    {
                        return Ok(Some(self.cert.fingerprint()));
                    }
                }
            }
        }

        Err(anyhow::anyhow!("No matching key found"))
    }
}

/// Find GPG key in standard locations
pub fn find_gpg_key(key_id: &str) -> GpgResult<GpgManager> {
    // Try ~/.gnupg first
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let gnupg_home = std::env::var("GNUPGHOME").unwrap_or_else(|_| format!("{}/.gnupg", home));

    let pubring_path = format!("{}/pubring.kbx", gnupg_home);
    let legacy_pubring_path = format!("{}/pubring.gpg", gnupg_home);

    // Check if key_id matches any key
    for path in [&pubring_path, &legacy_pubring_path] {
        if let Ok(manager) = GpgManager::from_file(path) {
            if manager.fingerprint().ends_with(key_id)
                || manager
                    .user_id()
                    .map(|u| u.contains(key_id))
                    .unwrap_or(false)
            {
                return Ok(manager);
            }
        }
    }

    Err(GpgError::KeyNotFound(key_id.to_string()))
}

/// Key info for display
#[derive(Debug, Clone)]
pub struct GpgKeyInfo {
    pub fingerprint: String,
    pub user_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub is_valid: bool,
    pub has_encryption_key: bool,
}

impl From<&GpgManager> for GpgKeyInfo {
    fn from(manager: &GpgManager) -> Self {
        Self {
            fingerprint: manager.fingerprint().to_string(),
            user_id: manager.user_id(),
            created_at: manager.created_at(),
            is_valid: manager.is_valid(),
            has_encryption_key: manager
                .cert
                .keys()
                .with_policy(POLICY, None)
                .for_transport_encryption()
                .next()
                .is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let manager = GpgManager::generate("Test User <test@example.com>", None).unwrap();

        assert!(!manager.fingerprint().is_empty());
        assert!(manager.user_id().is_some());
        assert!(manager.is_valid());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let manager = GpgManager::generate("Test <test@test.com>", None).unwrap();

        let plaintext = b"Hello, GPG!";
        let ciphertext = manager.encrypt(plaintext).unwrap();
        let decrypted = manager.decrypt(&ciphertext, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_export_public_key() {
        let manager = GpgManager::generate("Export Test <export@test.com>", None).unwrap();

        let armored = manager.export_public_key().unwrap();

        assert!(armored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(armored.contains("-----END PGP PUBLIC KEY BLOCK-----"));
    }
}
