//! Recovery key module for BIP39 mnemonic-based vault recovery
//!
//! This module provides:
//! - BIP39 24-word mnemonic generation
//! - Seed derivation from mnemonic
//! - QR code display for backup
//! - Recovery key verification
//!
//! The recovery key serves as a backup unlock method that can restore
//! access to a vault if the primary password is lost.

use bip39::{Language, Mnemonic};
use qrcode::QrCode;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::kek::derive_from_recovery_seed;
use crate::crypto::keys::{
    EncryptedVaultKey, KeyEncryptionKey, MethodData, UnlockMethod, VaultKey,
};
use crate::crypto::wrap::{generate_salt, wrap_vault_key};
use crate::crypto::CryptoError;

/// Recovery key data containing the mnemonic and derived values
#[derive(Clone)]
pub struct RecoveryKey {
    /// The 24-word BIP39 mnemonic
    mnemonic: Mnemonic,
    /// Derived 64-byte seed
    seed: [u8; 64],
}

impl RecoveryKey {
    /// Generate a new random recovery key with 24 words (256 bits of entropy)
    pub fn generate() -> Result<Self, CryptoError> {
        // Generate 256 bits of entropy for 24-word mnemonic
        let mut entropy = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| {
            CryptoError::KeyDerivationFailed(format!("Failed to generate mnemonic: {}", e))
        })?;

        // Derive seed using empty passphrase (standard BIP39)
        let seed_bytes = mnemonic.to_seed("");
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&seed_bytes);

        Ok(Self { mnemonic, seed })
    }

    /// Create a recovery key from an existing mnemonic phrase
    pub fn from_phrase(phrase: &str) -> Result<Self, CryptoError> {
        let mnemonic = Mnemonic::parse_normalized(phrase).map_err(|e| {
            CryptoError::KeyDerivationFailed(format!("Invalid mnemonic phrase: {}", e))
        })?;

        let seed_bytes = mnemonic.to_seed("");
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&seed_bytes);

        Ok(Self { mnemonic, seed })
    }

    /// Get the mnemonic words as a string
    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Get the mnemonic words as a vector
    pub fn words(&self) -> Vec<&'static str> {
        self.mnemonic.words().collect()
    }

    /// Get the raw seed bytes for key derivation
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }

    /// Derive a KEK from this recovery key with a salt
    pub fn derive_kek(&self, salt: &[u8]) -> Result<KeyEncryptionKey, CryptoError> {
        derive_from_recovery_seed(&self.seed, salt)
    }

    /// Generate a fingerprint (first 4 words) for identification
    /// This allows identifying the recovery key without exposing the full phrase
    pub fn fingerprint(&self) -> String {
        let words: Vec<&str> = self.mnemonic.words().take(4).collect();
        words.join(" ")
    }

    /// Generate a checksum of the full phrase for verification
    pub fn checksum(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.mnemonic.to_string().as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..4])
    }

    /// Wrap a vault key with this recovery key
    pub fn wrap_vault_key(
        &self,
        vault_key: &VaultKey,
        label: Option<String>,
    ) -> Result<(EncryptedVaultKey, Vec<u8>), CryptoError> {
        let salt = generate_salt();
        let kek = self.derive_kek(&salt)?;

        let encrypted = wrap_vault_key(
            vault_key,
            &kek,
            UnlockMethod::RecoveryKey,
            MethodData::Recovery {
                salt: salt.clone(),
                fingerprint: self.fingerprint(),
            },
            label,
        )?;

        Ok((encrypted, salt))
    }

    /// Display the recovery key in a formatted manner for backup
    pub fn display_formatted(&self) -> String {
        let words: Vec<&str> = self.words();
        let mut output = String::new();

        output.push_str("╔══════════════════════════════════════════════════════════╗\n");
        output.push_str("║                   RECOVERY KEY                           ║\n");
        output.push_str("║    Write down these 24 words and store them safely!      ║\n");
        output.push_str("╠══════════════════════════════════════════════════════════╣\n");

        // Display words in 4 columns of 6 words each
        for row in 0..6 {
            output.push_str("║  ");
            for col in 0..4 {
                let idx = row + col * 6;
                let word = words[idx];
                let num = idx + 1;
                output.push_str(&format!("{:2}. {:<12}", num, word));
            }
            output.push_str("  ║\n");
        }

        output.push_str("╠══════════════════════════════════════════════════════════╣\n");
        output.push_str(&format!(
            "║  Checksum: {}                                          ║\n",
            self.checksum()
        ));
        output.push_str("╚══════════════════════════════════════════════════════════╝\n");

        output
    }

    /// Generate a QR code containing the recovery phrase
    /// Returns a string representation for terminal display
    pub fn generate_qr(&self) -> Result<String, CryptoError> {
        let code = QrCode::new(self.phrase().as_bytes()).map_err(|e| {
            CryptoError::KeyDerivationFailed(format!("Failed to generate QR code: {}", e))
        })?;

        Ok(render_qr_to_terminal(&code))
    }
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        // Securely zero the seed on drop
        self.seed.zeroize();
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryKey")
            .field("fingerprint", &self.fingerprint())
            .field("mnemonic", &"[REDACTED]")
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

/// Render a QR code to terminal-friendly string using Unicode block characters
fn render_qr_to_terminal(code: &QrCode) -> String {
    let colors = code.to_colors();
    let width = code.width();
    let mut output = String::new();

    // Add quiet zone (required for QR code scanning)
    let quiet_zone = 2;

    // Top quiet zone
    for _ in 0..quiet_zone {
        for _ in 0..(width + quiet_zone * 2) {
            output.push_str("██");
        }
        output.push('\n');
    }

    // Process two rows at a time to use half-block characters
    for y in (0..colors.len()).step_by(width * 2) {
        // Left quiet zone
        for _ in 0..quiet_zone {
            output.push_str("██");
        }

        for x in 0..width {
            let top_idx = y + x;
            let bottom_idx = y + width + x;

            let top = if top_idx < colors.len() {
                colors[top_idx] == qrcode::Color::Light
            } else {
                true // Default to light (white)
            };

            let bottom = if bottom_idx < colors.len() {
                colors[bottom_idx] == qrcode::Color::Light
            } else {
                true // Default to light (white)
            };

            let char = match (top, bottom) {
                (true, true) => "██",   // Both white
                (true, false) => "▀▀",  // Top white, bottom black
                (false, true) => "▄▄",  // Top black, bottom white
                (false, false) => "  ", // Both black
            };
            output.push_str(char);
        }

        // Right quiet zone
        for _ in 0..quiet_zone {
            output.push_str("██");
        }
        output.push('\n');
    }

    // Bottom quiet zone
    for _ in 0..quiet_zone {
        for _ in 0..(width + quiet_zone * 2) {
            output.push_str("██");
        }
        output.push('\n');
    }

    output
}

/// Validate a mnemonic phrase without creating a full RecoveryKey
pub fn validate_phrase(phrase: &str) -> bool {
    Mnemonic::parse_normalized(phrase).is_ok()
}

/// Get word suggestions for a partial word (for autocomplete)
pub fn suggest_words(partial: &str) -> Vec<&'static str> {
    let wordlist = Language::English.word_list();
    wordlist
        .iter()
        .filter(|w| w.starts_with(partial))
        .take(10)
        .copied()
        .collect()
}

/// Verify a recovery phrase matches a stored fingerprint
pub fn verify_fingerprint(phrase: &str, expected_fingerprint: &str) -> bool {
    if let Ok(recovery_key) = RecoveryKey::from_phrase(phrase) {
        recovery_key.fingerprint() == expected_fingerprint
    } else {
        false
    }
}

// Re-export hex for checksum display
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_key_generation() {
        let key = RecoveryKey::generate().unwrap();

        // Should have 24 words
        assert_eq!(key.words().len(), 24);

        // Fingerprint should be first 4 words
        let words = key.words();
        let expected_fp = format!("{} {} {} {}", words[0], words[1], words[2], words[3]);
        assert_eq!(key.fingerprint(), expected_fp);
    }

    #[test]
    fn test_recovery_key_from_phrase() {
        // Use a valid test mnemonic
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let key = RecoveryKey::from_phrase(phrase).unwrap();
        assert_eq!(key.phrase(), phrase);
    }

    #[test]
    fn test_invalid_phrase_rejected() {
        let result = RecoveryKey::from_phrase("invalid mnemonic phrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_recovery_key_derive_kek() {
        let key = RecoveryKey::generate().unwrap();
        let salt = generate_salt();

        let kek1 = key.derive_kek(&salt).unwrap();
        let kek2 = key.derive_kek(&salt).unwrap();

        // Same key + salt should produce same KEK
        assert_eq!(kek1.expose(), kek2.expose());
    }

    #[test]
    fn test_different_salts_produce_different_keks() {
        let key = RecoveryKey::generate().unwrap();
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        let kek1 = key.derive_kek(&salt1).unwrap();
        let kek2 = key.derive_kek(&salt2).unwrap();

        // Different salts should produce different KEKs
        assert_ne!(kek1.expose(), kek2.expose());
    }

    #[test]
    fn test_wrap_vault_key() {
        let recovery_key = RecoveryKey::generate().unwrap();
        let vault_key = VaultKey::generate();

        let (encrypted, salt) = recovery_key
            .wrap_vault_key(&vault_key, Some("Test Recovery".to_string()))
            .unwrap();

        assert_eq!(encrypted.method, UnlockMethod::RecoveryKey);
        assert_eq!(encrypted.label, Some("Test Recovery".to_string()));
        assert!(!salt.is_empty());
    }

    #[test]
    fn test_validate_phrase() {
        let key = RecoveryKey::generate().unwrap();
        assert!(validate_phrase(&key.phrase()));
        assert!(!validate_phrase("invalid phrase"));
    }

    #[test]
    fn test_suggest_words() {
        let suggestions = suggest_words("aban");
        assert!(suggestions.contains(&"abandon"));
    }

    #[test]
    fn test_verify_fingerprint() {
        let key = RecoveryKey::generate().unwrap();
        let fingerprint = key.fingerprint();

        assert!(verify_fingerprint(&key.phrase(), &fingerprint));
        assert!(!verify_fingerprint(&key.phrase(), "wrong fingerprint"));
    }

    #[test]
    fn test_checksum() {
        let key = RecoveryKey::generate().unwrap();
        let checksum = key.checksum();

        // Checksum should be 8 hex characters (4 bytes)
        assert_eq!(checksum.len(), 8);

        // Same phrase should produce same checksum
        let key2 = RecoveryKey::from_phrase(&key.phrase()).unwrap();
        assert_eq!(key.checksum(), key2.checksum());
    }

    #[test]
    fn test_display_formatted() {
        let key = RecoveryKey::generate().unwrap();
        let display = key.display_formatted();

        // Should contain all 24 words
        for word in key.words() {
            assert!(display.contains(word));
        }

        // Should contain checksum
        assert!(display.contains(&key.checksum()));
    }

    #[test]
    fn test_qr_generation() {
        let key = RecoveryKey::generate().unwrap();
        let qr = key.generate_qr().unwrap();

        // QR should not be empty
        assert!(!qr.is_empty());

        // Should contain block characters
        assert!(qr.contains('█') || qr.contains('▀') || qr.contains('▄'));
    }

    #[test]
    fn test_recovery_key_debug_redacts() {
        let key = RecoveryKey::generate().unwrap();
        let debug = format!("{:?}", key);

        // Should NOT contain the full phrase
        assert!(
            !debug.contains(&key.phrase()),
            "Debug output contains full mnemonic phrase"
        );

        // Should contain fingerprint (first 4 words are OK to show for identification)
        assert!(debug.contains(&key.fingerprint()));

        // Should contain [REDACTED] markers
        assert!(debug.contains("[REDACTED]"));

        // Verify the debug output has the expected struct format
        assert!(debug.contains("RecoveryKey"));
    }
}
