//! Key wrapping and unwrapping operations
//!
//! This module provides functions to wrap (encrypt) and unwrap (decrypt)
//! the VaultKey using a KeyEncryptionKey. Uses XChaCha20-Poly1305 for
//! authenticated encryption.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use chrono::Utc;
use rand::RngCore;

use super::keys::{EncryptedVaultKey, KeyEncryptionKey, MethodData, UnlockMethod, VaultKey};
use super::CryptoError;

/// Wrap a VaultKey with a KeyEncryptionKey
///
/// # Arguments
/// * `vault_key` - The VaultKey to encrypt
/// * `kek` - The KeyEncryptionKey to encrypt with
/// * `method` - The unlock method type
/// * `method_data` - Method-specific data for key derivation
/// * `label` - Optional user-friendly label
///
/// # Returns
/// An EncryptedVaultKey containing the encrypted VaultKey and metadata
pub fn wrap_vault_key(
    vault_key: &VaultKey,
    kek: &KeyEncryptionKey,
    method: UnlockMethod,
    method_data: MethodData,
    label: Option<String>,
) -> Result<EncryptedVaultKey, CryptoError> {
    let cipher = XChaCha20Poly1305::new(kek.expose().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, vault_key.as_bytes())
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(&nonce);

    Ok(EncryptedVaultKey::new(
        method,
        ciphertext,
        nonce_array,
        method_data,
        label,
    ))
}

/// Unwrap a VaultKey using a KeyEncryptionKey
///
/// # Arguments
/// * `encrypted` - The EncryptedVaultKey to decrypt
/// * `kek` - The KeyEncryptionKey to decrypt with
///
/// # Returns
/// The decrypted VaultKey
pub fn unwrap_vault_key(
    encrypted: &EncryptedVaultKey,
    kek: &KeyEncryptionKey,
) -> Result<VaultKey, CryptoError> {
    let cipher = XChaCha20Poly1305::new(kek.expose().into());
    let nonce = XNonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed("Invalid key or corrupted data".to_string()))?;

    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: plaintext.len(),
        });
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&plaintext);
    Ok(VaultKey::from_bytes(key_bytes))
}

/// Re-wrap a VaultKey with a new KEK (for adding new unlock methods)
///
/// # Arguments
/// * `vault_key` - The VaultKey to wrap
/// * `new_kek` - The new KeyEncryptionKey to wrap with
/// * `method` - The new unlock method type
/// * `method_data` - Method-specific data for the new method
/// * `label` - Optional label for the new method
///
/// # Returns
/// A new EncryptedVaultKey for the new method
pub fn rewrap_vault_key(
    vault_key: &VaultKey,
    new_kek: &KeyEncryptionKey,
    method: UnlockMethod,
    method_data: MethodData,
    label: Option<String>,
) -> Result<EncryptedVaultKey, CryptoError> {
    wrap_vault_key(vault_key, new_kek, method, method_data, label)
}

/// Generate a random salt for key derivation
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random challenge for hardware key authentication
pub fn generate_challenge() -> Vec<u8> {
    let mut challenge = vec![0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    challenge
}

/// Helper to update the last_used timestamp on an encrypted key
pub fn mark_key_used(encrypted: &mut EncryptedVaultKey) {
    encrypted.last_used = Some(Utc::now());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kek::derive_from_password;
    use crate::crypto::KeyDeriver;
    use crate::models::KdfParams;

    fn create_test_kek() -> (KeyEncryptionKey, KdfParams) {
        let params = KeyDeriver::generate_params();
        let kek = derive_from_password(b"test password", &params).unwrap();
        (kek, params)
    }

    #[test]
    fn test_wrap_unwrap_vault_key() {
        let vault_key = VaultKey::generate();
        let (kek, params) = create_test_kek();

        let method_data = MethodData::Password {
            params: params.clone(),
        };

        let encrypted = wrap_vault_key(
            &vault_key,
            &kek,
            UnlockMethod::Password,
            method_data,
            Some("Test".to_string()),
        )
        .unwrap();

        // Verify encrypted key has expected structure
        assert_eq!(encrypted.method, UnlockMethod::Password);
        assert_eq!(encrypted.ciphertext.len(), 32 + 16); // VaultKey + Poly1305 tag
        assert_eq!(encrypted.label, Some("Test".to_string()));

        // Unwrap and verify
        let unwrapped = unwrap_vault_key(&encrypted, &kek).unwrap();
        assert_eq!(unwrapped.expose(), vault_key.expose());
    }

    #[test]
    fn test_unwrap_with_wrong_kek_fails() {
        let vault_key = VaultKey::generate();
        let (kek1, params1) = create_test_kek();

        let method_data = MethodData::Password {
            params: params1.clone(),
        };

        let encrypted =
            wrap_vault_key(&vault_key, &kek1, UnlockMethod::Password, method_data, None).unwrap();

        // Try to unwrap with different KEK
        let params2 = KeyDeriver::generate_params();
        let kek2 = derive_from_password(b"wrong password", &params2).unwrap();

        let result = unwrap_vault_key(&encrypted, &kek2);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_unlock_methods() {
        let vault_key = VaultKey::generate();

        // Create password KEK
        let password_params = KeyDeriver::generate_params();
        let password_kek = derive_from_password(b"password123", &password_params).unwrap();

        // Create recovery KEK (simulated)
        let recovery_seed = [0x42u8; 64];
        let recovery_salt = generate_salt();
        let recovery_kek =
            crate::crypto::kek::derive_from_recovery_seed(&recovery_seed, &recovery_salt).unwrap();

        // Wrap with password
        let password_encrypted = wrap_vault_key(
            &vault_key,
            &password_kek,
            UnlockMethod::Password,
            MethodData::Password {
                params: password_params.clone(),
            },
            Some("Password".to_string()),
        )
        .unwrap();

        // Wrap with recovery key
        let recovery_encrypted = wrap_vault_key(
            &vault_key,
            &recovery_kek,
            UnlockMethod::RecoveryKey,
            MethodData::Recovery {
                salt: recovery_salt,
                fingerprint: "abandon ability...".to_string(),
            },
            Some("Recovery".to_string()),
        )
        .unwrap();

        // Verify both can unwrap to same vault key
        let from_password = unwrap_vault_key(&password_encrypted, &password_kek).unwrap();
        let from_recovery = unwrap_vault_key(&recovery_encrypted, &recovery_kek).unwrap();

        assert_eq!(from_password.expose(), vault_key.expose());
        assert_eq!(from_recovery.expose(), vault_key.expose());
        assert_eq!(from_password.expose(), from_recovery.expose());
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2); // Salts should be unique
    }

    #[test]
    fn test_generate_challenge() {
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();

        assert_eq!(challenge1.len(), 32);
        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_rewrap_vault_key() {
        let vault_key = VaultKey::generate();

        // Original KEK
        let (original_kek, original_params) = create_test_kek();
        let original_method_data = MethodData::Password {
            params: original_params.clone(),
        };

        let original_encrypted = wrap_vault_key(
            &vault_key,
            &original_kek,
            UnlockMethod::Password,
            original_method_data,
            Some("Original".to_string()),
        )
        .unwrap();

        // New KEK (e.g., adding recovery key)
        let recovery_salt = generate_salt();
        let recovery_seed = [0x99u8; 64];
        let new_kek =
            crate::crypto::kek::derive_from_recovery_seed(&recovery_seed, &recovery_salt).unwrap();

        // Re-wrap for new method
        let new_encrypted = rewrap_vault_key(
            &vault_key,
            &new_kek,
            UnlockMethod::RecoveryKey,
            MethodData::Recovery {
                salt: recovery_salt,
                fingerprint: "test fingerprint".to_string(),
            },
            Some("Recovery".to_string()),
        )
        .unwrap();

        // Verify original still works
        let from_original = unwrap_vault_key(&original_encrypted, &original_kek).unwrap();
        assert_eq!(from_original.expose(), vault_key.expose());

        // Verify new method works
        let from_new = unwrap_vault_key(&new_encrypted, &new_kek).unwrap();
        assert_eq!(from_new.expose(), vault_key.expose());
    }

    #[test]
    fn test_mark_key_used() {
        let (kek, params) = create_test_kek();
        let vault_key = VaultKey::generate();

        let mut encrypted = wrap_vault_key(
            &vault_key,
            &kek,
            UnlockMethod::Password,
            MethodData::Password { params },
            None,
        )
        .unwrap();

        assert!(encrypted.last_used.is_none());

        mark_key_used(&mut encrypted);

        assert!(encrypted.last_used.is_some());
    }
}
