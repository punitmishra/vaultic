//! Key Encryption Key (KEK) derivation functions
//!
//! This module provides functions to derive KEKs from various unlock methods:
//! - Password: Argon2id with configurable parameters
//! - Recovery key: HKDF-SHA256 from BIP39 seed
//! - Hardware key: HKDF-SHA256 from HMAC response
//! - GPG key: Direct use of decrypted session key

use argon2::{Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use super::keys::KeyEncryptionKey;
use super::CryptoError;
use crate::models::KdfParams;

/// Context strings for HKDF derivation (domain separation)
const RECOVERY_CONTEXT: &[u8] = b"vaultic-recovery-kek-v1";
const HARDWARE_CONTEXT: &[u8] = b"vaultic-hardware-kek-v1";
const GPG_CONTEXT: &[u8] = b"vaultic-gpg-kek-v1";

/// Derive a KEK from a password using Argon2id
///
/// # Arguments
/// * `password` - The user's password
/// * `params` - KDF parameters (memory, time, parallelism, salt)
///
/// # Returns
/// A KeyEncryptionKey derived from the password
pub fn derive_from_password(
    password: &[u8],
    params: &KdfParams,
) -> Result<KeyEncryptionKey, CryptoError> {
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password, &params.salt, &mut output)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(KeyEncryptionKey::from_bytes(output))
}

/// Derive a KEK from a BIP39 recovery seed using HKDF-SHA256
///
/// # Arguments
/// * `seed` - The 64-byte seed derived from BIP39 mnemonic
/// * `salt` - Random salt (stored with the encrypted vault key)
///
/// # Returns
/// A KeyEncryptionKey derived from the recovery seed
pub fn derive_from_recovery_seed(
    seed: &[u8],
    salt: &[u8],
) -> Result<KeyEncryptionKey, CryptoError> {
    if seed.len() < 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: seed.len(),
        });
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), seed);
    let mut output = [0u8; 32];
    hk.expand(RECOVERY_CONTEXT, &mut output)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(KeyEncryptionKey::from_bytes(output))
}

/// Derive a KEK from a hardware key HMAC response using HKDF-SHA256
///
/// # Arguments
/// * `hmac_response` - The HMAC-SHA1 response from YubiKey (20 bytes)
/// * `salt` - Random salt (stored with the encrypted vault key)
///
/// # Returns
/// A KeyEncryptionKey derived from the hardware response
pub fn derive_from_hardware_response(
    hmac_response: &[u8],
    salt: &[u8],
) -> Result<KeyEncryptionKey, CryptoError> {
    if hmac_response.len() < 20 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 20,
            actual: hmac_response.len(),
        });
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), hmac_response);
    let mut output = [0u8; 32];
    hk.expand(HARDWARE_CONTEXT, &mut output)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(KeyEncryptionKey::from_bytes(output))
}

/// Derive a KEK from a GPG-decrypted session key using HKDF-SHA256
///
/// # Arguments
/// * `session_key` - The decrypted session key from GPG
/// * `salt` - Random salt (stored with the encrypted vault key)
///
/// # Returns
/// A KeyEncryptionKey derived from the GPG session key
pub fn derive_from_gpg_session(
    session_key: &[u8],
    salt: &[u8],
) -> Result<KeyEncryptionKey, CryptoError> {
    if session_key.is_empty() {
        return Err(CryptoError::KeyDerivationFailed(
            "Empty GPG session key".to_string(),
        ));
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), session_key);
    let mut output = [0u8; 32];
    hk.expand(GPG_CONTEXT, &mut output)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(KeyEncryptionKey::from_bytes(output))
}

/// Derive a KEK from a FIDO2/WebAuthn PRF output
///
/// # Arguments
/// * `prf_output` - The PRF output from WebAuthn (32+ bytes)
/// * `salt` - Random salt for additional domain separation
///
/// # Returns
/// A KeyEncryptionKey derived from the PRF output
pub fn derive_from_passkey_prf(
    prf_output: &[u8],
    salt: &[u8],
) -> Result<KeyEncryptionKey, CryptoError> {
    if prf_output.len() < 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: prf_output.len(),
        });
    }

    // PRF output is already high-entropy, but we still run through HKDF
    // for domain separation
    let hk = Hkdf::<Sha256>::new(Some(salt), prf_output);
    let mut output = [0u8; 32];
    hk.expand(b"vaultic-passkey-kek-v1", &mut output)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(KeyEncryptionKey::from_bytes(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyDeriver;

    #[test]
    fn test_derive_from_password() {
        let password = b"correct horse battery staple";
        let params = KeyDeriver::generate_params();

        let kek1 = derive_from_password(password, &params).unwrap();
        let kek2 = derive_from_password(password, &params).unwrap();

        // Same password and params should give same KEK
        assert_eq!(kek1.expose(), kek2.expose());

        // Different password should give different KEK
        let kek3 = derive_from_password(b"different password", &params).unwrap();
        assert_ne!(kek1.expose(), kek3.expose());
    }

    #[test]
    fn test_derive_from_password_different_salts() {
        let password = b"test password";
        let params1 = KeyDeriver::generate_params();
        let params2 = KeyDeriver::generate_params();

        let kek1 = derive_from_password(password, &params1).unwrap();
        let kek2 = derive_from_password(password, &params2).unwrap();

        // Different salts should give different KEKs
        assert_ne!(kek1.expose(), kek2.expose());
    }

    #[test]
    fn test_derive_from_recovery_seed() {
        let seed = [0x42u8; 64]; // Simulated BIP39 seed
        let salt = [0xABu8; 32];

        let kek1 = derive_from_recovery_seed(&seed, &salt).unwrap();
        let kek2 = derive_from_recovery_seed(&seed, &salt).unwrap();

        // Same seed and salt should give same KEK
        assert_eq!(kek1.expose(), kek2.expose());
    }

    #[test]
    fn test_derive_from_recovery_seed_different_salts() {
        let seed = [0x42u8; 64];
        let salt1 = [0xAAu8; 32];
        let salt2 = [0xBBu8; 32];

        let kek1 = derive_from_recovery_seed(&seed, &salt1).unwrap();
        let kek2 = derive_from_recovery_seed(&seed, &salt2).unwrap();

        // Different salts should give different KEKs
        assert_ne!(kek1.expose(), kek2.expose());
    }

    #[test]
    fn test_derive_from_hardware_response() {
        let hmac_response = [0x12u8; 20]; // Simulated HMAC-SHA1 output
        let salt = [0xCDu8; 32];

        let kek = derive_from_hardware_response(&hmac_response, &salt).unwrap();
        assert_eq!(kek.expose().len(), 32);
    }

    #[test]
    fn test_derive_from_hardware_response_too_short() {
        let short_response = [0x12u8; 10];
        let salt = [0xCDu8; 32];

        let result = derive_from_hardware_response(&short_response, &salt);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_from_gpg_session() {
        let session_key = [0xEFu8; 32];
        let salt = [0x11u8; 32];

        let kek = derive_from_gpg_session(&session_key, &salt).unwrap();
        assert_eq!(kek.expose().len(), 32);
    }

    #[test]
    fn test_derive_from_gpg_session_empty() {
        let empty_key: [u8; 0] = [];
        let salt = [0x11u8; 32];

        let result = derive_from_gpg_session(&empty_key, &salt);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_from_passkey_prf() {
        let prf_output = [0x99u8; 32];
        let salt = [0x22u8; 32];

        let kek = derive_from_passkey_prf(&prf_output, &salt).unwrap();
        assert_eq!(kek.expose().len(), 32);
    }

    #[test]
    fn test_different_methods_produce_different_keks() {
        let input = [0x42u8; 64];
        let salt = [0xABu8; 32];

        let recovery_kek = derive_from_recovery_seed(&input, &salt).unwrap();
        let hardware_kek = derive_from_hardware_response(&input[..20], &salt).unwrap();
        let gpg_kek = derive_from_gpg_session(&input[..32], &salt).unwrap();
        let passkey_kek = derive_from_passkey_prf(&input[..32], &salt).unwrap();

        // Different methods should produce different KEKs even with similar input
        assert_ne!(recovery_kek.expose(), hardware_kek.expose());
        assert_ne!(recovery_kek.expose(), gpg_kek.expose());
        assert_ne!(hardware_kek.expose(), passkey_kek.expose());
    }
}
