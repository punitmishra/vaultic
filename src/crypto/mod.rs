//! Cryptographic primitives for Vaultic
//!
//! This module provides all cryptographic operations used by Vaultic,
//! implementing industry-standard algorithms with secure defaults.
//!
//! # Security Design
//!
//! | Purpose | Algorithm | Key Size |
//! |---------|-----------|----------|
//! | Symmetric encryption | XChaCha20-Poly1305 | 256-bit |
//! | Key derivation | Argon2id | 256-bit output |
//! | Key exchange | X25519 | 256-bit |
//! | Signatures | Ed25519 | 256-bit |
//! | Key expansion | HKDF-SHA256 | Variable |
//!
//! # Key Derivation
//!
//! Passwords are processed through Argon2id with configurable parameters:
//! - Memory: 64 MiB (default) to 256 MiB (high security)
//! - Iterations: 3 (default) to 8 (high security)
//! - Parallelism: 4 threads
//!
//! # Example
//!
//! ```
//! use vaultic::crypto::{Cipher, MasterKey, PasswordGenerator};
//!
//! // Generate a strong password
//! let password = PasswordGenerator::new(20).generate();
//!
//! // Encrypt data
//! let key = MasterKey::from_bytes([0u8; 32]);
//! let cipher = Cipher::new(key.as_bytes());
//! let encrypted = cipher.encrypt(b"secret data").unwrap();
//! let decrypted = cipher.decrypt(&encrypted).unwrap();
//! ```

use argon2::{password_hash::SaltString, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::models::KdfParams;

/// Cryptographic errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Invalid nonce length")]
    InvalidNonceLength,

    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

/// Master key derived from password/FIDO2
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generate a random master key (for FIDO2 flow)
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Derive encryption and authentication keys
    pub fn derive_keys(&self) -> DerivedKeys {
        let hk = Hkdf::<Sha256>::new(None, &self.0);

        let mut encryption_key = [0u8; 32];
        let mut auth_key = [0u8; 32];

        hk.expand(b"vaultic-encryption-key-v1", &mut encryption_key)
            .expect("HKDF expansion failed");
        hk.expand(b"vaultic-auth-key-v1", &mut auth_key)
            .expect("HKDF expansion failed");

        DerivedKeys {
            encryption_key,
            auth_key,
        }
    }
}

/// Keys derived from master key
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub encryption_key: [u8; 32],
    pub auth_key: [u8; 32],
}

/// Main encryption/decryption engine
pub struct Cipher {
    cipher: XChaCha20Poly1305,
}

impl Cipher {
    /// Create a new cipher with the given key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = XChaCha20Poly1305::new(key.into());
        Self { cipher }
    }

    /// Encrypt plaintext, returning nonce + ciphertext
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(24 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend(ciphertext);
        Ok(result)
    }

    /// Decrypt ciphertext (expects nonce prepended)
    pub fn decrypt(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < 24 {
            return Err(CryptoError::InvalidNonceLength);
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    /// Encrypt with additional authenticated data
    pub fn encrypt_aad(&self, plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        use chacha20poly1305::aead::Payload;

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::with_capacity(24 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend(ciphertext);
        Ok(result)
    }

    /// Decrypt with additional authenticated data
    pub fn decrypt_aad(&self, ciphertext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        use chacha20poly1305::aead::Payload;

        if ciphertext.len() < 24 {
            return Err(CryptoError::InvalidNonceLength);
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);
        let payload = Payload {
            msg: encrypted,
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}

/// Key derivation using Argon2id
pub struct KeyDeriver;

impl KeyDeriver {
    /// Derive a master key from a password
    pub fn derive_from_password(password: &[u8], params: &KdfParams) -> CryptoResult<MasterKey> {
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

        Ok(MasterKey(output))
    }

    /// Generate new KDF parameters with random salt
    pub fn generate_params() -> KdfParams {
        let salt = SaltString::generate(&mut OsRng);
        KdfParams {
            algorithm: "argon2id".to_string(),
            memory_cost: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 4,
            salt: salt.as_str().as_bytes().to_vec(),
        }
    }

    /// Higher security params for sensitive vaults
    pub fn generate_high_security_params() -> KdfParams {
        let salt = SaltString::generate(&mut OsRng);
        KdfParams {
            algorithm: "argon2id".to_string(),
            memory_cost: 262144, // 256 MiB
            time_cost: 4,
            parallelism: 8,
            salt: salt.as_str().as_bytes().to_vec(),
        }
    }
}

/// Identity keypair for signing and key exchange
pub struct IdentityKeyPair {
    /// Ed25519 signing key
    signing_key: SigningKey,
    /// X25519 static secret for key exchange
    exchange_secret: StaticSecret,
}

impl IdentityKeyPair {
    /// Generate a new identity keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut exchange_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut exchange_bytes);
        let exchange_secret = StaticSecret::from(exchange_bytes);

        Self {
            signing_key,
            exchange_secret,
        }
    }

    /// Get the signing public key
    pub fn signing_public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the exchange public key
    pub fn exchange_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.exchange_secret)
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Perform key exchange with a recipient's public key
    pub fn key_exchange(&self, recipient_public: &X25519PublicKey) -> [u8; 32] {
        self.exchange_secret
            .diffie_hellman(recipient_public)
            .to_bytes()
    }

    /// Export keys for storage (encrypted with master key)
    pub fn export(&self, cipher: &Cipher) -> CryptoResult<Vec<u8>> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(self.signing_key.as_bytes());
        data.extend_from_slice(self.exchange_secret.as_bytes());
        cipher.encrypt(&data)
    }

    /// Import keys from encrypted storage
    pub fn import(encrypted: &[u8], cipher: &Cipher) -> CryptoResult<Self> {
        let data = cipher.decrypt(encrypted)?;
        if data.len() != 64 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 64,
                actual: data.len(),
            });
        }

        let signing_bytes: [u8; 32] = data[..32].try_into().unwrap();
        let exchange_bytes: [u8; 32] = data[32..].try_into().unwrap();

        let signing_key = SigningKey::from_bytes(&signing_bytes);
        let exchange_secret = StaticSecret::from(exchange_bytes);

        Ok(Self {
            signing_key,
            exchange_secret,
        })
    }

    /// Compute fingerprint (truncated hash of public keys)
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.signing_public_key().as_bytes());
        hasher.update(self.exchange_public_key().as_bytes());
        let hash = hasher.finalize();

        // Format as groups of 4 hex chars
        hash[..16]
            .chunks(4)
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Key exchange for sharing secrets
pub struct KeyExchange;

impl KeyExchange {
    /// Create a shared secret for encrypting data to share
    /// Returns (encrypted_key, symmetric_key)
    pub fn create_shared_secret(
        _sender_keypair: &IdentityKeyPair,
        recipient_public: &X25519PublicKey,
    ) -> ([u8; 32], Vec<u8>) {
        // Ephemeral key for perfect forward secrecy
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        // DH with ephemeral
        let shared_secret = ephemeral_secret.diffie_hellman(recipient_public);

        // Derive actual encryption key
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut symmetric_key = [0u8; 32];
        hk.expand(b"vaultic-shared-secret-v1", &mut symmetric_key)
            .expect("HKDF expansion failed");

        // Return ephemeral public key (to send) and symmetric key (for encryption)
        (symmetric_key, ephemeral_public.as_bytes().to_vec())
    }

    /// Recover shared secret from ephemeral public key
    pub fn recover_shared_secret(
        recipient_keypair: &IdentityKeyPair,
        ephemeral_public_bytes: &[u8],
    ) -> CryptoResult<[u8; 32]> {
        if ephemeral_public_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: ephemeral_public_bytes.len(),
            });
        }

        let ephemeral_public_array: [u8; 32] = ephemeral_public_bytes.try_into().unwrap();
        let ephemeral_public = X25519PublicKey::from(ephemeral_public_array);

        let shared_secret = recipient_keypair.key_exchange(&ephemeral_public);

        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut symmetric_key = [0u8; 32];
        hk.expand(b"vaultic-shared-secret-v1", &mut symmetric_key)
            .expect("HKDF expansion failed");

        Ok(symmetric_key)
    }
}

/// Signature verification utilities
pub struct SignatureVerifier;

impl SignatureVerifier {
    pub fn verify(
        public_key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> CryptoResult<()> {
        public_key
            .verify(message, signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

/// Password strength analyzer
pub struct PasswordAnalyzer;

impl PasswordAnalyzer {
    /// Calculate password entropy in bits
    pub fn entropy(password: &str) -> f64 {
        let len = password.len() as f64;
        let mut charset_size = 0u32;

        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        if has_lower {
            charset_size += 26;
        }
        if has_upper {
            charset_size += 26;
        }
        if has_digit {
            charset_size += 10;
        }
        if has_special {
            charset_size += 32;
        }

        len * (charset_size as f64).log2()
    }

    /// Assess password strength
    pub fn strength(password: &str) -> crate::models::PasswordStrength {
        use crate::models::PasswordStrength;

        let entropy = Self::entropy(password);

        if entropy < 28.0 {
            PasswordStrength::VeryWeak
        } else if entropy < 36.0 {
            PasswordStrength::Weak
        } else if entropy < 60.0 {
            PasswordStrength::Fair
        } else if entropy < 80.0 {
            PasswordStrength::Strong
        } else {
            PasswordStrength::VeryStrong
        }
    }

    /// Check for common password patterns
    pub fn has_common_patterns(password: &str) -> bool {
        let lower = password.to_lowercase();

        // Common sequences
        let sequences = [
            "123456", "qwerty", "password", "abc123", "111111", "letmein",
        ];

        sequences.iter().any(|seq| lower.contains(seq))
    }
}

/// Secure password generator
pub struct PasswordGenerator {
    length: usize,
    use_uppercase: bool,
    use_lowercase: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool,
    custom_symbols: Option<String>,
}

impl Default for PasswordGenerator {
    fn default() -> Self {
        Self {
            length: 20,
            use_uppercase: true,
            use_lowercase: true,
            use_digits: true,
            use_symbols: true,
            exclude_ambiguous: true,
            custom_symbols: None,
        }
    }
}

impl PasswordGenerator {
    pub fn new(length: usize) -> Self {
        Self {
            length,
            ..Default::default()
        }
    }

    pub fn with_uppercase(mut self, use_it: bool) -> Self {
        self.use_uppercase = use_it;
        self
    }

    pub fn with_lowercase(mut self, use_it: bool) -> Self {
        self.use_lowercase = use_it;
        self
    }

    pub fn with_digits(mut self, use_it: bool) -> Self {
        self.use_digits = use_it;
        self
    }

    pub fn with_symbols(mut self, use_it: bool) -> Self {
        self.use_symbols = use_it;
        self
    }

    pub fn exclude_ambiguous(mut self, exclude: bool) -> Self {
        self.exclude_ambiguous = exclude;
        self
    }

    pub fn generate(&self) -> String {
        let mut charset = String::new();

        const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
        const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const DIGITS: &str = "0123456789";
        const SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        const AMBIGUOUS: &str = "0O1lI";

        if self.use_lowercase {
            charset.push_str(LOWERCASE);
        }
        if self.use_uppercase {
            charset.push_str(UPPERCASE);
        }
        if self.use_digits {
            charset.push_str(DIGITS);
        }
        if self.use_symbols {
            if let Some(ref custom) = self.custom_symbols {
                charset.push_str(custom);
            } else {
                charset.push_str(SYMBOLS);
            }
        }

        if self.exclude_ambiguous {
            charset = charset
                .chars()
                .filter(|c| !AMBIGUOUS.contains(*c))
                .collect();
        }

        let charset: Vec<char> = charset.chars().collect();
        if charset.is_empty() {
            return String::new();
        }

        let mut password = String::with_capacity(self.length);
        let mut rng = OsRng;

        for _ in 0..self.length {
            let idx = (rng.next_u32() as usize) % charset.len();
            password.push(charset[idx]);
        }

        password
    }

    /// Generate a memorable passphrase
    pub fn generate_passphrase(word_count: usize) -> String {
        // Simple word list (in production, use EFF wordlist)
        const WORDS: &[&str] = &[
            "correct", "horse", "battery", "staple", "quantum", "crystal", "thunder", "phoenix",
            "dragon", "silver", "golden", "cosmic", "nebula", "galaxy", "solar", "lunar",
            "stellar", "orbital", "cipher", "vector", "matrix", "prism", "vertex", "helix",
            "carbon", "silicon", "helium", "neon", "argon", "xenon",
        ];

        let mut rng = OsRng;
        let mut words = Vec::with_capacity(word_count);

        for _ in 0..word_count {
            let idx = (rng.next_u32() as usize) % WORDS.len();
            words.push(WORDS[idx]);
        }

        words.join("-")
    }
}

// Hex encoding utility
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let cipher = Cipher::new(&key);
        let plaintext = b"Hello, Vaultic!";

        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_key_derivation() {
        let password = b"super_secret_password";
        let params = KeyDeriver::generate_params();

        let key1 = KeyDeriver::derive_from_password(password, &params).unwrap();
        let key2 = KeyDeriver::derive_from_password(password, &params).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_identity_keypair() {
        let keypair = IdentityKeyPair::generate();
        let message = b"Sign this message";

        let signature = keypair.sign(message);
        let public_key = keypair.signing_public_key();

        SignatureVerifier::verify(&public_key, message, &signature).unwrap();
    }

    #[test]
    fn test_password_generator() {
        let password = PasswordGenerator::new(24).generate();
        assert_eq!(password.len(), 24);

        let entropy = PasswordAnalyzer::entropy(&password);
        assert!(entropy > 60.0);
    }

    #[test]
    fn test_key_exchange() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let (alice_key, ephemeral) =
            KeyExchange::create_shared_secret(&alice, &bob.exchange_public_key());
        let bob_key = KeyExchange::recover_shared_secret(&bob, &ephemeral).unwrap();

        assert_eq!(alice_key, bob_key);
    }
}
