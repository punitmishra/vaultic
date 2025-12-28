//! TOTP (Time-based One-Time Password) support
//!
//! Implements RFC 6238 for TOTP generation, compatible with
//! Google Authenticator, Authy, and other TOTP apps.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;

/// TOTP errors
#[derive(Debug, Error)]
pub enum TotpError {
    #[error("Invalid secret: {0}")]
    InvalidSecret(String),

    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    #[error("System time error")]
    SystemTimeError,
}

pub type TotpResult<T> = Result<T, TotpError>;

/// TOTP hash algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    /// Parse algorithm from string
    pub fn from_str(s: &str) -> TotpResult<Self> {
        match s.to_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(TotpError::InvalidAlgorithm(s.to_string())),
        }
    }

    /// Get algorithm name
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// TOTP generator
#[derive(Debug, Clone)]
pub struct Totp {
    /// Secret key (decoded from base32)
    secret: Vec<u8>,
    /// Number of digits (6 or 8)
    digits: u32,
    /// Time step in seconds (usually 30)
    period: u64,
    /// Hash algorithm
    algorithm: Algorithm,
    /// Issuer name
    issuer: Option<String>,
    /// Account name
    account: Option<String>,
}

impl Totp {
    /// Create a new TOTP generator with default settings
    pub fn new(secret: &str) -> TotpResult<Self> {
        let decoded = decode_base32(secret)?;

        Ok(Self {
            secret: decoded,
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
            issuer: None,
            account: None,
        })
    }

    /// Set number of digits (6 or 8)
    pub fn digits(mut self, digits: u32) -> Self {
        self.digits = digits.clamp(6, 8);
        self
    }

    /// Set time period in seconds
    pub fn period(mut self, period: u64) -> Self {
        self.period = period.max(1);
        self
    }

    /// Set hash algorithm
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set issuer
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set account name
    pub fn account(mut self, account: impl Into<String>) -> Self {
        self.account = Some(account.into());
        self
    }

    /// Generate current TOTP code
    pub fn generate(&self) -> TotpResult<String> {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TotpError::SystemTimeError)?
            .as_secs();

        self.generate_at(time)
    }

    /// Generate TOTP code for a specific time
    pub fn generate_at(&self, time: u64) -> TotpResult<String> {
        let counter = time / self.period;
        self.generate_hotp(counter)
    }

    /// Generate HOTP (counter-based)
    fn generate_hotp(&self, counter: u64) -> TotpResult<String> {
        let counter_bytes = counter.to_be_bytes();

        let hash = match self.algorithm {
            Algorithm::Sha1 => {
                let mut mac =
                    Hmac::<Sha1>::new_from_slice(&self.secret).map_err(|_| {
                        TotpError::InvalidSecret("Invalid key length".to_string())
                    })?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::Sha256 => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(&self.secret).map_err(|_| {
                        TotpError::InvalidSecret("Invalid key length".to_string())
                    })?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::Sha512 => {
                let mut mac =
                    Hmac::<Sha512>::new_from_slice(&self.secret).map_err(|_| {
                        TotpError::InvalidSecret("Invalid key length".to_string())
                    })?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
        };

        // Dynamic truncation
        let offset = (hash.last().unwrap() & 0x0f) as usize;
        let binary = u32::from_be_bytes([
            hash[offset] & 0x7f,
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ]);

        let otp = binary % 10u32.pow(self.digits);

        Ok(format!("{:0>width$}", otp, width = self.digits as usize))
    }

    /// Verify a TOTP code (allows 1 period skew)
    pub fn verify(&self, code: &str) -> TotpResult<bool> {
        self.verify_with_skew(code, 1)
    }

    /// Verify a TOTP code with custom time skew
    pub fn verify_with_skew(&self, code: &str, skew: u64) -> TotpResult<bool> {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TotpError::SystemTimeError)?
            .as_secs();

        let current_counter = time / self.period;

        for offset in 0..=skew {
            // Check current and past periods
            if self.generate_hotp(current_counter - offset)? == code {
                return Ok(true);
            }
            // Check future periods (for clock skew)
            if offset > 0 && self.generate_hotp(current_counter + offset)? == code {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get seconds remaining until next code
    pub fn seconds_remaining(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.period - (now % self.period)
    }

    /// Generate otpauth:// URI for QR codes
    pub fn to_uri(&self) -> String {
        let secret = encode_base32(&self.secret);

        let label = match (&self.issuer, &self.account) {
            (Some(issuer), Some(account)) => {
                format!("{}:{}", urlencoding::encode(issuer), urlencoding::encode(account))
            }
            (None, Some(account)) => urlencoding::encode(account).to_string(),
            (Some(issuer), None) => urlencoding::encode(issuer).to_string(),
            (None, None) => "vaultic".to_string(),
        };

        let mut uri = format!("otpauth://totp/{}?secret={}", label, secret);

        if let Some(ref issuer) = self.issuer {
            uri.push_str(&format!("&issuer={}", urlencoding::encode(issuer)));
        }

        if self.algorithm != Algorithm::Sha1 {
            uri.push_str(&format!("&algorithm={}", self.algorithm.as_str()));
        }

        if self.digits != 6 {
            uri.push_str(&format!("&digits={}", self.digits));
        }

        if self.period != 30 {
            uri.push_str(&format!("&period={}", self.period));
        }

        uri
    }

    /// Parse from otpauth:// URI
    pub fn from_uri(uri: &str) -> TotpResult<Self> {
        let url = url::Url::parse(uri)
            .map_err(|_| TotpError::InvalidSecret("Invalid URI format".to_string()))?;

        if url.scheme() != "otpauth" {
            return Err(TotpError::InvalidSecret("Not an otpauth URI".to_string()));
        }

        let mut secret = None;
        let mut digits = 6;
        let mut period = 30;
        let mut algorithm = Algorithm::Sha1;
        let mut issuer = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "secret" => secret = Some(value.to_string()),
                "digits" => {
                    digits = value
                        .parse()
                        .map_err(|_| TotpError::InvalidSecret("Invalid digits".to_string()))?
                }
                "period" => {
                    period = value
                        .parse()
                        .map_err(|_| TotpError::InvalidSecret("Invalid period".to_string()))?
                }
                "algorithm" => algorithm = Algorithm::from_str(&value)?,
                "issuer" => issuer = Some(value.to_string()),
                _ => {}
            }
        }

        let secret = secret.ok_or_else(|| TotpError::InvalidSecret("Missing secret".to_string()))?;
        let decoded = decode_base32(&secret)?;

        // Extract account from path
        let path = url.path().trim_start_matches('/');
        let account = if path.contains(':') {
            path.split(':').last().map(|s| s.to_string())
        } else if !path.is_empty() {
            Some(path.to_string())
        } else {
            None
        };

        Ok(Self {
            secret: decoded,
            digits,
            period,
            algorithm,
            issuer,
            account,
        })
    }

    /// Generate a random secret
    pub fn generate_secret(length: usize) -> String {
        use rand::RngCore;

        let mut bytes = vec![0u8; length];
        rand::rngs::OsRng.fill_bytes(&mut bytes);

        encode_base32(&bytes)
    }
}

/// Decode base32 (RFC 4648)
fn decode_base32(input: &str) -> TotpResult<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let input = input
        .to_uppercase()
        .replace([' ', '-'], "")
        .trim_end_matches('=')
        .to_string();

    let mut output = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits = 0;

    for c in input.chars() {
        let value = ALPHABET
            .iter()
            .position(|&x| x == c as u8)
            .ok_or_else(|| TotpError::InvalidSecret(format!("Invalid character: {}", c)))?
            as u64;

        buffer = (buffer << 5) | value;
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

/// Encode base32 (RFC 4648)
fn encode_base32(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut output = String::with_capacity((input.len() * 8 + 4) / 5);
    let mut buffer: u64 = 0;
    let mut bits = 0;

    for &byte in input {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            output.push(ALPHABET[index] as char);
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        output.push(ALPHABET[index] as char);
    }

    output
}

/// TOTP display helper
pub struct TotpDisplay {
    /// Current code
    pub code: String,
    /// Seconds remaining
    pub remaining: u64,
    /// Total period
    pub period: u64,
}

impl TotpDisplay {
    /// Create from TOTP generator
    pub fn from_totp(totp: &Totp) -> TotpResult<Self> {
        Ok(Self {
            code: totp.generate()?,
            remaining: totp.seconds_remaining(),
            period: totp.period,
        })
    }

    /// Format code with spaces (e.g., "123 456")
    pub fn formatted_code(&self) -> String {
        if self.code.len() == 6 {
            format!("{} {}", &self.code[..3], &self.code[3..])
        } else if self.code.len() == 8 {
            format!("{} {}", &self.code[..4], &self.code[4..])
        } else {
            self.code.clone()
        }
    }

    /// Get progress bar (for CLI display)
    pub fn progress_bar(&self, width: usize) -> String {
        let filled = (self.remaining as f64 / self.period as f64 * width as f64) as usize;
        let empty = width - filled;

        format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test vector
    const TEST_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"

    #[test]
    fn test_decode_base32() {
        let decoded = decode_base32(TEST_SECRET).unwrap();
        assert_eq!(decoded, b"12345678901234567890");
    }

    #[test]
    fn test_encode_base32() {
        let encoded = encode_base32(b"12345678901234567890");
        assert_eq!(encoded, TEST_SECRET);
    }

    #[test]
    fn test_totp_generation() {
        let totp = Totp::new(TEST_SECRET).unwrap();

        // Test at a known time (RFC 6238 test vector)
        // Time = 59, expected = 287082
        let code = totp.generate_at(59).unwrap();
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_totp_sha256() {
        // SHA256 test secret (32 bytes)
        let secret = encode_base32(b"12345678901234567890123456789012");
        let totp = Totp::new(&secret)
            .unwrap()
            .algorithm(Algorithm::Sha256);

        // Just verify it generates a 6-digit code
        let code = totp.generate_at(59).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_verification() {
        let totp = Totp::new(TEST_SECRET).unwrap();

        // Generate current code
        let code = totp.generate().unwrap();

        // Should verify
        assert!(totp.verify(&code).unwrap());

        // Wrong code should fail
        assert!(!totp.verify("000000").unwrap());
    }

    #[test]
    fn test_totp_uri() {
        let totp = Totp::new(TEST_SECRET)
            .unwrap()
            .issuer("Vaultic")
            .account("test@example.com");

        let uri = totp.to_uri();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("issuer=Vaultic"));
    }

    #[test]
    fn test_parse_uri() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let totp = Totp::from_uri(uri).unwrap();

        assert_eq!(totp.issuer, Some("Example".to_string()));
        assert_eq!(totp.account, Some("alice@google.com".to_string()));
    }

    #[test]
    fn test_generate_secret() {
        let secret = Totp::generate_secret(20);
        assert!(!secret.is_empty());

        // Should be valid base32
        let totp = Totp::new(&secret);
        assert!(totp.is_ok());
    }

    #[test]
    fn test_totp_display() {
        let totp = Totp::new(TEST_SECRET).unwrap();
        let display = TotpDisplay::from_totp(&totp).unwrap();

        assert_eq!(display.code.len(), 6);
        assert!(display.remaining <= 30);
        assert_eq!(display.period, 30);

        // Test formatted output
        let formatted = display.formatted_code();
        assert!(formatted.contains(' '));
    }
}
