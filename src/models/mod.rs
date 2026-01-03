//! Core data models for Vaultic
//! All sensitive data implements Zeroize for secure memory cleanup

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Entry types supported by Vaultic
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    Password,
    SecureNote,
    CreditCard,
    Identity,
    SshKey,
    ApiKey,
    Totp,
    Custom(String),
}

impl std::fmt::Display for EntryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password => write!(f, "Password"),
            Self::SecureNote => write!(f, "Secure Note"),
            Self::CreditCard => write!(f, "Credit Card"),
            Self::Identity => write!(f, "Identity"),
            Self::SshKey => write!(f, "SSH Key"),
            Self::ApiKey => write!(f, "API Key"),
            Self::Totp => write!(f, "TOTP"),
            Self::Custom(name) => write!(f, "Custom: {}", name),
        }
    }
}

/// A sensitive string that zeroes memory on drop
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED {} chars]", self.0.len())
    }
}

impl From<String> for SensitiveString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SensitiveString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// Password strength assessment
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PasswordStrength {
    VeryWeak,
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

impl PasswordStrength {
    pub fn color(&self) -> &'static str {
        match self {
            Self::VeryWeak => "red",
            Self::Weak => "yellow",
            Self::Fair => "cyan",
            Self::Strong => "green",
            Self::VeryStrong => "bright green",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Self::VeryWeak => "🔴",
            Self::Weak => "🟠",
            Self::Fair => "🟡",
            Self::Strong => "🟢",
            Self::VeryStrong => "💚",
        }
    }
}

/// Custom field for flexible data storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: SensitiveString,
    pub is_hidden: bool,
}

/// A historical password entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub password: SensitiveString,
    pub changed_at: DateTime<Utc>,
}

/// A password/secret entry in the vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: Uuid,
    pub entry_type: EntryType,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<SensitiveString>,
    pub url: Option<String>,
    pub notes: Option<SensitiveString>,
    pub tags: Vec<String>,
    pub folder: Option<String>,
    pub custom_fields: Vec<CustomField>,
    pub totp_secret: Option<SensitiveString>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub password_changed_at: Option<DateTime<Utc>>,
    pub password_strength: Option<PasswordStrength>,
    pub favorite: bool,
    /// Days until password should be rotated (AI can suggest this)
    pub rotation_days: Option<u32>,
    /// Shared with these user IDs (public key fingerprints)
    pub shared_with: Vec<String>,
    /// Password history (last N passwords)
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
}

/// Maximum number of passwords to keep in history
pub const MAX_PASSWORD_HISTORY: usize = 5;

impl VaultEntry {
    pub fn new(name: impl Into<String>, entry_type: EntryType) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            entry_type,
            name: name.into(),
            username: None,
            password: None,
            url: None,
            notes: None,
            tags: Vec::new(),
            folder: None,
            custom_fields: Vec::new(),
            totp_secret: None,
            created_at: now,
            updated_at: now,
            last_accessed: None,
            password_changed_at: None,
            password_strength: None,
            favorite: false,
            rotation_days: Some(90), // Default 90-day rotation
            shared_with: Vec::new(),
            password_history: Vec::new(),
        }
    }

    pub fn with_password(mut self, password: impl Into<SensitiveString>) -> Self {
        self.password = Some(password.into());
        self.password_changed_at = Some(Utc::now());
        self
    }

    /// Set a new password, saving the old one to history
    pub fn set_password(&mut self, new_password: impl Into<SensitiveString>) {
        let now = Utc::now();

        // Save current password to history if it exists
        if let Some(old_password) = self.password.take() {
            let history_entry = PasswordHistoryEntry {
                password: old_password,
                changed_at: self.password_changed_at.unwrap_or(self.created_at),
            };
            self.password_history.insert(0, history_entry);

            // Keep only last N passwords
            self.password_history.truncate(MAX_PASSWORD_HISTORY);
        }

        self.password = Some(new_password.into());
        self.password_changed_at = Some(now);
        self.updated_at = now;
    }

    /// Get password history
    pub fn get_password_history(&self) -> &[PasswordHistoryEntry] {
        &self.password_history
    }

    /// Restore a password from history by index
    pub fn restore_password(&mut self, index: usize) -> Option<()> {
        if index >= self.password_history.len() {
            return None;
        }

        let history_entry = self.password_history.remove(index);

        // Save current password to history
        if let Some(current) = self.password.take() {
            let current_entry = PasswordHistoryEntry {
                password: current,
                changed_at: self.password_changed_at.unwrap_or(self.created_at),
            };
            self.password_history.insert(0, current_entry);
            self.password_history.truncate(MAX_PASSWORD_HISTORY);
        }

        self.password = Some(history_entry.password);
        self.password_changed_at = Some(Utc::now());
        self.updated_at = Utc::now();

        Some(())
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn touch(&mut self) {
        self.last_accessed = Some(Utc::now());
    }

    /// Check if password needs rotation
    pub fn needs_rotation(&self) -> bool {
        if let (Some(changed_at), Some(rotation_days)) =
            (self.password_changed_at, self.rotation_days)
        {
            let days_since = (Utc::now() - changed_at).num_days();
            days_since >= rotation_days as i64
        } else {
            false
        }
    }

    /// Days until rotation is needed
    pub fn days_until_rotation(&self) -> Option<i64> {
        if let (Some(changed_at), Some(rotation_days)) =
            (self.password_changed_at, self.rotation_days)
        {
            let days_since = (Utc::now() - changed_at).num_days();
            Some(rotation_days as i64 - days_since)
        } else {
            None
        }
    }
}

/// Vault metadata (stored separately, encrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u32,
    pub entry_count: usize,
    /// Public key fingerprint of the vault owner
    pub owner_fingerprint: String,
    /// Encryption algorithm used
    pub encryption_algo: String,
    /// KDF parameters
    pub kdf_params: KdfParams,
}

/// Key derivation function parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String, // "argon2id"
    pub memory_cost: u32,  // in KiB
    pub time_cost: u32,    // iterations
    pub parallelism: u32,
    pub salt: Vec<u8>,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            memory_cost: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 4,
            salt: Vec::new(), // Will be generated
        }
    }
}

/// User identity for sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    pub id: Uuid,
    pub name: String,
    pub email: Option<String>,
    /// X25519 public key for key exchange
    pub public_key: Vec<u8>,
    /// Ed25519 public key for signatures
    pub signing_key: Vec<u8>,
    /// Fingerprint for easy identification
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub trusted: bool,
}

/// Shared secret for password sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSecret {
    pub id: Uuid,
    pub entry_id: Uuid,
    /// Encrypted entry data (encrypted with shared symmetric key)
    pub encrypted_data: Vec<u8>,
    /// Symmetric key encrypted with recipient's public key
    pub encrypted_key: Vec<u8>,
    /// Sender's fingerprint
    pub sender_fingerprint: String,
    /// Recipient's fingerprint
    pub recipient_fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    /// One-time share (deleted after first access)
    pub one_time: bool,
    /// Access count
    pub access_count: u32,
    /// Max access count (None = unlimited)
    pub max_access_count: Option<u32>,
}

/// AI suggestion for password management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSuggestion {
    pub id: Uuid,
    pub entry_id: Option<Uuid>,
    pub suggestion_type: SuggestionType,
    pub message: String,
    pub priority: SuggestionPriority,
    pub created_at: DateTime<Utc>,
    pub dismissed: bool,
    pub action_taken: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionType {
    RotatePassword,
    WeakPassword,
    DuplicatePassword,
    BreachedPassword,
    MissingMfa,
    UnusedEntry,
    OrganizeSuggestion,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
    pub entry_id: Option<Uuid>,
    pub entry_name: Option<String>,
    pub details: Option<String>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    VaultUnlock,
    VaultLock,
    EntryCreated,
    EntryUpdated,
    EntryDeleted,
    EntryAccessed,
    PasswordCopied,
    PasswordGenerated,
    EntryShared,
    SharedSecretAccessed,
    ExportPerformed,
    ImportPerformed,
    SettingsChanged,
    FidoAuthenticated,
}

/// Search/filter parameters
#[derive(Debug, Clone, Default)]
pub struct SearchFilter {
    pub query: Option<String>,
    pub entry_type: Option<EntryType>,
    pub tags: Vec<String>,
    pub folder: Option<String>,
    pub favorites_only: bool,
    pub needs_rotation: bool,
    pub weak_passwords: bool,
    pub limit: Option<usize>,
    pub offset: usize,
}

impl SearchFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = Some(query.into());
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn favorites(mut self) -> Self {
        self.favorites_only = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_entry_creation() {
        let entry = VaultEntry::new("GitHub", EntryType::Password)
            .with_username("user@example.com")
            .with_password("super_secret")
            .with_url("https://github.com");

        assert_eq!(entry.name, "GitHub");
        assert_eq!(entry.username, Some("user@example.com".to_string()));
        assert!(entry.password.is_some());
    }

    #[test]
    fn test_sensitive_string_debug() {
        let secret = SensitiveString::new("my_password");
        let debug_output = format!("{:?}", secret);
        assert!(!debug_output.contains("my_password"));
        assert!(debug_output.contains("REDACTED"));
    }

    #[test]
    fn test_rotation_check() {
        let mut entry = VaultEntry::new("Test", EntryType::Password);
        entry.rotation_days = Some(1);
        entry.password_changed_at = Some(Utc::now() - chrono::Duration::days(2));
        assert!(entry.needs_rotation());
    }

    #[test]
    fn test_password_history() {
        let mut entry = VaultEntry::new("Test", EntryType::Password).with_password("password1");

        // Change password - should save old one to history
        entry.set_password("password2");
        assert_eq!(entry.password.as_ref().unwrap().expose(), "password2");
        assert_eq!(entry.password_history.len(), 1);
        assert_eq!(entry.password_history[0].password.expose(), "password1");

        // Change again
        entry.set_password("password3");
        assert_eq!(entry.password.as_ref().unwrap().expose(), "password3");
        assert_eq!(entry.password_history.len(), 2);
        assert_eq!(entry.password_history[0].password.expose(), "password2");
        assert_eq!(entry.password_history[1].password.expose(), "password1");
    }

    #[test]
    fn test_password_history_limit() {
        let mut entry = VaultEntry::new("Test", EntryType::Password).with_password("password0");

        // Add more than MAX_PASSWORD_HISTORY passwords
        for i in 1..=7 {
            entry.set_password(format!("password{}", i));
        }

        // Should only keep MAX_PASSWORD_HISTORY (5) entries
        assert_eq!(entry.password_history.len(), MAX_PASSWORD_HISTORY);
        assert_eq!(entry.password.as_ref().unwrap().expose(), "password7");
    }

    #[test]
    fn test_password_restore() {
        let mut entry = VaultEntry::new("Test", EntryType::Password).with_password("old_password");
        entry.set_password("new_password");

        // Restore old password
        assert!(entry.restore_password(0).is_some());
        assert_eq!(entry.password.as_ref().unwrap().expose(), "old_password");

        // Current should now be in history
        assert_eq!(entry.password_history[0].password.expose(), "new_password");
    }

    #[test]
    fn test_custom_fields() {
        let mut entry = VaultEntry::new("Test", EntryType::Password);

        // Add custom fields
        entry.custom_fields.push(CustomField {
            name: "security_question".to_string(),
            value: SensitiveString::new("What is your pet's name?"),
            is_hidden: false,
        });
        entry.custom_fields.push(CustomField {
            name: "security_answer".to_string(),
            value: SensitiveString::new("Fluffy"),
            is_hidden: true,
        });

        assert_eq!(entry.custom_fields.len(), 2);
        assert_eq!(entry.custom_fields[0].name, "security_question");
        assert!(!entry.custom_fields[0].is_hidden);
        assert!(entry.custom_fields[1].is_hidden);
    }

    #[test]
    fn test_entry_with_notes() {
        let mut entry = VaultEntry::new("Test", EntryType::Password);
        entry.notes = Some(SensitiveString::new("This is a secure note"));

        assert!(entry.notes.is_some());
        assert_eq!(
            entry.notes.as_ref().unwrap().expose(),
            "This is a secure note"
        );
    }

    #[test]
    fn test_favorite_flag() {
        let mut entry = VaultEntry::new("Test", EntryType::Password);
        assert!(!entry.favorite);

        entry.favorite = true;
        assert!(entry.favorite);
    }
}
