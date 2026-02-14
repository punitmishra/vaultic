//! Integration tests for Vaultic
//!
//! These tests verify end-to-end functionality of the password manager.

use tempfile::tempdir;
use vaultic::crypto::{MasterKey, PasswordAnalyzer, PasswordGenerator};
use vaultic::models::{EntryType, PasswordStrength, SensitiveString, VaultEntry};
use vaultic::storage::VaultStorage;

/// Create a temporary vault for testing
fn create_test_vault() -> (tempfile::TempDir, VaultStorage, MasterKey) {
    // Each call creates a unique temp directory
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");

    // Create a test master key
    let master_key = MasterKey::from_bytes([42u8; 32]);

    // Create the vault
    let storage = VaultStorage::create(
        &vault_path,
        "Test Vault",
        &master_key,
        vaultic::models::KdfParams::default(),
        "test-fingerprint".to_string(),
    )
    .expect("Failed to create vault");

    (temp_dir, storage, master_key)
}

// ============================================================================
// Password Generator Tests
// ============================================================================

#[test]
fn test_password_generator_default() {
    let generator = PasswordGenerator::new(16);
    let password = generator.generate();

    assert_eq!(password.len(), 16);
    // Should have good strength
    let strength = PasswordAnalyzer::strength(&password);
    assert!(strength >= PasswordStrength::Fair);
}

#[test]
fn test_password_generator_custom() {
    let generator = PasswordGenerator::new(24)
        .with_uppercase(true)
        .with_lowercase(true)
        .with_digits(true)
        .with_symbols(true);

    let password = generator.generate();
    assert_eq!(password.len(), 24);

    // Should have very strong strength with all character types
    let strength = PasswordAnalyzer::strength(&password);
    assert!(strength >= PasswordStrength::Strong);
}

#[test]
fn test_password_generator_no_symbols() {
    let generator = PasswordGenerator::new(20).with_symbols(false);

    let password = generator.generate();
    assert_eq!(password.len(), 20);

    // Should not contain common symbols
    let symbols = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    for c in password.chars() {
        assert!(!symbols.contains(c), "Password should not contain symbols");
    }
}

// ============================================================================
// Password Strength Analysis Tests
// ============================================================================

#[test]
fn test_password_strength_very_weak() {
    let strength = PasswordAnalyzer::strength("123456");
    assert_eq!(strength, PasswordStrength::VeryWeak);
}

#[test]
fn test_password_strength_weak() {
    let strength = PasswordAnalyzer::strength("password123");
    // Common passwords should be rated poorly
    assert!(strength <= PasswordStrength::Fair);
}

#[test]
fn test_password_strength_strong() {
    let strength = PasswordAnalyzer::strength("Tr0ub4dor&3#Horse");
    assert!(strength >= PasswordStrength::Fair);
}

#[test]
fn test_password_entropy() {
    let low_entropy = PasswordAnalyzer::entropy("aaaaaa");
    let high_entropy = PasswordAnalyzer::entropy("Kj#9mP$2xL@5nQ");

    assert!(high_entropy > low_entropy);
    assert!(high_entropy > 50.0); // Should have good entropy
}

// ============================================================================
// Vault Entry Tests
// ============================================================================

#[test]
fn test_vault_entry_creation() {
    let entry = VaultEntry::new("GitHub", EntryType::Password)
        .with_username("user@example.com")
        .with_password("super_secret")
        .with_url("https://github.com")
        .with_tags(vec!["work".to_string(), "code".to_string()]);

    assert_eq!(entry.name, "GitHub");
    assert_eq!(entry.username, Some("user@example.com".to_string()));
    assert!(entry.password.is_some());
    assert_eq!(entry.url, Some("https://github.com".to_string()));
    assert_eq!(entry.tags.len(), 2);
}

#[test]
fn test_vault_entry_password_history() {
    let mut entry = VaultEntry::new("Test", EntryType::Password).with_password("password1");

    // Change password multiple times
    entry.set_password("password2");
    entry.set_password("password3");

    // Should have history
    assert_eq!(entry.password_history.len(), 2);
    assert_eq!(entry.password.as_ref().unwrap().expose(), "password3");

    // Restore old password
    entry.restore_password(0);
    assert_eq!(entry.password.as_ref().unwrap().expose(), "password2");
}

#[test]
fn test_vault_entry_custom_fields() {
    let mut entry = VaultEntry::new("Bank", EntryType::Password);

    entry.custom_fields.push(vaultic::models::CustomField {
        name: "Security Question".to_string(),
        value: SensitiveString::new("What is your pet's name?"),
        is_hidden: false,
    });

    entry.custom_fields.push(vaultic::models::CustomField {
        name: "Security Answer".to_string(),
        value: SensitiveString::new("Fluffy"),
        is_hidden: true,
    });

    assert_eq!(entry.custom_fields.len(), 2);
    assert!(!entry.custom_fields[0].is_hidden);
    assert!(entry.custom_fields[1].is_hidden);
}

// ============================================================================
// Sensitive String Tests
// ============================================================================

#[test]
fn test_sensitive_string_redacted_debug() {
    let secret = SensitiveString::new("my_password");
    let debug_output = format!("{:?}", secret);

    assert!(!debug_output.contains("my_password"));
    assert!(debug_output.contains("REDACTED"));
}

#[test]
fn test_sensitive_string_expose() {
    let secret = SensitiveString::new("test_value");
    assert_eq!(secret.expose(), "test_value");
    assert_eq!(secret.len(), 10);
    assert!(!secret.is_empty());
}

// ============================================================================
// Storage Tests
// ============================================================================

#[test]
fn test_vault_create_and_list() {
    let (_temp_dir, mut storage, master_key) = create_test_vault();

    // Unlock the vault
    storage.unlock(&master_key).expect("Failed to unlock");

    // Add entries
    let entry1 = VaultEntry::new("GitHub", EntryType::Password)
        .with_username("user1@example.com")
        .with_password("secret1");

    let entry2 = VaultEntry::new("Gmail", EntryType::Password)
        .with_username("user2@example.com")
        .with_password("secret2");

    storage.add_entry(&entry1).expect("Failed to add entry1");
    storage.add_entry(&entry2).expect("Failed to add entry2");

    // List entries
    let entries = storage.list_entries().expect("Failed to list entries");
    assert_eq!(entries.len(), 2);
}

#[test]
fn test_vault_search() {
    let (_temp_dir, mut storage, master_key) = create_test_vault();
    storage.unlock(&master_key).expect("Failed to unlock");

    // Add entries with different tags
    let entry1 =
        VaultEntry::new("Work GitHub", EntryType::Password).with_tags(vec!["work".to_string()]);

    let entry2 = VaultEntry::new("Personal GitHub", EntryType::Password)
        .with_tags(vec!["personal".to_string()]);

    let entry3 = VaultEntry::new("Work Email", EntryType::Password)
        .with_tags(vec!["work".to_string(), "email".to_string()]);

    storage.add_entry(&entry1).unwrap();
    storage.add_entry(&entry2).unwrap();
    storage.add_entry(&entry3).unwrap();

    // Search by tag
    let filter = vaultic::models::SearchFilter {
        query: None,
        entry_type: None,
        tags: vec!["work".to_string()],
        folder: None,
        favorites_only: false,
        needs_rotation: false,
        weak_passwords: false,
        offset: 0,
        limit: None,
    };

    let results = storage.search_entries(&filter).unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn test_vault_update_entry() {
    let (_temp_dir, mut storage, master_key) = create_test_vault();
    storage.unlock(&master_key).expect("Failed to unlock");

    // Add entry
    let mut entry = VaultEntry::new("Test", EntryType::Password).with_password("original");

    storage.add_entry(&entry).unwrap();

    // Update password
    entry.set_password("updated");
    storage.update_entry(&entry).unwrap();

    // Verify update
    let retrieved = storage.get_entry(&entry.id).unwrap().unwrap();
    assert_eq!(retrieved.password.as_ref().unwrap().expose(), "updated");
    assert_eq!(retrieved.password_history.len(), 1);
}

#[test]
fn test_vault_delete_entry() {
    let (_temp_dir, mut storage, master_key) = create_test_vault();
    storage.unlock(&master_key).expect("Failed to unlock");

    // Add entry
    let entry = VaultEntry::new("ToDelete", EntryType::Password);
    let id = entry.id;
    storage.add_entry(&entry).unwrap();

    // Verify it exists
    assert!(storage.get_entry(&id).unwrap().is_some());

    // Delete
    storage.delete_entry(&id).unwrap();

    // Verify it's gone
    assert!(storage.get_entry(&id).unwrap().is_none());
}

// ============================================================================
// Entry Type Tests
// ============================================================================

#[test]
fn test_entry_types() {
    let types = vec![
        (EntryType::Password, "Password"),
        (EntryType::SecureNote, "Secure Note"),
        (EntryType::CreditCard, "Credit Card"),
        (EntryType::Identity, "Identity"),
        (EntryType::SshKey, "SSH Key"),
        (EntryType::ApiKey, "API Key"),
        (EntryType::Totp, "TOTP"),
        (EntryType::Custom("MyType".to_string()), "Custom: MyType"),
    ];

    for (entry_type, expected_display) in types {
        assert_eq!(format!("{}", entry_type), expected_display);
    }
}

// ============================================================================
// Password Strength Color Tests
// ============================================================================

#[test]
fn test_password_strength_colors() {
    assert_eq!(PasswordStrength::VeryWeak.color(), "red");
    assert_eq!(PasswordStrength::Weak.color(), "yellow");
    assert_eq!(PasswordStrength::Fair.color(), "cyan");
    assert_eq!(PasswordStrength::Strong.color(), "green");
    assert_eq!(PasswordStrength::VeryStrong.color(), "bright green");
}

#[test]
fn test_password_strength_ordering() {
    assert!(PasswordStrength::VeryWeak < PasswordStrength::Weak);
    assert!(PasswordStrength::Weak < PasswordStrength::Fair);
    assert!(PasswordStrength::Fair < PasswordStrength::Strong);
    assert!(PasswordStrength::Strong < PasswordStrength::VeryStrong);
}

// ============================================================================
// BIP39 Recovery Key Tests
// ============================================================================

#[test]
fn test_recovery_key_generation() {
    use vaultic::recovery::RecoveryKey;

    let key = RecoveryKey::generate().expect("Failed to generate recovery key");

    // Should have 24 words
    assert_eq!(key.words().len(), 24);

    // Phrase should be valid
    let phrase = key.phrase();
    assert!(!phrase.is_empty());

    // Fingerprint should be first 4 words
    let fingerprint = key.fingerprint();
    let first_four: Vec<&str> = key.words().iter().take(4).copied().collect();
    assert_eq!(fingerprint, first_four.join(" "));
}

#[test]
fn test_recovery_key_from_phrase() {
    use vaultic::recovery::RecoveryKey;

    // Generate a key and get its phrase
    let original = RecoveryKey::generate().expect("Failed to generate");
    let phrase = original.phrase();

    // Parse the phrase back
    let parsed = RecoveryKey::from_phrase(&phrase).expect("Failed to parse phrase");

    // Should produce the same fingerprint
    assert_eq!(original.fingerprint(), parsed.fingerprint());
    assert_eq!(original.checksum(), parsed.checksum());
}

#[test]
fn test_recovery_key_invalid_phrase() {
    use vaultic::recovery::RecoveryKey;

    // Invalid phrases should fail
    assert!(RecoveryKey::from_phrase("not a valid phrase").is_err());
    assert!(RecoveryKey::from_phrase("abandon abandon abandon").is_err());
    assert!(RecoveryKey::from_phrase("").is_err());
}

#[test]
fn test_recovery_key_wrap_unwrap() {
    use vaultic::crypto::keys::VaultKey;
    use vaultic::crypto::wrap::unwrap_vault_key;
    use vaultic::recovery::RecoveryKey;

    // Generate a vault key
    let vault_key = VaultKey::generate();

    // Generate a recovery key
    let recovery_key = RecoveryKey::generate().expect("Failed to generate recovery key");

    // Wrap the vault key
    let (encrypted_key, salt) = recovery_key
        .wrap_vault_key(&vault_key, Some("Test Recovery".to_string()))
        .expect("Failed to wrap vault key");

    // Derive the same KEK and unwrap
    let recovery_kek = recovery_key
        .derive_kek(&salt)
        .expect("Failed to derive KEK");

    let unwrapped = unwrap_vault_key(&encrypted_key, &recovery_kek).expect("Failed to unwrap");

    // Should match original
    assert_eq!(vault_key.as_bytes(), unwrapped.as_bytes());
}

#[test]
fn test_recovery_key_different_salts() {
    use vaultic::recovery::RecoveryKey;

    let key = RecoveryKey::generate().expect("Failed to generate");

    let salt1 = [1u8; 32];
    let salt2 = [2u8; 32];

    let kek1 = key.derive_kek(&salt1).expect("Failed to derive KEK 1");
    let kek2 = key.derive_kek(&salt2).expect("Failed to derive KEK 2");

    // Different salts should produce different KEKs
    assert_ne!(kek1.as_bytes(), kek2.as_bytes());
}

#[test]
fn test_recovery_key_qr_generation() {
    use vaultic::recovery::RecoveryKey;

    let key = RecoveryKey::generate().expect("Failed to generate");

    let qr = key.generate_qr().expect("Failed to generate QR");

    // QR should contain unicode block characters
    assert!(qr.contains('█') || qr.contains('▀') || qr.contains('▄'));
    // Should be non-empty
    assert!(!qr.is_empty());
}

#[test]
fn test_recovery_key_display_formatted() {
    use vaultic::recovery::RecoveryKey;

    let key = RecoveryKey::generate().expect("Failed to generate");

    let display = key.display_formatted();

    // Should contain numbered words
    assert!(display.contains("1."));
    assert!(display.contains("24."));
    // Should be multi-line
    assert!(display.lines().count() > 1);
}

// ============================================================================
// AI Auto-Tagging Tests
// ============================================================================

#[test]
fn test_auto_tag_github_url() {
    use vaultic::ai::PasswordAi;

    let entry =
        VaultEntry::new("My GitHub", EntryType::Password).with_url("https://github.com/user/repo");

    let tags = PasswordAi::suggest_tags(&entry);
    assert!(tags.contains(&"development".to_string()));
    assert!(tags.contains(&"git".to_string()));
}

#[test]
fn test_auto_tag_social_media() {
    use vaultic::ai::PasswordAi;

    let entry =
        VaultEntry::new("Twitter Account", EntryType::Password).with_url("https://twitter.com");

    let tags = PasswordAi::suggest_tags(&entry);
    assert!(tags.contains(&"social-media".to_string()));
}

#[test]
fn test_auto_tag_finance() {
    use vaultic::ai::PasswordAi;

    let entry =
        VaultEntry::new("PayPal", EntryType::Password).with_url("https://www.paypal.com/myaccount");

    let tags = PasswordAi::suggest_tags(&entry);
    assert!(tags.contains(&"finance".to_string()));
    assert!(tags.contains(&"payment".to_string()));
}

#[test]
fn test_auto_tag_credit_card_type() {
    use vaultic::ai::PasswordAi;

    let entry = VaultEntry::new("Visa Gold Card", EntryType::CreditCard);

    let tags = PasswordAi::suggest_tags(&entry);
    assert!(tags.contains(&"finance".to_string()));
    assert!(tags.contains(&"payment".to_string()));
}

#[test]
fn test_auto_tag_ssh_key_type() {
    use vaultic::ai::PasswordAi;

    let entry = VaultEntry::new("Production Server", EntryType::SshKey);

    let tags = PasswordAi::suggest_tags(&entry);
    assert!(tags.contains(&"development".to_string()));
    assert!(tags.contains(&"infrastructure".to_string()));
}

#[test]
fn test_auto_tag_cloud_providers() {
    use vaultic::ai::PasswordAi;

    let aws_entry = VaultEntry::new("AWS Console", EntryType::Password)
        .with_url("https://console.aws.amazon.com");
    let gcp_entry =
        VaultEntry::new("GCP", EntryType::Password).with_url("https://console.cloud.google.com");
    let azure_entry =
        VaultEntry::new("Azure Portal", EntryType::Password).with_url("https://portal.azure.com");

    let aws_tags = PasswordAi::suggest_tags(&aws_entry);
    let gcp_tags = PasswordAi::suggest_tags(&gcp_entry);
    let azure_tags = PasswordAi::suggest_tags(&azure_entry);

    assert!(aws_tags.contains(&"cloud".to_string()));
    assert!(aws_tags.contains(&"aws".to_string()));
    assert!(gcp_tags.contains(&"cloud".to_string()));
    assert!(gcp_tags.contains(&"gcp".to_string()));
    assert!(azure_tags.contains(&"cloud".to_string()));
    assert!(azure_tags.contains(&"azure".to_string()));
}

#[test]
fn test_auto_tag_excludes_existing() {
    use vaultic::ai::PasswordAi;

    let entry = VaultEntry::new("GitHub", EntryType::Password)
        .with_url("https://github.com")
        .with_tags(vec!["development".to_string(), "git".to_string()]);

    let tags = PasswordAi::suggest_tags(&entry);

    // Should not suggest tags that already exist
    assert!(!tags.contains(&"development".to_string()));
    assert!(!tags.contains(&"git".to_string()));
}

#[test]
fn test_auto_tag_email_services() {
    use vaultic::ai::PasswordAi;

    let gmail_entry =
        VaultEntry::new("Gmail", EntryType::Password).with_url("https://mail.google.com");
    let outlook_entry =
        VaultEntry::new("Outlook", EntryType::Password).with_url("https://outlook.com");

    let gmail_tags = PasswordAi::suggest_tags(&gmail_entry);
    let outlook_tags = PasswordAi::suggest_tags(&outlook_entry);

    assert!(gmail_tags.contains(&"email".to_string()));
    assert!(outlook_tags.contains(&"email".to_string()));
}

#[test]
fn test_auto_tag_streaming() {
    use vaultic::ai::PasswordAi;

    let netflix_entry =
        VaultEntry::new("Netflix", EntryType::Password).with_url("https://www.netflix.com");
    let spotify_entry =
        VaultEntry::new("Spotify", EntryType::Password).with_url("https://www.spotify.com");

    let netflix_tags = PasswordAi::suggest_tags(&netflix_entry);
    let spotify_tags = PasswordAi::suggest_tags(&spotify_entry);

    assert!(netflix_tags.contains(&"entertainment".to_string()));
    assert!(netflix_tags.contains(&"streaming".to_string()));
    assert!(spotify_tags.contains(&"entertainment".to_string()));
}

// ============================================================================
// Shell Integration Tests (Phase 4)
// ============================================================================

#[test]
fn test_vault_entry_new_fields() {
    // Test that new VaultEntry fields are initialized correctly
    let entry = VaultEntry::new("Test SSH Key", EntryType::SshKey);

    assert!(entry.ssh_key_data.is_none());
    assert!(entry.env_mappings.is_empty());
}

#[test]
fn test_ssh_key_data_struct() {
    use vaultic::models::{SshKeyData, SshKeyType};

    let ssh_data = SshKeyData {
        key_type: SshKeyType::Ed25519,
        fingerprint: "SHA256:abc123".to_string(),
        public_key: Some("ssh-ed25519 AAAA...".to_string()),
        comment: Some("user@host".to_string()),
        bits: None,
    };

    assert_eq!(ssh_data.key_type, SshKeyType::Ed25519);
    assert_eq!(ssh_data.fingerprint, "SHA256:abc123");
    assert!(ssh_data.public_key.is_some());
}

#[test]
fn test_env_mapping_struct() {
    use vaultic::models::EnvMapping;

    let mapping = EnvMapping {
        env_var: "AWS_ACCESS_KEY".to_string(),
        field: "username".to_string(),
    };

    assert_eq!(mapping.env_var, "AWS_ACCESS_KEY");
    assert_eq!(mapping.field, "username");
}

#[test]
fn test_ssh_key_type_display() {
    use vaultic::models::SshKeyType;

    assert_eq!(format!("{}", SshKeyType::Ed25519), "ED25519");
    assert_eq!(format!("{}", SshKeyType::Rsa), "RSA");
    assert_eq!(format!("{}", SshKeyType::Ecdsa), "ECDSA");
    assert_eq!(format!("{}", SshKeyType::Dsa), "DSA");
    assert_eq!(format!("{}", SshKeyType::Unknown), "Unknown");
}

#[test]
fn test_vault_entry_with_ssh_data() {
    use vaultic::models::{SshKeyData, SshKeyType};

    let mut entry = VaultEntry::new("Server SSH Key", EntryType::SshKey);

    entry.ssh_key_data = Some(SshKeyData {
        key_type: SshKeyType::Rsa,
        fingerprint: "SHA256:xyz789".to_string(),
        public_key: Some("ssh-rsa AAAA...".to_string()),
        comment: Some("admin@server".to_string()),
        bits: Some(4096),
    });

    assert!(entry.ssh_key_data.is_some());
    let data = entry.ssh_key_data.as_ref().unwrap();
    assert_eq!(data.key_type, SshKeyType::Rsa);
    assert_eq!(data.bits, Some(4096));
}

#[test]
fn test_vault_entry_with_env_mappings() {
    use vaultic::models::EnvMapping;

    let mut entry = VaultEntry::new("AWS Credentials", EntryType::Password)
        .with_username("AKIAIOSFODNN7EXAMPLE")
        .with_password("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

    entry.env_mappings = vec![
        EnvMapping {
            env_var: "AWS_ACCESS_KEY_ID".to_string(),
            field: "username".to_string(),
        },
        EnvMapping {
            env_var: "AWS_SECRET_ACCESS_KEY".to_string(),
            field: "password".to_string(),
        },
    ];

    assert_eq!(entry.env_mappings.len(), 2);
    assert_eq!(entry.env_mappings[0].env_var, "AWS_ACCESS_KEY_ID");
    assert_eq!(entry.env_mappings[1].field, "password");
}

// ============================================================================
// TOTP QR Scanning Tests
// ============================================================================

#[test]
fn test_vault_entry_with_totp() {
    let (_temp_dir, mut storage, master_key) = create_test_vault();
    storage.unlock(&master_key).unwrap();

    // Create entry with TOTP
    let mut entry = VaultEntry::new("GitHub", EntryType::Password)
        .with_username("user@github.com")
        .with_password("secret123");
    entry.totp_secret = Some(SensitiveString::new("JBSWY3DPEHPK3PXP"));

    storage.add_entry(&entry).unwrap();

    // Retrieve and verify
    let entries = storage.list_entries().unwrap();
    let found = entries.iter().find(|e| e.name == "GitHub").unwrap();
    assert!(found.totp_secret.is_some());
    assert_eq!(
        found.totp_secret.as_ref().unwrap().expose(),
        "JBSWY3DPEHPK3PXP"
    );

    // Verify TOTP code generation works
    let totp = vaultic::totp::Totp::new(found.totp_secret.as_ref().unwrap().expose()).unwrap();
    let code = totp.generate().unwrap();
    assert_eq!(code.len(), 6);
}

#[test]
fn test_totp_from_uri_roundtrip() {
    let uri = "otpauth://totp/GitHub:user@github.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
    let totp = vaultic::totp::Totp::from_uri(uri).unwrap();

    assert_eq!(totp.get_issuer(), Some("GitHub"));
    assert_eq!(totp.get_account(), Some("user@github.com"));

    // Secret should roundtrip
    let secret = totp.secret_base32();
    let totp2 = vaultic::totp::Totp::new(&secret).unwrap();
    let code1 = totp.generate().unwrap();
    let code2 = totp2.generate().unwrap();
    assert_eq!(code1, code2);
}

#[test]
fn test_totp_qr_scan_roundtrip() {
    // Generate a TOTP URI and QR code, then scan it back
    let original = vaultic::totp::Totp::new("JBSWY3DPEHPK3PXP")
        .unwrap()
        .issuer("IntegrationTest")
        .account("test@example.com");
    let uri = original.to_uri();

    // Generate QR code as image
    let code = qrcode::QrCode::new(uri.as_bytes()).unwrap();
    let img = code.render::<image::Luma<u8>>().build();

    // Save to temp file
    let temp_dir = tempdir().unwrap();
    let path = temp_dir.path().join("test_totp.png");
    img.save(&path).unwrap();

    // Scan it back
    let scanned = vaultic::totp::Totp::scan_qr_image(&path).unwrap();
    assert_eq!(scanned.get_issuer(), Some("IntegrationTest"));
    assert_eq!(scanned.get_account(), Some("test@example.com"));

    // Both should generate same TOTP codes
    assert_eq!(
        original.generate_at(1000000).unwrap(),
        scanned.generate_at(1000000).unwrap()
    );
}
