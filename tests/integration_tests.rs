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
