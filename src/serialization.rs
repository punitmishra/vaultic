//! Centralized bincode serialization for on-disk and wire formats.
//!
//! Every persisted/transported bincode value in Vaultic goes through
//! [`encode`] / [`decode`], which hard-code [`bincode::config::legacy()`].
//! That configuration (fixed-width integers, little-endian, no byte limit)
//! is byte-for-byte compatible with the `bincode::serialize` /
//! `bincode::deserialize` free functions from bincode 1.x, so upgrading the
//! crate to 2.x requires **no vault migration**: existing vault records,
//! encrypted backups, and share blobs decode unchanged, and newly written
//! bytes are identical to what 1.x produced.
//!
//! Routing every call site through this one module is the single most
//! important safeguard against per-site configuration drift — no other code
//! is permitted to call `bincode::*` directly.
//!
//! The byte-equality guarantee is enforced by the golden-vector tests below,
//! whose expected constants were captured from bincode 1.3 before the upgrade.

use serde::de::DeserializeOwned;
use serde::Serialize;

pub use bincode::error::{DecodeError, EncodeError};

/// Serialize `value` with bincode's legacy (1.x-compatible) configuration.
///
/// `?Sized` mirrors bincode 1.x's `serialize`, so slices such as
/// `&[VaultEntry]` can be encoded directly.
pub fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, EncodeError> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy())
}

/// Deserialize a `T` from `bytes` with bincode's legacy (1.x-compatible)
/// configuration. Trailing bytes past the first value are ignored, matching
/// how these buffers are produced (exactly one value per encrypted blob).
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    bincode::serde::decode_from_slice(bytes, bincode::config::legacy()).map(|(value, _)| value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{BackupMetadata, EncryptedBackup};
    use crate::models::{
        CustomField, EntryType, EnvMapping, KdfParams, PasswordHistoryEntry, PasswordStrength,
        SensitiveString, SshKeyData, SshKeyType, VaultEntry, VaultMetadata,
    };
    use crate::sharing::ShareData;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    // === Golden byte-vectors captured from bincode 1.3 (`bincode::serialize`) ===
    // If any of these assertions fail after a bincode upgrade, the on-disk /
    // wire format changed and existing vaults would NOT decode. Do not "fix"
    // the test by regenerating the constant — investigate the format change.
    const GOLDEN_VAULT_ENTRY: &str = "10000000000000000123456789abcdef0123456789abcdef07000000060000000000000073657276657206000000000000004769744875620107000000000000006f63746f636174010b0000000000000068756e74657232f09f949001120000000000000068747470733a2f2f6769746875622e636f6d010f000000000000007072696d617279206163636f756e7402000000000000000400000000000000776f726b0300000000000000646576010b00000000000000456e67696e656572696e67010000000000000008000000000000007265636f766572790900000000000000636f6465732d313233010110000000000000004a425357593344504548504b335058501400000000000000323032302d30392d31335431323a32363a34305a1400000000000000323032302d30392d31335431323a33353a30305a011400000000000000323032302d30392d31345431363a31333a32305a00010300000001015a0000000100000000000000070000000000000066703a61626364010000000000000008000000000000006f6c642d706173731400000000000000323032302d30392d30315432323a34303a30305a01000000000b000000000000005348413235363a616263640110000000000000007373682d6564323535313920414141410001000100000100000000000000080000000000000047485f544f4b454e080000000000000070617373776f7264";
    const GOLDEN_VAULT_METADATA: &str = "1000000000000000feedfacecafebeef001122334455667708000000000000004d79205661756c741400000000000000323032302d30392d31335431323a32363a34305a1400000000000000323032302d30392d31335431323a32363a34315a020000002a000000000000001300000000000000303031313a323233333a343435353a3636373712000000000000005843686143686132302d506f6c793133303508000000000000006172676f6e32696400000100030000000400000008000000000000000102030405060708";
    const GOLDEN_SHARE_DATA: &str = "10000000000000000123456789abcdef0123456789abcdef0600000000000000476974487562000000000107000000000000006f63746f63617401070000000000000068756e7465723201120000000000000068747470733a2f2f6769746875622e636f6d00010000000000000001000000000000006b01000000000000007600001400000000000000323032302d30392d31335431323a32363a34305a0500000000000000416c696365";
    const GOLDEN_ENCRYPTED_BACKUP: &str = "010000001400000000000000323032302d30392d31335431323a32363a34305a03000000000000000500000000000000322e322e300700000000000000deadbeef000102";

    fn fixed_dt(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("valid fixed timestamp")
    }

    fn fixed_uuid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn golden_vault_entry() -> VaultEntry {
        VaultEntry {
            id: fixed_uuid(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            entry_type: EntryType::Custom("server".to_string()),
            name: "GitHub".to_string(),
            username: Some("octocat".to_string()),
            password: Some(SensitiveString::new("hunter2🔐")),
            url: Some("https://github.com".to_string()),
            notes: Some(SensitiveString::new("primary account")),
            tags: vec!["work".to_string(), "dev".to_string()],
            folder: Some("Engineering".to_string()),
            custom_fields: vec![CustomField {
                name: "recovery".to_string(),
                value: SensitiveString::new("codes-123"),
                is_hidden: true,
            }],
            totp_secret: Some(SensitiveString::new("JBSWY3DPEHPK3PXP")),
            created_at: fixed_dt(1_600_000_000),
            updated_at: fixed_dt(1_600_000_500),
            last_accessed: Some(fixed_dt(1_600_100_000)),
            password_changed_at: None,
            password_strength: Some(PasswordStrength::Strong),
            favorite: true,
            rotation_days: Some(90),
            shared_with: vec!["fp:abcd".to_string()],
            password_history: vec![PasswordHistoryEntry {
                password: SensitiveString::new("old-pass"),
                changed_at: fixed_dt(1_599_000_000),
            }],
            ssh_key_data: Some(SshKeyData {
                key_type: SshKeyType::Ed25519,
                fingerprint: "SHA256:abcd".to_string(),
                public_key: Some("ssh-ed25519 AAAA".to_string()),
                comment: None,
                bits: Some(256),
            }),
            env_mappings: vec![EnvMapping {
                env_var: "GH_TOKEN".to_string(),
                field: "password".to_string(),
            }],
        }
    }

    fn golden_vault_metadata() -> VaultMetadata {
        VaultMetadata {
            id: fixed_uuid(0xfeed_face_cafe_beef_0011_2233_4455_6677),
            name: "My Vault".to_string(),
            created_at: fixed_dt(1_600_000_000),
            updated_at: fixed_dt(1_600_000_001),
            version: 2,
            entry_count: 42,
            owner_fingerprint: "0011:2233:4455:6677".to_string(),
            encryption_algo: "XChaCha20-Poly1305".to_string(),
            kdf_params: KdfParams {
                algorithm: "argon2id".to_string(),
                memory_cost: 65536,
                time_cost: 3,
                parallelism: 4,
                salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            },
        }
    }

    fn golden_share_data() -> ShareData {
        ShareData {
            entry_id: fixed_uuid(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            name: "GitHub".to_string(),
            entry_type: EntryType::Password,
            username: Some("octocat".to_string()),
            password: Some("hunter2".to_string()),
            url: Some("https://github.com".to_string()),
            notes: None,
            custom_fields: vec![("k".to_string(), "v".to_string(), false)],
            totp_secret: None,
            shared_at: fixed_dt(1_600_000_000),
            sender_name: "Alice".to_string(),
        }
    }

    fn golden_encrypted_backup() -> EncryptedBackup {
        EncryptedBackup {
            metadata: BackupMetadata {
                version: 1,
                exported_at: fixed_dt(1_600_000_000),
                entry_count: 3,
                app_version: "2.2.0".to_string(),
            },
            encrypted_data: vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02],
        }
    }

    // --- The gate: bincode 2 `legacy()` must reproduce bincode 1.3 bytes ---

    #[test]
    fn golden_vault_entry_bytes_match_bincode_1_3() {
        assert_eq!(
            to_hex(&encode(&golden_vault_entry()).unwrap()),
            GOLDEN_VAULT_ENTRY
        );
    }

    #[test]
    fn golden_vault_metadata_bytes_match_bincode_1_3() {
        assert_eq!(
            to_hex(&encode(&golden_vault_metadata()).unwrap()),
            GOLDEN_VAULT_METADATA
        );
    }

    #[test]
    fn golden_share_data_bytes_match_bincode_1_3() {
        assert_eq!(
            to_hex(&encode(&golden_share_data()).unwrap()),
            GOLDEN_SHARE_DATA
        );
    }

    #[test]
    fn golden_encrypted_backup_bytes_match_bincode_1_3() {
        assert_eq!(
            to_hex(&encode(&golden_encrypted_backup()).unwrap()),
            GOLDEN_ENCRYPTED_BACKUP
        );
    }

    // --- Round-trips: decode(encode(x)) reproduces the same bytes ---

    fn assert_roundtrips<T>(value: &T)
    where
        T: Serialize + DeserializeOwned,
    {
        let bytes = encode(value).unwrap();
        let decoded: T = decode(&bytes).unwrap();
        assert_eq!(encode(&decoded).unwrap(), bytes);
    }

    #[test]
    fn vault_entry_roundtrips() {
        assert_roundtrips(&golden_vault_entry());
    }

    #[test]
    fn vault_metadata_roundtrips() {
        assert_roundtrips(&golden_vault_metadata());
    }

    #[test]
    fn share_data_roundtrips() {
        assert_roundtrips(&golden_share_data());
    }

    #[test]
    fn encrypted_backup_roundtrips() {
        assert_roundtrips(&golden_encrypted_backup());
    }

    /// Decoding the exact bytes bincode 1.3 wrote must succeed — this is the
    /// "a v2.2-created vault still unlocks" guarantee in miniature.
    #[test]
    fn decodes_bincode_1_3_bytes() {
        let bytes = hex_to_bytes(GOLDEN_VAULT_ENTRY);
        let entry: VaultEntry = decode(&bytes).unwrap();
        assert_eq!(entry.name, "GitHub");
        assert_eq!(entry.username.as_deref(), Some("octocat"));
        assert_eq!(entry.password.as_ref().unwrap().expose(), "hunter2🔐");
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
