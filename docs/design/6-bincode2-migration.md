# Design: Migrate bincode 1.3 → 2.x (issue #6)

> Status: **design only** (no code). Prepared as the design-first artifact
> required for a vault-format-adjacent change per `CONTRIBUTING.md`.

## Context

`bincode` is the serializer for **every encrypted vault record on disk**
(entries, metadata, identities, shared secrets, audit log, config values, and
the vault's own keypair), plus the portable encrypted-backup and share blobs.
Issue #6 wants it moved off the unmaintained-adjacent 1.3 line to 2.x.

The crux is **on-disk byte compatibility**: an incorrect config silently bricks
every existing user vault. This design keeps the on-disk bytes identical, so no
data migration is required.

## Approach

Adopt **bincode 2 with its `serde` compatibility feature** and the
**`bincode::config::legacy()`** configuration, keeping all existing
`#[derive(Serialize, Deserialize)]` types untouched.

`legacy()` is bincode 2's documented byte-for-byte reproduction of bincode
1.3's `bincode::serialize()` free-function config (little-endian, fixed-width
ints, `usize` → `u64`, no length limit). Result: **zero on-disk format
change**; existing vaults read and write unchanged; **no data migration**.

The only real churn is API surface (free functions removed) and error types
(`bincode::Error`/`ErrorKind` → `EncodeError`/`DecodeError`).

**Deliberately NOT** switching to bincode 2's native `Encode`/`Decode` derives:
they change the on-disk bytes (varint) and can't be derived on foreign types
(`Uuid`, `chrono::DateTime`). Not worth forcing a vault migration.

## Inventory of bincode usage

**Generic on-disk path (encrypted, sled-backed) — `src/storage/mod.rs`**
- `store_encrypted<T: Serialize>` (:213) / `load_encrypted<T: DeserializeOwned>` (:229) — generic; callers persist `VaultMetadata`, `VaultEntry`, `UserIdentity`, `SharedSecret`, `AuditLogEntry`, config `String` values, and the own keypair.
- `load_metadata` (:242) `VaultMetadata`; `list_entries` (:336) `VaultEntry`; identities (:469, :487) `UserIdentity`; shared secrets (:514) `SharedSecret`; audit log (:587) `AuditLogEntry`.
- `export_backup` (:637) / `import_backup` (:647) — `VaultBackup`.

**Portable file/wire blobs (bincode is the inner codec inside the cipher)**
- `src/export.rs` (:99 `Vec<VaultEntry>`, :116 `EncryptedBackup`) and `src/import.rs` (:45 `EncryptedBackup`, :52 `Vec<VaultEntry>`) — the `.vaultic` encrypted export file format.
- `src/sharing/mod.rs` (:113 serialize `ShareData`, :167 deserialize) — the share blob.

**Error-type usage only (NOT serialization — must still be fixed)**
- `src/storage/mod.rs:73` `StorageError::Serialization(#[from] bincode::Error)`.
- `src/sharing/mod.rs:21` `SharingError::Serialization(#[from] bincode::Error)`.
- `src/storage/keyring.rs:45,:70` and `src/storage/mod.rs:681,:694` (`KdfParamsStorage`) **abuse** `bincode::Error::from(ErrorKind::Custom(..))` to wrap `serde_json` errors. Keyring and `kdf_params.json` are stored as **serde_json**, not bincode. bincode 2 removes `bincode::Error`/`ErrorKind`, so this abuse must be replaced regardless.

Sessions use `serde_json`, not bincode (no change).

## bincode 1 → 2 API differences

- **Free functions removed.** `bincode::serialize(v)` → `bincode::serde::encode_to_vec(v, config)`; `bincode::deserialize(b)` → `bincode::serde::decode_from_slice(b, config).map(|(v, _len)| v)` (discard the trailing bytes-read `usize`). Requires `features = ["serde"]`.
- **Config is explicit.** No implicit default; every call takes a `Config`. Use `bincode::config::legacy()`.
- **serde compat vs `Encode`/`Decode`.** Native derives change bytes (varint) and can't apply to `Uuid`/`DateTime` — rejected. serde-compat keeps existing derives and, under `legacy()`, matches 1.3 output.
- **Errors.** `bincode::Error` (`Box<ErrorKind>`) → separate `bincode::error::EncodeError` and `bincode::error::DecodeError`.

## On-disk format impact (the crux)

With `features = ["serde"]` + `bincode::config::legacy()`, output is
**byte-identical** to bincode 1.3's `bincode::serialize()` because:
- `legacy()` = little-endian + fixint + `usize` as `u64` + unlimited length — the exact config the 1.3 free function used (the 1.3 `DefaultOptions` varint path was never used here).
- Enum discriminants stay `u32` fixint; `Option` stays 1-byte tag + payload; both versions' serde adapters report `is_human_readable() == false`, so `Uuid` (16-byte compact) and `chrono::DateTime` behave identically.

**No data migration required; fully read/write compatible.** This must be
*proven*, not assumed — see the golden-vector gate. If (and only if) it fails,
fall back to keeping a bincode-1 read path — not expected.

## Migration + rollback

Format is unchanged, so no per-vault runtime migration and **no functional
change to `src/migration/mod.rs`**. Reuse its timestamped-backup + rollback
pattern only as the safety net for the dependency bump itself:
- Runtime "old vault" detection is a non-issue (bytes match).
- Rollback of the change = `git revert` the bump; user data is never rewritten.
- Leave `VaultMigrator::backup_kdf_params`/`rollback` (`src/migration/mod.rs:154`, `:169`) untouched — orthogonal v1→v2 keyring migration.

## Steps for the implementer

1. `Cargo.toml:53` — `bincode = "1.3"` → `bincode = { version = "2", features = ["serde"] }`.
2. Add an internal helper (e.g. `src/serde_compat.rs`): `encode<T: Serialize>(&T) -> Result<Vec<u8>, EncodeError>` and `decode<T: DeserializeOwned>(&[u8]) -> Result<T, DecodeError>`, both hard-coding `bincode::config::legacy()`. Centralizes the config so it can never drift per call site. **This is the single most important risk control.**
3. `src/storage/mod.rs` — replace `serialize`/`deserialize` at :213, :229, :242, :336, :469, :487, :514, :587, :637, :647 with the helper. Split `StorageError::Serialization` (:73) into `Encode(#[from] EncodeError)` and `Decode(#[from] DecodeError)`; add a `Json(String)` variant.
4. `src/storage/mod.rs:681,:694` + `src/storage/keyring.rs:45,:70` — replace the `bincode::Error::from(ErrorKind::Custom(..))` abuse with `StorageError::Json(e.to_string())`.
5. `src/sharing/mod.rs` — :113/:167 use the helper; split `SharingError::Serialization` (:21).
6. `src/export.rs` :99, :116 and `src/import.rs` :45, :52 — swap to helper; map errors into existing `String` error variants.
7. `cargo build --release`, `cargo clippy`, `cargo fmt`.
8. Regenerate `Cargo.lock`; `cargo audit` to confirm the advisory clears.

## Out of scope

- Native `Encode`/`Decode` derives / varint `standard()` config (would force a vault migration).
- `src/migration/mod.rs` logic, sessions (`serde_json`), keyring/kdf on-disk format (`serde_json`).
- Refactoring `store_encrypted`/`load_encrypted` signatures beyond routing through the helper.

## Test strategy

- **Golden-vector byte test (the gate):** commit a bincode-1.3-serialized `VaultEntry` (+ `VaultMetadata`, `SharedSecret`) as a hex fixture; assert bincode-2 `legacy()` produces identical bytes and decodes it back. This proves existing vaults are safe.
- **Round-trip unit tests** per type (`VaultEntry` with `#[serde(default)]` fields present and absent, `VaultMetadata`, `UserIdentity`, `SharedSecret`, `AuditLogEntry`, `ShareData`, `EncryptedBackup`).
- **Cross-version vault test:** generate a sled vault with the pre-bump binary, commit as fixture, then unlock + `list_entries` + `get` with the post-bump binary.
- Full existing suite green; export→import and share→open round-trips end-to-end.

## Risks

- **Silent format drift** if a call site forgets `legacy()` — mitigated by the centralized helper (step 2). Highest-severity risk.
- **`decode_from_slice` trailing-length** — forgetting to discard the `usize` compiles wrong; covered by round-trip tests.
- **Error-variant fan-out** — many `?` sites depend on `From<bincode::Error>`; a missing conversion is a compile error, not a runtime bug (low risk).
