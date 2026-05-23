//! Benchmarks for vault storage operations against a 10k-entry vault.
//!
//! Run with `cargo bench --bench vault_ops`. The vault is built once per
//! benchmark group using a deterministic RNG so runs are comparable.

use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tempfile::TempDir;
use uuid::Uuid;

use vaultic::crypto::MasterKey;
use vaultic::models::{EntryType, KdfParams, SearchFilter, SensitiveString, VaultEntry};
use vaultic::storage::VaultStorage;

const ENTRY_COUNT: usize = 10_000;
const SEED: u64 = 0xC0FFEE_BEEF_42_42;

/// Deterministic test fixture: builds a vault directory with `count` entries
/// and returns it along with the master key used to encrypt them.
struct Fixture {
    _dir: TempDir,
    path: PathBuf,
    key: MasterKey,
    sample_ids: Vec<Uuid>,
    sample_names: Vec<String>,
}

fn build_fixture(count: usize) -> Fixture {
    // Place the vault inside a tempdir, but never let it pre-exist —
    // VaultStorage::create rejects an existing path.
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("vault");
    let key = MasterKey::from_bytes([0x11; 32]);

    let mut storage = VaultStorage::create(
        &path,
        "bench",
        &key,
        KdfParams::default(),
        "bench-owner".to_string(),
    )
    .expect("create");

    let mut rng = StdRng::seed_from_u64(SEED);
    let mut sample_ids = Vec::with_capacity(64);
    let mut sample_names = Vec::with_capacity(64);

    for i in 0..count {
        let entry = make_entry(i, &mut rng);
        if i % (count / 64).max(1) == 0 && sample_ids.len() < 64 {
            sample_ids.push(entry.id);
            sample_names.push(entry.name.clone());
        }
        storage.add_entry(&entry).expect("add");
    }

    drop(storage);

    Fixture {
        _dir: dir,
        path,
        key,
        sample_ids,
        sample_names,
    }
}

fn make_entry(i: usize, rng: &mut StdRng) -> VaultEntry {
    let providers = [
        "GitHub",
        "GitLab",
        "AWS",
        "Azure",
        "Google",
        "Slack",
        "Linear",
        "Notion",
        "Stripe",
        "Twilio",
        "DataDog",
        "Cloudflare",
        "PagerDuty",
        "Sentry",
        "Vercel",
        "Heroku",
    ];
    let provider = providers[i % providers.len()];
    let suffix: u32 = rng.gen_range(0..1_000_000);
    let name = format!("{} acct {:06}", provider, suffix);

    let mut entry = VaultEntry::new(name, EntryType::Password);
    entry.username = Some(format!("user{}@example.com", i));
    entry.password = Some(SensitiveString::new(random_password(rng)));
    entry.url = Some(format!(
        "https://{}.example.com/login",
        provider.to_lowercase()
    ));
    entry.tags = pick_tags(i);
    entry.folder = Some(if i % 3 == 0 { "personal" } else { "work" }.to_string());
    entry.favorite = i % 50 == 0;
    entry
}

fn random_password(rng: &mut StdRng) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    (0..20)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn pick_tags(i: usize) -> Vec<String> {
    let pool = [
        "prod", "staging", "dev", "shared", "infra", "billing", "ops", "personal", "team",
    ];
    let take = (i % 4) + 1;
    pool.iter()
        .skip(i % pool.len())
        .chain(pool.iter())
        .take(take)
        .map(|s| s.to_string())
        .collect()
}

fn open_unlocked(fixture: &Fixture) -> VaultStorage {
    let mut storage = VaultStorage::open(&fixture.path).expect("open");
    storage.unlock(&fixture.key).expect("unlock");
    storage
}

fn bench_list_all(c: &mut Criterion) {
    let fixture = build_fixture(ENTRY_COUNT);
    let storage = open_unlocked(&fixture);

    let mut group = c.benchmark_group("list_all_10k");
    group.sample_size(10);
    group.bench_function("list_entries", |b| {
        b.iter(|| {
            let entries = storage.list_entries().expect("list");
            assert_eq!(entries.len(), ENTRY_COUNT);
            entries
        });
    });
    group.finish();
}

fn bench_search(c: &mut Criterion) {
    let fixture = build_fixture(ENTRY_COUNT);
    let storage = open_unlocked(&fixture);
    let known_query = fixture.sample_names[0]
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();

    let mut group = c.benchmark_group("search_10k");
    group.sample_size(10);

    group.bench_function("by_name_hit", |b| {
        let filter = SearchFilter::new().with_query(&known_query);
        b.iter(|| storage.search_entries(&filter).expect("search"));
    });

    group.bench_function("by_name_miss", |b| {
        let filter = SearchFilter::new().with_query("zzz_not_in_vault_zzz");
        b.iter(|| storage.search_entries(&filter).expect("search"));
    });

    group.bench_function("fuzzy_short", |b| {
        let filter = SearchFilter::new().with_query("git");
        b.iter(|| storage.search_entries(&filter).expect("search"));
    });

    group.bench_function("fuzzy_typo", |b| {
        let filter = SearchFilter::new().with_query("gthb");
        b.iter(|| storage.search_entries(&filter).expect("search"));
    });

    group.finish();
}

fn bench_get(c: &mut Criterion) {
    let fixture = build_fixture(ENTRY_COUNT);
    let storage = open_unlocked(&fixture);
    let id = fixture.sample_ids[fixture.sample_ids.len() / 2];

    let mut group = c.benchmark_group("get_10k");
    group.bench_function("get_by_id", |b| {
        b.iter(|| storage.get_entry(&id).expect("get"));
    });
    group.finish();
}

fn bench_add(c: &mut Criterion) {
    let fixture = build_fixture(ENTRY_COUNT);
    // Hold one storage handle open: opening sled on macOS briefly retains
    // its file lock after drop, which causes `iter_batched` setups to
    // race themselves with WouldBlock when each iteration reopens the db.
    let mut storage = open_unlocked(&fixture);
    let mut rng = StdRng::seed_from_u64(SEED ^ 0xA5A5A5A5);
    let mut counter = ENTRY_COUNT;

    let mut group = c.benchmark_group("add_into_10k_vault");
    group.sample_size(10);
    group.bench_function("add_entry", |b| {
        b.iter_batched(
            || {
                counter += 1;
                make_entry(counter, &mut rng)
            },
            |entry| {
                storage.add_entry(&entry).expect("add");
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_unlock(c: &mut Criterion) {
    // Measures the cost of validating a master key against an already-open
    // sled handle: HKDF derivation + AEAD decrypt of the metadata blob.
    // Reusing one open handle avoids macOS's sled file-lock retention from
    // racing rapid open/drop cycles.
    let fixture = build_fixture(ENTRY_COUNT);
    let mut storage = VaultStorage::open(&fixture.path).expect("open");

    let mut group = c.benchmark_group("unlock_10k");
    group.bench_function("unlock", |b| {
        b.iter(|| {
            storage.unlock(&fixture.key).expect("unlock");
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_list_all,
    bench_search,
    bench_get,
    bench_add,
    bench_unlock
);
criterion_main!(benches);
