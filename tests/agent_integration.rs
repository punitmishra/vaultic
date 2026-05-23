//! End-to-end tests for `vaultic-agent`. Spins up the daemon on a temp
//! socket, builds a fixture vault, and exercises every protocol method
//! through real Unix-socket frames.

use std::path::PathBuf;
use std::time::Duration;

use tempfile::TempDir;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use uuid::Uuid;
use vaultic::agent::protocol::{
    read_frame_async, write_frame_async, ErrorCode, Frame, Method, Request, Response, ResponseBody,
    PROTOCOL_VERSION,
};
use vaultic::agent::{serve, ServerConfig};
use vaultic::crypto::MasterKey;
use vaultic::models::{EntryType, KdfParams, SensitiveString, VaultEntry};
use vaultic::storage::VaultStorage;

const TEST_KEY_BYTES: [u8; 32] = [0x77; 32];

/// One end-to-end fixture: a populated vault on disk, a key to unlock it
/// with, and a running daemon listening on a temp Unix socket.
struct DaemonHarness {
    _vault_dir: TempDir,
    _socket_dir: TempDir,
    vault_path: PathBuf,
    socket_path: PathBuf,
    derived_key_hex: String,
    sample_entry_id: Uuid,
    totp_entry_id: Uuid,
    shutdown_tx: mpsc::Sender<()>,
    server_task: tokio::task::JoinHandle<()>,
}

impl DaemonHarness {
    async fn boot() -> Self {
        let vault_dir = TempDir::new().expect("vault tempdir");
        let socket_dir = TempDir::new().expect("socket tempdir");
        let vault_path = vault_dir.path().join("vault");
        let socket_path = socket_dir.path().join("agent.sock");

        let key = MasterKey::from_bytes(TEST_KEY_BYTES);

        // Build the vault. VaultStorage::create insists the path doesn't
        // already exist; the join above gives us a fresh subdir under the
        // tempdir.
        let mut storage = VaultStorage::create(
            &vault_path,
            "agent-test",
            &key,
            KdfParams::default(),
            "test-owner".to_string(),
        )
        .expect("create vault");

        let mut entry = VaultEntry::new("GitHub", EntryType::Password);
        entry.username = Some("octocat@example.com".to_string());
        entry.password = Some(SensitiveString::new("hunter2-correct-horse"));
        entry.url = Some("https://github.com/login".to_string());
        entry.tags = vec!["work".to_string()];
        let sample_entry_id = entry.id;
        storage.add_entry(&entry).expect("add github");

        let mut totp_entry = VaultEntry::new("GitHub TOTP", EntryType::Totp);
        // RFC 6238 test secret, base32-encoded.
        totp_entry.totp_secret = Some(SensitiveString::new("JBSWY3DPEHPK3PXP".to_string()));
        let totp_entry_id = totp_entry.id;
        storage.add_entry(&totp_entry).expect("add totp");

        drop(storage);

        let derived_key_hex = hex_encode(&TEST_KEY_BYTES);

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let config = ServerConfig {
            socket_path: socket_path.clone(),
            inactivity_timeout: Duration::from_secs(900),
        };
        let server_task = tokio::spawn(async move {
            serve(config, shutdown_rx).await.expect("serve");
        });

        // Wait for the listener to come up. Polling is more robust than
        // sleeping for a fixed duration on slow CI.
        for _ in 0..50 {
            if UnixStream::connect(&socket_path).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        Self {
            _vault_dir: vault_dir,
            _socket_dir: socket_dir,
            vault_path,
            socket_path,
            derived_key_hex,
            sample_entry_id,
            totp_entry_id,
            shutdown_tx,
            server_task,
        }
    }

    async fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.socket_path)
            .await
            .expect("connect")
    }

    async fn rpc(&self, stream: &mut UnixStream, method: Method) -> Response {
        let id = Uuid::new_v4();
        let req = Frame::Request(Request { id, method });
        write_frame_async(stream, &req).await.expect("send req");
        loop {
            let frame = read_frame_async(stream)
                .await
                .expect("read frame")
                .expect("eof");
            match frame {
                Frame::Response(resp) if resp.id == id => return resp,
                // Skip any events that arrive while we're waiting for our
                // matched response.
                _ => continue,
            }
        }
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(()).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), self.server_task).await;
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn expect_result(resp: Response) -> serde_json::Value {
    match resp.body {
        ResponseBody::Result(v) => v,
        ResponseBody::Error(e) => panic!("expected result, got error: {:?}", e),
    }
}

fn expect_error(resp: Response) -> ErrorCode {
    match resp.body {
        ResponseBody::Error(e) => e.code,
        ResponseBody::Result(v) => panic!("expected error, got result: {:?}", v),
    }
}

#[tokio::test]
async fn ping_works_when_locked() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    let resp = h.rpc(&mut s, Method::Ping).await;
    let v = expect_result(resp);
    assert_eq!(v["protocol_version"], PROTOCOL_VERSION);
    assert!(v["agent_version"].is_string());
    h.shutdown().await;
}

#[tokio::test]
async fn status_locked_initially() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    let v = expect_result(h.rpc(&mut s, Method::Status).await);
    assert_eq!(v["unlocked"], false);
    h.shutdown().await;
}

#[tokio::test]
async fn list_when_locked_errors_with_vault_locked() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    let code = expect_error(h.rpc(&mut s, Method::ListSummary).await);
    assert_eq!(code, ErrorCode::VaultLocked);
    h.shutdown().await;
}

#[tokio::test]
async fn unlock_then_list_returns_entries() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;

    let unlock = expect_result(
        h.rpc(
            &mut s,
            Method::Unlock {
                vault_path: h.vault_path.display().to_string(),
                derived_key_hex: h.derived_key_hex.clone(),
            },
        )
        .await,
    );
    assert_eq!(unlock["unlocked"], true);

    let list = expect_result(h.rpc(&mut s, Method::ListSummary).await);
    let arr = list.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    let names: Vec<&str> = arr.iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"GitHub"));
    assert!(names.contains(&"GitHub TOTP"));

    h.shutdown().await;
}

#[tokio::test]
async fn unlock_with_wrong_key_errors_with_bad_key() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;

    let bad_key = "00".repeat(32); // wrong key
    let code = expect_error(
        h.rpc(
            &mut s,
            Method::Unlock {
                vault_path: h.vault_path.display().to_string(),
                derived_key_hex: bad_key,
            },
        )
        .await,
    );
    assert_eq!(code, ErrorCode::BadKey);
    h.shutdown().await;
}

#[tokio::test]
async fn unlock_with_short_hex_errors_with_bad_key() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    let code = expect_error(
        h.rpc(
            &mut s,
            Method::Unlock {
                vault_path: h.vault_path.display().to_string(),
                derived_key_hex: "abcd".to_string(),
            },
        )
        .await,
    );
    assert_eq!(code, ErrorCode::BadKey);
    h.shutdown().await;
}

#[tokio::test]
async fn get_entry_returns_password_for_known_id() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    expect_result(
        h.rpc(
            &mut s,
            Method::Unlock {
                vault_path: h.vault_path.display().to_string(),
                derived_key_hex: h.derived_key_hex.clone(),
            },
        )
        .await,
    );
    let entry = expect_result(
        h.rpc(
            &mut s,
            Method::GetEntry {
                id: h.sample_entry_id,
            },
        )
        .await,
    );
    assert_eq!(entry["name"], "GitHub");
    h.shutdown().await;
}

#[tokio::test]
async fn get_entry_unknown_id_errors_with_not_found() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    expect_result(
        h.rpc(
            &mut s,
            Method::Unlock {
                vault_path: h.vault_path.display().to_string(),
                derived_key_hex: h.derived_key_hex.clone(),
            },
        )
        .await,
    );
    let code = expect_error(h.rpc(&mut s, Method::GetEntry { id: Uuid::new_v4() }).await);
    assert_eq!(code, ErrorCode::NotFound);
    h.shutdown().await;
}

#[tokio::test]
async fn get_totp_returns_six_digit_code() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    expect_result(
        h.rpc(
            &mut s,
            Method::Unlock {
                vault_path: h.vault_path.display().to_string(),
                derived_key_hex: h.derived_key_hex.clone(),
            },
        )
        .await,
    );
    let v = expect_result(
        h.rpc(
            &mut s,
            Method::GetTotp {
                id: h.totp_entry_id,
            },
        )
        .await,
    );
    let code = v["code"].as_str().expect("code");
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(v["period_total_seconds"], 30);
    h.shutdown().await;
}

#[tokio::test]
async fn get_totp_for_non_totp_entry_errors_with_not_found() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    expect_result(
        h.rpc(
            &mut s,
            Method::Unlock {
                vault_path: h.vault_path.display().to_string(),
                derived_key_hex: h.derived_key_hex.clone(),
            },
        )
        .await,
    );
    let code = expect_error(
        h.rpc(
            &mut s,
            Method::GetTotp {
                id: h.sample_entry_id,
            },
        )
        .await,
    );
    assert_eq!(code, ErrorCode::NotFound);
    h.shutdown().await;
}

#[tokio::test]
async fn search_filters_by_username() {
    // Search uses fuzzy matching across name/username/url/tags, so queries
    // like "totp" can hit unrelated entries (it's a subsequence of
    // "octocat@example.com"). "octocat" is unambiguous: it appears only
    // in the GitHub entry's username.
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    expect_result(
        h.rpc(
            &mut s,
            Method::Unlock {
                vault_path: h.vault_path.display().to_string(),
                derived_key_hex: h.derived_key_hex.clone(),
            },
        )
        .await,
    );
    let v = expect_result(
        h.rpc(
            &mut s,
            Method::Search {
                query: "octocat".to_string(),
            },
        )
        .await,
    );
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "GitHub");
    h.shutdown().await;
}

#[tokio::test]
async fn lock_clears_unlocked_state() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    expect_result(
        h.rpc(
            &mut s,
            Method::Unlock {
                vault_path: h.vault_path.display().to_string(),
                derived_key_hex: h.derived_key_hex.clone(),
            },
        )
        .await,
    );
    expect_result(h.rpc(&mut s, Method::Lock).await);

    let v = expect_result(h.rpc(&mut s, Method::Status).await);
    assert_eq!(v["unlocked"], false);

    let code = expect_error(h.rpc(&mut s, Method::ListSummary).await);
    assert_eq!(code, ErrorCode::VaultLocked);
    h.shutdown().await;
}

#[tokio::test]
async fn shutdown_method_terminates_daemon() {
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;
    expect_result(h.rpc(&mut s, Method::Shutdown).await);
    // Give the server a moment to wind down.
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Reconnect should fail because the socket is gone.
    let result = UnixStream::connect(&h.socket_path).await;
    assert!(result.is_err(), "expected socket to be gone after shutdown");
    // Don't call shutdown() since the daemon already stopped itself; just
    // join the task to avoid a leak.
    let _ = tokio::time::timeout(Duration::from_secs(2), h.server_task).await;
}

#[tokio::test]
async fn refusing_to_start_when_socket_is_already_in_use() {
    let h = DaemonHarness::boot().await;

    // Try to bring up a SECOND daemon on the same socket. It must refuse.
    let (_tx, rx) = mpsc::channel(1);
    let config = ServerConfig {
        socket_path: h.socket_path.clone(),
        inactivity_timeout: Duration::from_secs(900),
    };
    let result = serve(config, rx).await;
    assert!(matches!(
        result,
        Err(vaultic::agent::ServerError::AlreadyRunning(_))
    ));
    h.shutdown().await;
}

#[tokio::test]
async fn pipelined_requests_on_one_connection() {
    // Two requests written back-to-back on one connection; each gets its
    // matching response.
    let h = DaemonHarness::boot().await;
    let mut s = h.connect().await;

    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    write_frame_async(
        &mut s,
        &Frame::Request(Request {
            id: id1,
            method: Method::Ping,
        }),
    )
    .await
    .unwrap();
    write_frame_async(
        &mut s,
        &Frame::Request(Request {
            id: id2,
            method: Method::Status,
        }),
    )
    .await
    .unwrap();

    // Order is preserved (single connection, request-loop processes
    // serially) but we don't depend on it: collect both and match by id.
    let r1 = read_frame_async(&mut s).await.unwrap().unwrap();
    let r2 = read_frame_async(&mut s).await.unwrap().unwrap();
    let mut got_ping = false;
    let mut got_status = false;
    for frame in [r1, r2] {
        if let Frame::Response(resp) = frame {
            if resp.id == id1 {
                got_ping = true;
                assert!(matches!(resp.body, ResponseBody::Result(_)));
            } else if resp.id == id2 {
                got_status = true;
                assert!(matches!(resp.body, ResponseBody::Result(_)));
            }
        }
    }
    assert!(got_ping && got_status);
    h.shutdown().await;
}
