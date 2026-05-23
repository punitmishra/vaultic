//! Wire protocol for `vaultic-agent`.
//!
//! Messages are framed: 4-byte little-endian length prefix followed by a UTF-8
//! JSON payload. Maximum frame size is 1 MiB. The framing format matches Chrome
//! native messaging so a future browser extension can talk to the same daemon
//! over the same wire (with a different transport).
//!
//! Every interaction is a request/response pair carrying a stable `id` so
//! clients can pipeline multiple in-flight requests over one connection. The
//! daemon may also push unsolicited `event` frames (lock-on-timeout etc.).
//!
//! See `docs/AGENT_PROTOCOL.md` for the canonical specification.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Bumped whenever the wire format changes in a backwards-incompatible way.
/// Clients send their version in `ping`; daemons that disagree refuse the
/// connection with `protocol_mismatch`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum frame size accepted on the wire. Larger frames are rejected as a
/// safety measure against malformed or malicious peers; no legitimate message
/// should approach this size.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

// ============ Top-level frame ============

/// One wire frame. Either a client `request`, a daemon `response`, or a
/// daemon-pushed `event`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    Request(Request),
    Response(Response),
    Event(Event),
}

// ============ Requests ============

/// A client-initiated request. The `id` is echoed back in the matching
/// `Response`; `kind` carries method name and parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: Uuid,
    #[serde(flatten)]
    pub method: Method,
}

/// Method signatures the daemon understands.
///
/// `unlock` takes a 32-byte derived key (hex-encoded). The client is
/// responsible for running Argon2id against the user's password using the
/// vault's `kdf_params.json`. The daemon never sees the raw password — see
/// the threat-model section of `docs/AGENT_PROTOCOL.md` for the rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Method {
    /// Liveness check. Returns daemon version + protocol version.
    Ping,

    /// Vault state. No params.
    Status,

    /// Open the vault and store the unlocked key in daemon memory.
    Unlock {
        /// Filesystem path to the vault directory.
        vault_path: String,
        /// Argon2id-derived master key, 32 bytes hex-encoded (64 chars).
        /// The daemon zeroes the encoded string after parsing.
        derived_key_hex: String,
    },

    /// Drop the unlocked key from daemon memory.
    Lock,

    /// Summary list of all entries (no passwords or notes).
    /// Returns `Vec<EntrySummary>` ordered by name.
    ListSummary,

    /// Fetch one entry by id, including secret fields. Daemon must be
    /// unlocked. Caller is expected to display+forget; daemon does not
    /// log this access (caller may, if desired).
    GetEntry { id: Uuid },

    /// Compute the current TOTP code for an entry that has a totp_secret.
    /// Returns `TotpView` (code + remaining seconds in current period).
    GetTotp { id: Uuid },

    /// Filtered list. Same shape as `ListSummary` but applies a fuzzy
    /// query against name/username/url/tags.
    Search { query: String },
}

// ============ Responses ============

/// Daemon's reply to a `Request`. `id` matches the request's `id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: Uuid,
    #[serde(flatten)]
    pub body: ResponseBody,
}

/// Either a successful payload or a typed error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBody {
    Result(serde_json::Value),
    Error(AgentError),
}

/// Stable, machine-readable error envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentError {
    pub code: ErrorCode,
    pub message: String,
}

/// Stable error codes. Add new ones rather than repurposing existing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Method requires an unlocked vault.
    VaultLocked,
    /// Entry id not found in the vault.
    NotFound,
    /// Derived key did not unwrap the vault metadata. Either wrong password
    /// or a corrupt vault.
    BadKey,
    /// IO/storage layer error (filesystem, sled, decryption).
    VaultIo,
    /// Wire-format problem: bad framing, invalid JSON, oversized frame.
    Ipc,
    /// Method or feature not implemented in this daemon version.
    NotImplemented,
    /// Client and daemon disagree on protocol version.
    ProtocolMismatch,
}

// ============ Events ============

/// Unsolicited frame pushed by the daemon. No `id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Event {
    /// Daemon auto-locked due to inactivity.
    SessionExpired,
    /// Daemon is shutting down. Clients should disconnect.
    Shutdown,
}

// ============ Domain types returned in responses ============

/// Reply payload for `ListSummary` / `Search`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntrySummary {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub tags: Vec<String>,
    pub folder: Option<String>,
    pub favorite: bool,
    pub has_password: bool,
    pub has_totp: bool,
}

/// Reply payload for `GetTotp`. Caller decides how to display.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpView {
    pub code: String,
    pub period_remaining_seconds: u32,
    pub period_total_seconds: u32,
}

/// Reply payload for `Status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusView {
    pub unlocked: bool,
    pub vault_path: Option<String>,
    pub entry_count: Option<usize>,
    /// Wallclock instant when the daemon will auto-lock if no further
    /// activity. Serialized as RFC 3339.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Reply payload for `Ping`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PongView {
    pub agent_version: String,
    pub protocol_version: u32,
}

// ============ Framing ============

/// Errors raised by the framing layer.
#[derive(Debug, Error)]
pub enum FramingError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame too large: {got} bytes (max {})", MAX_FRAME_BYTES)]
    TooLarge { got: usize },

    #[error("invalid utf-8 in frame body")]
    InvalidUtf8,

    #[error("invalid json in frame body: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

/// Write a single frame: 4-byte LE length + UTF-8 JSON body.
pub fn write_frame<W: Write>(w: &mut W, frame: &Frame) -> Result<(), FramingError> {
    let body = serde_json::to_vec(frame)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FramingError::TooLarge { got: body.len() });
    }
    let len = body.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    Ok(())
}

/// Read a single frame. Returns `Ok(None)` on clean EOF (peer closed before
/// any bytes of a new frame); returns `Err` on partial frames or other IO.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Frame>, FramingError> {
    let mut len_buf = [0u8; 4];
    match read_exact_or_eof(r, &mut len_buf)? {
        ReadResult::Eof => return Ok(None),
        ReadResult::Ok => {}
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FramingError::TooLarge { got: len });
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    if std::str::from_utf8(&body).is_err() {
        return Err(FramingError::InvalidUtf8);
    }
    let frame: Frame = serde_json::from_slice(&body)?;
    Ok(Some(frame))
}

enum ReadResult {
    Ok,
    Eof,
}

/// `read_exact` that distinguishes "clean EOF before any bytes" from "EOF
/// mid-frame". The former is a graceful shutdown; the latter is a protocol
/// error.
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<ReadResult, FramingError> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => {
                if filled == 0 {
                    return Ok(ReadResult::Eof);
                }
                return Err(FramingError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "partial frame: peer closed mid-message",
                )));
            }
            n => filled += n,
        }
    }
    Ok(ReadResult::Ok)
}

// ============ Tests ============

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_request(method: Method) -> Frame {
        Frame::Request(Request {
            id: Uuid::nil(),
            method,
        })
    }

    #[test]
    fn frame_roundtrip_ping() {
        let frame = make_request(Method::Ping);
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        let read = read_frame(&mut Cursor::new(&buf)).unwrap().unwrap();
        match read {
            Frame::Request(Request {
                method: Method::Ping,
                ..
            }) => {}
            other => panic!("expected ping, got {:?}", other),
        }
    }

    #[test]
    fn frame_roundtrip_unlock() {
        let frame = make_request(Method::Unlock {
            vault_path: "/path/to/vault".to_string(),
            derived_key_hex: "00".repeat(32),
        });
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        let read = read_frame(&mut Cursor::new(&buf)).unwrap().unwrap();
        match read {
            Frame::Request(Request {
                method:
                    Method::Unlock {
                        vault_path,
                        derived_key_hex,
                    },
                ..
            }) => {
                assert_eq!(vault_path, "/path/to/vault");
                assert_eq!(derived_key_hex.len(), 64);
            }
            other => panic!("expected unlock, got {:?}", other),
        }
    }

    #[test]
    fn frame_roundtrip_response_result() {
        let frame = Frame::Response(Response {
            id: Uuid::nil(),
            body: ResponseBody::Result(serde_json::json!({"ok": true})),
        });
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        let read = read_frame(&mut Cursor::new(&buf)).unwrap().unwrap();
        match read {
            Frame::Response(Response {
                body: ResponseBody::Result(v),
                ..
            }) => assert_eq!(v["ok"], true),
            other => panic!("expected result, got {:?}", other),
        }
    }

    #[test]
    fn frame_roundtrip_response_error() {
        let frame = Frame::Response(Response {
            id: Uuid::nil(),
            body: ResponseBody::Error(AgentError {
                code: ErrorCode::VaultLocked,
                message: "vault is locked".to_string(),
            }),
        });
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        let read = read_frame(&mut Cursor::new(&buf)).unwrap().unwrap();
        match read {
            Frame::Response(Response {
                body: ResponseBody::Error(e),
                ..
            }) => assert_eq!(e.code, ErrorCode::VaultLocked),
            other => panic!("expected error, got {:?}", other),
        }
    }

    #[test]
    fn frame_roundtrip_event() {
        let frame = Frame::Event(Event::SessionExpired);
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        let read = read_frame(&mut Cursor::new(&buf)).unwrap().unwrap();
        match read {
            Frame::Event(Event::SessionExpired) => {}
            other => panic!("expected session_expired, got {:?}", other),
        }
    }

    #[test]
    fn read_clean_eof_returns_none() {
        let mut empty = Cursor::new(Vec::<u8>::new());
        let read = read_frame(&mut empty).unwrap();
        assert!(read.is_none());
    }

    #[test]
    fn read_partial_frame_is_error() {
        // length prefix says 100 bytes but we only provide 1
        let mut bad = vec![100u8, 0, 0, 0];
        bad.push(b'x');
        let mut cur = Cursor::new(bad);
        let result = read_frame(&mut cur);
        assert!(result.is_err());
    }

    #[test]
    fn oversized_frame_rejected_on_read() {
        let too_big = (MAX_FRAME_BYTES + 1) as u32;
        let bytes = too_big.to_le_bytes().to_vec();
        let mut cur = Cursor::new(bytes);
        let result = read_frame(&mut cur);
        assert!(matches!(result, Err(FramingError::TooLarge { .. })));
    }

    #[test]
    fn invalid_json_rejected() {
        let body = b"this is not json";
        let mut buf = (body.len() as u32).to_le_bytes().to_vec();
        buf.extend_from_slice(body);
        let result = read_frame(&mut Cursor::new(buf));
        assert!(matches!(result, Err(FramingError::InvalidJson(_))));
    }

    #[test]
    fn json_shape_request_uses_tagged_method() {
        // Lock down the JSON shape so future protocol clients (incl. browser
        // ext, written in TS) can rely on it.
        let frame = make_request(Method::Lock);
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "request");
        assert_eq!(json["method"], "lock");
    }

    #[test]
    fn json_shape_unlock_carries_params() {
        let frame = make_request(Method::Unlock {
            vault_path: "/v".into(),
            derived_key_hex: "ab".repeat(32),
        });
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["method"], "unlock");
        assert_eq!(json["params"]["vault_path"], "/v");
        assert_eq!(
            json["params"]["derived_key_hex"].as_str().unwrap().len(),
            64
        );
    }

    #[test]
    fn json_shape_response_error_codes_stable() {
        // The error code names are part of the public protocol. Lock them
        // down so a refactor can't accidentally rename them.
        for (code, expected) in [
            (ErrorCode::VaultLocked, "vault_locked"),
            (ErrorCode::NotFound, "not_found"),
            (ErrorCode::BadKey, "bad_key"),
            (ErrorCode::VaultIo, "vault_io"),
            (ErrorCode::Ipc, "ipc"),
            (ErrorCode::NotImplemented, "not_implemented"),
            (ErrorCode::ProtocolMismatch, "protocol_mismatch"),
        ] {
            let v = serde_json::to_value(code).unwrap();
            assert_eq!(v.as_str(), Some(expected), "code {:?}", code);
        }
    }
}
