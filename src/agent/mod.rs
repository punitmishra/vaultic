//! `vaultic-agent` — long-running daemon that holds an unlocked vault key in
//! memory and serves clients (GUI, future CLI/TUI/browser-extension) over a
//! Unix-domain socket.
//!
//! This module establishes the wire protocol and shared types. The daemon's
//! socket-listener implementation lives in `src/bin/vaultic_agent.rs` (added
//! over follow-up sessions tracked in issue #9).
//!
//! The protocol is documented in detail in `docs/AGENT_PROTOCOL.md`.

pub mod client;
pub mod keys;
pub mod paths;
pub mod protocol;
pub mod server;
pub mod state;

pub use client::{AgentClient, ClientError};
pub use keys::{derive_for_unlock, DerivedKeyHex, KeyError};
pub use protocol::{
    AgentError, ErrorCode, Frame, FramingError, Method, Request, Response, ResponseBody,
    PROTOCOL_VERSION,
};
pub use server::{serve, ServerConfig, ServerError};
pub use state::{AgentState, StateError};
