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

// These re-exports are public-API conveniences for users of the `vaultic`
// library (the GUI binary, integration tests, future browser-extension
// host). The `vaultic` CLI binary doesn't use them directly — it imports
// the deeper paths through `cli::agent_bridge` — so its compilation sees
// them as unused. Allow that without weakening the lib's surface.
#[allow(unused_imports)]
pub use client::{AgentClient, ClientError};
#[allow(unused_imports)]
pub use keys::{derive_for_unlock, DerivedKeyHex, KeyError};
#[allow(unused_imports)]
pub use protocol::{
    AgentError, ErrorCode, Frame, FramingError, Method, Request, Response, ResponseBody,
    PROTOCOL_VERSION,
};
#[allow(unused_imports)]
pub use server::{serve, ServerConfig, ServerError};
#[allow(unused_imports)]
pub use state::{AgentState, StateError};
