//! Async client for `vaultic-agent`.
//!
//! Wraps a `UnixStream` and the framing layer, exposing one typed method per
//! protocol method. Used by `vaultic-gui` directly and available for any
//! future client (CLI-via-agent, browser-extension host, integration tests).

use std::path::Path;

use thiserror::Error;
use tokio::net::UnixStream;
use uuid::Uuid;

use crate::agent::protocol::{
    read_frame_async, write_frame_async, AgentError, EntrySummary, ErrorCode, Frame, FramingError,
    Method, PongView, Request, Response, ResponseBody, StatusView, TotpView,
};
use crate::models::VaultEntry;

/// Errors a client call can return.
///
/// `Agent` carries a typed `ErrorCode` for control-flow decisions (e.g.
/// "vault is locked, prompt for password"). `Transport` and `Framing` mean
/// the connection itself is unhealthy and the caller should treat the
/// `AgentClient` as discarded.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Transport(#[from] std::io::Error),

    #[error("framing: {0}")]
    Framing(#[from] FramingError),

    #[error("agent error [{:?}]: {}", .0.code, .0.message)]
    Agent(AgentError),

    #[error("agent closed connection before responding")]
    EofBeforeResponse,

    #[error("agent returned unexpected payload: {0}")]
    BadPayload(String),
}

impl ClientError {
    /// Convenience for callers that only care whether this is a typed
    /// agent-level error vs a connection-level failure.
    pub fn agent_code(&self) -> Option<ErrorCode> {
        match self {
            ClientError::Agent(e) => Some(e.code),
            _ => None,
        }
    }
}

/// One open connection to a running `vaultic-agent`. Not thread-safe — wrap
/// in a single-owner task (the GUI's worker thread) or behind a Mutex.
pub struct AgentClient {
    stream: UnixStream,
}

impl AgentClient {
    /// Connect to the daemon at the given socket path.
    pub async fn connect(socket_path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(socket_path).await?;
        Ok(Self { stream })
    }

    /// Send `method`, wait for the matching response. Skips any unsolicited
    /// `Event` frames that arrive in the meantime.
    async fn call(&mut self, method: Method) -> Result<serde_json::Value, ClientError> {
        let id = Uuid::new_v4();
        let frame = Frame::Request(Request { id, method });
        write_frame_async(&mut self.stream, &frame).await?;

        loop {
            let frame = read_frame_async(&mut self.stream)
                .await?
                .ok_or(ClientError::EofBeforeResponse)?;
            match frame {
                Frame::Response(Response { id: rid, body }) if rid == id => match body {
                    ResponseBody::Result(v) => return Ok(v),
                    ResponseBody::Error(e) => return Err(ClientError::Agent(e)),
                },
                // Out-of-band response (different id) or event — skip and
                // keep waiting for the matched id. Real clients in real
                // sessions don't generate this case, but the protocol
                // allows it, so we tolerate it instead of panicking.
                _ => continue,
            }
        }
    }

    pub async fn ping(&mut self) -> Result<PongView, ClientError> {
        let v = self.call(Method::Ping).await?;
        serde_json::from_value(v).map_err(|e| ClientError::BadPayload(e.to_string()))
    }

    pub async fn status(&mut self) -> Result<StatusView, ClientError> {
        let v = self.call(Method::Status).await?;
        serde_json::from_value(v).map_err(|e| ClientError::BadPayload(e.to_string()))
    }

    pub async fn unlock(
        &mut self,
        vault_path: String,
        derived_key_hex: String,
    ) -> Result<(), ClientError> {
        self.call(Method::Unlock {
            vault_path,
            derived_key_hex,
        })
        .await?;
        Ok(())
    }

    pub async fn lock(&mut self) -> Result<(), ClientError> {
        self.call(Method::Lock).await?;
        Ok(())
    }

    pub async fn list_summary(&mut self) -> Result<Vec<EntrySummary>, ClientError> {
        let v = self.call(Method::ListSummary).await?;
        serde_json::from_value(v).map_err(|e| ClientError::BadPayload(e.to_string()))
    }

    pub async fn get_entry(&mut self, id: Uuid) -> Result<VaultEntry, ClientError> {
        let v = self.call(Method::GetEntry { id }).await?;
        serde_json::from_value(v).map_err(|e| ClientError::BadPayload(e.to_string()))
    }

    pub async fn get_totp(&mut self, id: Uuid) -> Result<TotpView, ClientError> {
        let v = self.call(Method::GetTotp { id }).await?;
        serde_json::from_value(v).map_err(|e| ClientError::BadPayload(e.to_string()))
    }

    pub async fn search(&mut self, query: String) -> Result<Vec<EntrySummary>, ClientError> {
        let v = self.call(Method::Search { query }).await?;
        serde_json::from_value(v).map_err(|e| ClientError::BadPayload(e.to_string()))
    }

    pub async fn shutdown(&mut self) -> Result<(), ClientError> {
        self.call(Method::Shutdown).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{serve, ServerConfig};
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    /// Boots a daemon on a temp socket so we can sanity-check the client end
    /// independently of the integration tests in `tests/agent_integration.rs`.
    async fn boot_daemon() -> (TempDir, std::path::PathBuf, mpsc::Sender<()>) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent.sock");
        let (tx, rx) = mpsc::channel(1);
        let p = path.clone();
        tokio::spawn(async move {
            let _ = serve(
                ServerConfig {
                    socket_path: p,
                    inactivity_timeout: Duration::from_secs(900),
                },
                rx,
            )
            .await;
        });
        for _ in 0..50 {
            if UnixStream::connect(&path).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        (dir, path, tx)
    }

    #[tokio::test]
    async fn ping_returns_pong() {
        let (_dir, path, shutdown) = boot_daemon().await;
        let mut client = AgentClient::connect(&path).await.unwrap();
        let pong = client.ping().await.unwrap();
        assert_eq!(
            pong.protocol_version,
            super::super::protocol::PROTOCOL_VERSION
        );
        let _ = shutdown.send(()).await;
    }

    #[tokio::test]
    async fn list_when_locked_surfaces_typed_error() {
        let (_dir, path, shutdown) = boot_daemon().await;
        let mut client = AgentClient::connect(&path).await.unwrap();
        let err = client.list_summary().await.unwrap_err();
        assert_eq!(err.agent_code(), Some(ErrorCode::VaultLocked));
        let _ = shutdown.send(()).await;
    }
}
