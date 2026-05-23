//! Resolution of the `vaultic-agent` Unix-domain socket path.
//!
//! The socket is per-user. Linux: under `$XDG_RUNTIME_DIR/vaultic/` so it
//! lives on tmpfs and dies with the user session. macOS: under
//! `~/Library/Caches/vaultic/` since `$XDG_RUNTIME_DIR` isn't a convention
//! there. Windows is out of scope for v1.

use std::path::PathBuf;

use thiserror::Error;

/// Errors raised when resolving the socket path.
#[derive(Debug, Error)]
pub enum PathError {
    #[error("could not determine a per-user socket directory for this OS")]
    NoBaseDirectory,
    #[error("unsupported operating system: {0}")]
    UnsupportedOs(String),
}

const DIR_NAME: &str = "vaultic";
const SOCK_FILE: &str = "agent.sock";

/// Resolve the path the agent should listen on (and clients should connect
/// to). The parent directory may not exist yet — callers that intend to bind
/// the socket should create it with mode 0700.
pub fn agent_socket_path() -> Result<PathBuf, PathError> {
    let base = base_dir_for_current_os()?;
    Ok(base.join(DIR_NAME).join(SOCK_FILE))
}

/// The per-user directory containing the socket. Public so `vaultic-agent
/// start` can mkdir(p) it with mode 0700 before binding.
pub fn agent_dir() -> Result<PathBuf, PathError> {
    let base = base_dir_for_current_os()?;
    Ok(base.join(DIR_NAME))
}

#[cfg(target_os = "linux")]
fn base_dir_for_current_os() -> Result<PathBuf, PathError> {
    base_dir_linux(dirs::runtime_dir(), dirs::cache_dir())
}

#[cfg(target_os = "macos")]
fn base_dir_for_current_os() -> Result<PathBuf, PathError> {
    base_dir_macos(dirs::cache_dir())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn base_dir_for_current_os() -> Result<PathBuf, PathError> {
    Err(PathError::UnsupportedOs(std::env::consts::OS.to_string()))
}

/// Linux resolution. Prefers `$XDG_RUNTIME_DIR` (per-session tmpfs, the
/// XDG-canonical home for sockets); falls back to `XDG_CACHE_HOME` (typically
/// `~/.cache`) if the runtime dir isn't available — better to land on disk
/// than refuse to start.
fn base_dir_linux(
    runtime_dir: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
) -> Result<PathBuf, PathError> {
    runtime_dir.or(cache_dir).ok_or(PathError::NoBaseDirectory)
}

/// macOS resolution. We use `~/Library/Caches/` (the value `dirs::cache_dir`
/// returns on macOS): per-user, persists across reboots, fine for a Unix
/// socket that we manage explicitly.
fn base_dir_macos(cache_dir: Option<PathBuf>) -> Result<PathBuf, PathError> {
    cache_dir.ok_or(PathError::NoBaseDirectory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_prefers_xdg_runtime_dir() {
        let runtime = Some(PathBuf::from("/run/user/1000"));
        let cache = Some(PathBuf::from("/home/alice/.cache"));
        let resolved = base_dir_linux(runtime, cache).unwrap();
        assert_eq!(resolved, PathBuf::from("/run/user/1000"));
    }

    #[test]
    fn linux_falls_back_to_cache_when_runtime_missing() {
        let cache = Some(PathBuf::from("/home/alice/.cache"));
        let resolved = base_dir_linux(None, cache).unwrap();
        assert_eq!(resolved, PathBuf::from("/home/alice/.cache"));
    }

    #[test]
    fn linux_errors_when_neither_resolvable() {
        let err = base_dir_linux(None, None).unwrap_err();
        assert!(matches!(err, PathError::NoBaseDirectory));
    }

    #[test]
    fn macos_uses_cache_dir() {
        let resolved = base_dir_macos(Some(PathBuf::from("/Users/alice/Library/Caches"))).unwrap();
        assert_eq!(resolved, PathBuf::from("/Users/alice/Library/Caches"));
    }

    #[test]
    fn macos_errors_when_no_cache_dir() {
        let err = base_dir_macos(None).unwrap_err();
        assert!(matches!(err, PathError::NoBaseDirectory));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn agent_socket_path_ends_in_known_filename() {
        let p = agent_socket_path().unwrap();
        assert_eq!(p.file_name().unwrap(), SOCK_FILE);
        assert_eq!(p.parent().unwrap().file_name().unwrap(), DIR_NAME);
    }
}
