//! Install `vaultic-agent` as a per-user service so it starts on login.
//!
//! macOS → a launchd LaunchAgent (`~/Library/LaunchAgents/com.vaultic.agent.plist`).
//! Linux → a systemd **user** unit (`~/.config/systemd/user/vaultic-agent.service`).
//!
//! User-level (not system-wide): the agent holds the current user's unlocked
//! vault key in memory, so it belongs to the user session and needs no root.
//!
//! The file-content generators ([`launchd_plist`], [`systemd_unit`]) are pure
//! and unit-tested; `install`/`uninstall` additionally shell out to
//! `launchctl` / `systemctl --user`.

use std::path::{Path, PathBuf};

/// launchd label / systemd unit name.
pub const LAUNCHD_LABEL: &str = "com.vaultic.agent";
pub const SYSTEMD_UNIT: &str = "vaultic-agent.service";

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("`vaultic-agent service` supports macOS (launchd) and Linux (systemd --user) only")]
    UnsupportedPlatform,

    #[error("could not locate the vaultic-agent executable: {0}")]
    ExePath(String),

    #[error("could not determine your home directory for the service file location")]
    NoHome,

    #[error("writing {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("`{cmd}` failed ({status}). The service file is at {path}; you can run it manually.")]
    Command {
        cmd: String,
        status: String,
        path: PathBuf,
    },

    #[error("could not run `{cmd}`: {source} (is it installed and on PATH?)")]
    Spawn { cmd: String, source: std::io::Error },
}

/// Build the launchd plist that runs `<exe> start [--socket <socket>]` at login.
pub fn launchd_plist(exe: &Path, socket: Option<&Path>) -> String {
    let mut args = format!(
        "        <string>{}</string>\n        <string>start</string>\n",
        xml_escape(&exe.display().to_string())
    );
    if let Some(s) = socket {
        args.push_str(&format!(
            "        <string>--socket</string>\n        <string>{}</string>\n",
            xml_escape(&s.display().to_string())
        ));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        args = args,
    )
}

/// Build the systemd user unit that runs `<exe> start [--socket <socket>]`.
pub fn systemd_unit(exe: &Path, socket: Option<&Path>) -> String {
    // systemd parses ExecStart with shell-like quoting; double-quote the exe
    // (and socket) so paths containing spaces survive.
    let mut exec = format!("\"{}\" start", exe.display());
    if let Some(s) = socket {
        exec.push_str(&format!(" --socket \"{}\"", s.display()));
    }
    format!(
        "[Unit]\n\
         Description=Vaultic password-manager agent\n\
         Documentation=https://github.com/punitmishra/vaultic\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec}\n\
         Restart=on-failure\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn current_exe() -> Result<PathBuf, ServiceError> {
    std::env::current_exe().map_err(|e| ServiceError::ExePath(e.to_string()))
}

// ---------------------------------------------------------------------------
// macOS (launchd)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn plist_path() -> Result<PathBuf, ServiceError> {
    let home = std::env::var_os("HOME").ok_or(ServiceError::NoHome)?;
    Ok(PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist")))
}

#[cfg(target_os = "macos")]
pub fn install(socket: Option<&Path>) -> Result<PathBuf, ServiceError> {
    let exe = current_exe()?;
    let path = plist_path()?;
    write_file(&path, &launchd_plist(&exe, socket))?;
    // `launchctl load -w` registers the agent and marks it enabled. It is
    // deprecated in favor of `bootstrap`, but works across macOS versions and
    // does not need the gui/<uid> domain string. A failure returns Err (the
    // file is already written, and the error names the manual command).
    run_tool(
        "launchctl",
        &["load", "-w", &path.display().to_string()],
        &path,
    )?;
    Ok(path)
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<PathBuf, ServiceError> {
    let path = plist_path()?;
    if path.exists() {
        let _ = run_tool(
            "launchctl",
            &["unload", "-w", &path.display().to_string()],
            &path,
        );
        std::fs::remove_file(&path).map_err(|e| ServiceError::Write {
            path: path.clone(),
            source: e,
        })?;
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
pub fn status() -> Result<String, ServiceError> {
    let path = plist_path()?;
    if !path.exists() {
        return Ok(format!("not installed (no {})", path.display()));
    }
    let listed = std::process::Command::new("launchctl")
        .args(["list", LAUNCHD_LABEL])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    Ok(format!(
        "installed at {} ({})",
        path.display(),
        if listed { "loaded" } else { "not loaded" }
    ))
}

// ---------------------------------------------------------------------------
// Linux (systemd --user)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn unit_path() -> Result<PathBuf, ServiceError> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x),
        _ => {
            let home = std::env::var_os("HOME").ok_or(ServiceError::NoHome)?;
            PathBuf::from(home).join(".config")
        }
    };
    Ok(base.join("systemd/user").join(SYSTEMD_UNIT))
}

#[cfg(target_os = "linux")]
pub fn install(socket: Option<&Path>) -> Result<PathBuf, ServiceError> {
    let exe = current_exe()?;
    let path = unit_path()?;
    write_file(&path, &systemd_unit(&exe, socket))?;
    let _ = run_tool("systemctl", &["--user", "daemon-reload"], &path);
    run_tool(
        "systemctl",
        &["--user", "enable", "--now", SYSTEMD_UNIT],
        &path,
    )?;
    Ok(path)
}

#[cfg(target_os = "linux")]
pub fn uninstall() -> Result<PathBuf, ServiceError> {
    let path = unit_path()?;
    if path.exists() {
        let _ = run_tool(
            "systemctl",
            &["--user", "disable", "--now", SYSTEMD_UNIT],
            &path,
        );
        std::fs::remove_file(&path).map_err(|e| ServiceError::Write {
            path: path.clone(),
            source: e,
        })?;
        let _ = run_tool("systemctl", &["--user", "daemon-reload"], &path);
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
pub fn status() -> Result<String, ServiceError> {
    let path = unit_path()?;
    if !path.exists() {
        return Ok(format!("not installed (no {})", path.display()));
    }
    let active = std::process::Command::new("systemctl")
        .args(["--user", "is-active", SYSTEMD_UNIT])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    Ok(format!("installed at {} ({})", path.display(), active))
}

// ---------------------------------------------------------------------------
// Unsupported platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn install(_socket: Option<&Path>) -> Result<PathBuf, ServiceError> {
    Err(ServiceError::UnsupportedPlatform)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn uninstall() -> Result<PathBuf, ServiceError> {
    Err(ServiceError::UnsupportedPlatform)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn status() -> Result<String, ServiceError> {
    Err(ServiceError::UnsupportedPlatform)
}

// ---------------------------------------------------------------------------
// Shared helpers (used only by the supported-platform paths)
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn write_file(path: &Path, contents: &str) -> Result<(), ServiceError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ServiceError::Write {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    std::fs::write(path, contents).map_err(|e| ServiceError::Write {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Run a service tool; return whether it succeeded, or a `Command`/`Spawn`
/// error. A non-zero exit is surfaced so the caller can tell the user the file
/// was written and how to load it by hand.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_tool(cmd: &str, args: &[&str], path: &Path) -> Result<bool, ServiceError> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| ServiceError::Spawn {
            cmd: cmd.to_string(),
            source: e,
        })?;
    if output.status.success() {
        Ok(true)
    } else {
        Err(ServiceError::Command {
            cmd: format!("{cmd} {}", args.join(" ")),
            status: output.status.to_string(),
            path: path.to_path_buf(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchd_plist_embeds_exe_and_start() {
        let p = launchd_plist(Path::new("/usr/local/bin/vaultic-agent"), None);
        assert!(p.contains("<string>com.vaultic.agent</string>"));
        assert!(p.contains("<string>/usr/local/bin/vaultic-agent</string>"));
        assert!(p.contains("<string>start</string>"));
        assert!(p.contains("<key>RunAtLoad</key>"));
        // No socket override → no --socket arg.
        assert!(!p.contains("--socket"));
    }

    #[test]
    fn launchd_plist_includes_socket_override() {
        let p = launchd_plist(
            Path::new("/opt/vaultic/vaultic-agent"),
            Some(Path::new("/tmp/v.sock")),
        );
        assert!(p.contains("<string>--socket</string>"));
        assert!(p.contains("<string>/tmp/v.sock</string>"));
    }

    #[test]
    fn launchd_plist_escapes_xml_metacharacters() {
        let p = launchd_plist(Path::new("/home/a&b/vaultic-agent"), None);
        assert!(p.contains("/home/a&amp;b/vaultic-agent"));
        assert!(!p.contains("a&b/vaultic-agent"));
    }

    #[test]
    fn systemd_unit_quotes_exec_and_sets_install_target() {
        let u = systemd_unit(Path::new("/usr/bin/vaultic-agent"), None);
        assert!(u.contains("ExecStart=\"/usr/bin/vaultic-agent\" start"));
        assert!(u.contains("WantedBy=default.target"));
        assert!(u.contains("Restart=on-failure"));
        assert!(!u.contains("--socket"));
    }

    #[test]
    fn systemd_unit_includes_socket_override() {
        let u = systemd_unit(
            Path::new("/usr/bin/vaultic-agent"),
            Some(Path::new("/run/v.sock")),
        );
        assert!(u.contains("ExecStart=\"/usr/bin/vaultic-agent\" start --socket \"/run/v.sock\""));
    }
}
