//! `vaultic-mcp` — MCP server for AI tool integration.
//!
//! This binary implements the Model Context Protocol (MCP), allowing AI
//! assistants like Claude Code to securely access credentials from Vaultic
//! without users having to paste secrets in chat.
//!
//! # Architecture
//!
//! ```text
//! Claude Code ──(MCP/stdio)──► vaultic-mcp ──(Unix socket)──► vaultic-agent ──► Vault
//! ```
//!
//! # Security Model
//!
//! - Vault must be pre-unlocked via `vaultic unlock` (no password over MCP)
//! - Secret-access tools require user consent (prompted on stderr)
//! - All credentials stay local (never sent to AI servers)
//! - Rate limiting prevents credential enumeration
//!
//! # Usage
//!
//! Add to your Claude Code configuration:
//!
//! ```json
//! {
//!   "mcpServers": {
//!     "vaultic": {
//!       "command": "vaultic-mcp"
//!     }
//!   }
//! }
//! ```

use std::process::ExitCode;

use clap::Parser;
use rmcp::serve_server;
use rmcp::transport::io::stdio;
use tracing_subscriber::EnvFilter;

use vaultic::mcp::{McpConfig, VaulticMcpServer};

#[derive(Parser)]
#[command(
    name = "vaultic-mcp",
    about = "MCP server for AI tool integration with Vaultic password manager",
    version
)]
struct Args {
    /// Disable user consent prompts for secret access.
    /// WARNING: Only use this in trusted, non-interactive environments.
    #[arg(long, default_value = "false")]
    no_consent: bool,

    /// Custom socket path for vaultic-agent.
    /// Defaults to the standard per-user socket path.
    #[arg(long)]
    socket: Option<String>,

    /// Path to a consent-policy config (TOML). Defaults to
    /// $XDG_CONFIG_HOME/vaultic/mcp.toml if present.
    #[arg(long)]
    config: Option<String>,

    /// Enable verbose logging to stderr.
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Initialize logging to stderr (stdout is reserved for MCP protocol)
    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("vaultic_mcp=debug,vaultic=info")),
            )
            .with_writer(std::io::stderr)
            .init();
    }

    // Load the optional consent-policy config (auto-approve allowlist).
    let config = match McpConfig::resolve(args.config.as_deref().map(std::path::Path::new)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("vaultic-mcp: {}", e);
            return ExitCode::FAILURE;
        }
    };
    if config.has_auto_approve() {
        eprintln!("vaultic-mcp: consent-policy config loaded (auto-approve rules active)");
    }

    // Create the MCP server
    let server = if let Some(socket) = args.socket {
        VaulticMcpServer::with_socket_path(!args.no_consent, socket, config)
    } else {
        VaulticMcpServer::new(!args.no_consent, config)
    };

    // Start the MCP server over stdio
    eprintln!("vaultic-mcp v{} starting...", env!("CARGO_PKG_VERSION"));

    let transport = stdio();

    match serve_server(server, transport).await {
        Ok(running) => {
            // Wait for the service to complete
            match running.waiting().await {
                Ok(rmcp::service::QuitReason::Closed) => {
                    eprintln!("vaultic-mcp: connection closed");
                    ExitCode::SUCCESS
                }
                Ok(rmcp::service::QuitReason::Cancelled) => {
                    eprintln!("vaultic-mcp: cancelled");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("vaultic-mcp error: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("vaultic-mcp failed to start: {}", e);
            ExitCode::FAILURE
        }
    }
}
