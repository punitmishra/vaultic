//! Vaultic - A lightweight, security-focused password manager
//!
//! Features:
//! - FIDO2/YubiKey hardware authentication
//! - End-to-end encryption (XChaCha20-Poly1305 + Argon2id)
//! - AI-powered password analysis and suggestions
//! - Secure sharing with perfect forward secrecy
//! - Local-first, no cloud dependencies

// Allow unused code during development (many features are stubbed)
#![allow(dead_code)]

use clap::Parser;
use std::process::ExitCode;

mod ai;
mod cli;
mod crypto;
mod export;
#[cfg(feature = "fido2")]
mod fido2;
#[cfg(feature = "gpg")]
mod gpg;
mod import;
mod models;
mod session;
mod sharing;
mod storage;
mod totp;
mod tui;

use cli::{run_command, Cli};

fn main() -> ExitCode {
    // Initialize logging
    if std::env::var("VAULTIC_DEBUG").is_ok() {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    }

    let cli = Cli::parse();

    match run_command(cli) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\x1b[31m✗ Error:\x1b[0m {}", e);
            ExitCode::FAILURE
        }
    }
}
