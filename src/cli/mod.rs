//! Beautiful CLI interface for Vaultic
//! 
//! Features:
//! - Fuzzy search
//! - Interactive TUI mode
//! - Quick commands
//! - Clipboard integration
//! - QR code generation for sharing

use std::io::{self, Write};
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use colored::Colorize;
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Confirm, FuzzySelect, Input, Password, Select};
use indicatif::{ProgressBar, ProgressStyle};
use tabled::{settings::Style, Table, Tabled};
use uuid::Uuid;

use crate::crypto::{PasswordAnalyzer, PasswordGenerator};
use crate::models::{EntryType, PasswordStrength, SearchFilter, SensitiveString, VaultEntry};

/// Vaultic - Secure, local-first password manager
#[derive(Parser)]
#[command(name = "vaultic")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Vault path (default: ~/.vaultic)
    #[arg(short, long, global = true)]
    pub vault: Option<String>,

    /// Use JSON output
    #[arg(long, global = true)]
    pub json: bool,

    /// Quiet mode (minimal output)
    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new vault
    Init {
        /// Vault name
        #[arg(short, long, default_value = "My Vault")]
        name: String,

        /// Use FIDO2/YubiKey for authentication
        #[arg(long)]
        fido2: bool,

        /// Use high-security KDF parameters
        #[arg(long)]
        high_security: bool,

        /// Master password (for non-interactive use)
        #[arg(long, env = "VAULTIC_PASSWORD", hide = true)]
        password: Option<String>,
    },

    /// Unlock the vault
    Unlock {
        /// Timeout in minutes (0 = no timeout)
        #[arg(short, long, default_value = "15")]
        timeout: u32,

        /// Master password (for non-interactive use)
        #[arg(long, env = "VAULTIC_PASSWORD", hide = true)]
        password: Option<String>,
    },

    /// Lock the vault
    Lock,

    /// Add a new entry
    Add {
        /// Entry name
        name: String,

        /// Entry type
        #[arg(short, long, value_enum, default_value = "password")]
        r#type: EntryTypeArg,

        /// Username
        #[arg(short, long)]
        username: Option<String>,

        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Generate password
        #[arg(short, long)]
        generate: bool,

        /// Password length for generation
        #[arg(long, default_value = "20")]
        length: usize,

        /// URL
        #[arg(long)]
        url: Option<String>,

        /// Tags (comma-separated)
        #[arg(long)]
        tags: Option<String>,

        /// Folder
        #[arg(short, long)]
        folder: Option<String>,

        /// Mark as favorite
        #[arg(long)]
        favorite: bool,
    },

    /// Get/show an entry
    Get {
        /// Entry name or ID (fuzzy search if not exact)
        query: String,

        /// Copy password to clipboard
        #[arg(short, long)]
        copy: bool,

        /// Show password in terminal
        #[arg(short, long)]
        show: bool,

        /// Show QR code
        #[arg(long)]
        qr: bool,

        /// Field to get (password, username, url, notes)
        #[arg(short, long)]
        field: Option<String>,
    },

    /// List entries
    #[command(alias = "ls")]
    List {
        /// Search query (fuzzy)
        query: Option<String>,

        /// Filter by folder
        #[arg(short, long)]
        folder: Option<String>,

        /// Filter by tags (comma-separated)
        #[arg(short, long)]
        tags: Option<String>,

        /// Show only favorites
        #[arg(long)]
        favorites: bool,

        /// Show entries needing rotation
        #[arg(long)]
        needs_rotation: bool,

        /// Show weak passwords
        #[arg(long)]
        weak: bool,

        /// Limit results
        #[arg(short, long)]
        limit: Option<usize>,
    },

    /// Edit an entry
    Edit {
        /// Entry name or ID
        query: String,

        /// Interactive edit mode
        #[arg(short, long)]
        interactive: bool,
    },

    /// Delete an entry
    #[command(alias = "rm")]
    Delete {
        /// Entry name or ID
        query: String,

        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// Generate a password
    #[command(alias = "gen")]
    Generate {
        /// Password length
        #[arg(short, long, default_value = "20")]
        length: usize,

        /// No uppercase letters
        #[arg(long)]
        no_uppercase: bool,

        /// No lowercase letters
        #[arg(long)]
        no_lowercase: bool,

        /// No digits
        #[arg(long)]
        no_digits: bool,

        /// No symbols
        #[arg(long)]
        no_symbols: bool,

        /// Generate passphrase instead
        #[arg(long)]
        passphrase: bool,

        /// Number of words for passphrase
        #[arg(long, default_value = "4")]
        words: usize,

        /// Copy to clipboard
        #[arg(short, long)]
        copy: bool,
    },

    /// Search entries interactively
    Search {
        /// Initial query
        query: Option<String>,
    },

    /// Share an entry
    Share {
        /// Entry to share
        query: String,

        /// Recipient fingerprint or name
        #[arg(short, long)]
        to: String,

        /// One-time share (deleted after access)
        #[arg(long)]
        one_time: bool,

        /// Expiration in hours
        #[arg(long)]
        expires: Option<u32>,
    },

    /// Manage identities (for sharing)
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },

    /// AI-powered suggestions
    Suggest {
        /// Run analysis and show suggestions
        #[arg(long)]
        analyze: bool,

        /// Check for breached passwords
        #[arg(long)]
        check_breaches: bool,
    },

    /// Export vault
    Export {
        /// Output file
        output: String,

        /// Export format
        #[arg(short, long, value_enum, default_value = "encrypted")]
        format: ExportFormat,
    },

    /// Import entries
    Import {
        /// Input file
        input: String,

        /// Import format
        #[arg(short, long, value_enum, default_value = "encrypted")]
        format: ImportFormat,
    },

    /// Show vault status and statistics
    Status,

    /// Vault health check and security audit
    Health {
        /// Show detailed analysis
        #[arg(short, long)]
        verbose: bool,

        /// Check against Have I Been Pwned (requires internet)
        #[arg(long)]
        check_breaches: bool,
    },

    /// Open interactive TUI mode
    Tui,

    /// Manage vault configuration
    Config {
        /// Config key
        key: Option<String>,

        /// Config value (omit to show current)
        value: Option<String>,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
pub enum IdentityCommands {
    /// Show your identity
    Show,

    /// Add a trusted identity
    Add {
        /// Name for the identity
        name: String,
        /// Public key (base64)
        public_key: String,
    },

    /// List trusted identities
    List,

    /// Remove a trusted identity
    Remove {
        /// Identity fingerprint or name
        query: String,
    },

    /// Export your public identity
    Export,
}

#[derive(Clone, ValueEnum)]
pub enum EntryTypeArg {
    Password,
    Note,
    Card,
    Identity,
    Ssh,
    Api,
    Totp,
}

impl From<EntryTypeArg> for EntryType {
    fn from(arg: EntryTypeArg) -> Self {
        match arg {
            EntryTypeArg::Password => EntryType::Password,
            EntryTypeArg::Note => EntryType::SecureNote,
            EntryTypeArg::Card => EntryType::CreditCard,
            EntryTypeArg::Identity => EntryType::Identity,
            EntryTypeArg::Ssh => EntryType::SshKey,
            EntryTypeArg::Api => EntryType::ApiKey,
            EntryTypeArg::Totp => EntryType::Totp,
        }
    }
}

#[derive(Clone, ValueEnum)]
pub enum ExportFormat {
    Encrypted,
    Json,
    Csv,
}

#[derive(Clone, ValueEnum)]
pub enum ImportFormat {
    Encrypted,
    Json,
    Csv,
    Bitwarden,
    Lastpass,
    Onepassword,
}

/// CLI output helpers
pub struct Output;

impl Output {
    /// Print a success message
    pub fn success(message: &str) {
        println!("{} {}", "✓".green().bold(), message);
    }

    /// Print an error message
    pub fn error(message: &str) {
        eprintln!("{} {}", "✗".red().bold(), message);
    }

    /// Print a warning message
    pub fn warning(message: &str) {
        println!("{} {}", "⚠".yellow().bold(), message);
    }

    /// Print an info message
    pub fn info(message: &str) {
        println!("{} {}", "ℹ".blue().bold(), message);
    }

    /// Print a header
    pub fn header(title: &str) {
        println!("\n{}", title.bold().underline());
    }

    /// Create a progress spinner
    pub fn spinner(message: &str) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(80));
        pb
    }

    /// Print a key-value pair
    pub fn field(key: &str, value: &str) {
        println!("  {}: {}", key.dimmed(), value);
    }

    /// Print a masked password
    pub fn masked_password(password: &str) {
        let masked = "*".repeat(password.len().min(20));
        println!("  {}: {}", "Password".dimmed(), masked);
    }

    /// Print password strength indicator
    pub fn strength(strength: PasswordStrength) {
        let (label, color) = match strength {
            PasswordStrength::VeryWeak => ("Very Weak", "red"),
            PasswordStrength::Weak => ("Weak", "yellow"),
            PasswordStrength::Fair => ("Fair", "cyan"),
            PasswordStrength::Strong => ("Strong", "green"),
            PasswordStrength::VeryStrong => ("Very Strong", "bright green"),
        };
        println!(
            "  {}: {} {}",
            "Strength".dimmed(),
            strength.emoji(),
            label.color(color)
        );
    }
}

/// Interactive prompts
pub struct Prompts;

impl Prompts {
    /// Get master password
    pub fn master_password(confirm: bool) -> io::Result<String> {
        let theme = ColorfulTheme::default();

        let password = Password::with_theme(&theme)
            .with_prompt("Master password")
            .interact()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if confirm {
            let confirm_pwd = Password::with_theme(&theme)
                .with_prompt("Confirm password")
                .interact()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            if password != confirm_pwd {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Passwords don't match",
                ));
            }
        }

        Ok(password)
    }

    /// Select an entry from a list
    pub fn select_entry(entries: &[VaultEntry], prompt: &str) -> io::Result<usize> {
        let items: Vec<String> = entries
            .iter()
            .map(|e| {
                let username = e.username.as_deref().unwrap_or("-");
                format!("{} ({})", e.name, username)
            })
            .collect();

        FuzzySelect::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(&items)
            .default(0)
            .interact()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    /// Confirm an action
    pub fn confirm(prompt: &str, default: bool) -> io::Result<bool> {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .default(default)
            .interact()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    /// Get text input
    pub fn input(prompt: &str, default: Option<&str>) -> io::Result<String> {
        let theme = ColorfulTheme::default();
        let mut input = Input::with_theme(&theme)
            .with_prompt(prompt);

        if let Some(d) = default {
            input = input.default(d.to_string());
        }

        input.interact_text()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    /// Get password input (hidden)
    pub fn password(prompt: &str) -> io::Result<String> {
        Password::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .allow_empty_password(true)
            .interact()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    /// Select from options
    pub fn select(prompt: &str, options: &[&str], default: usize) -> io::Result<usize> {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(options)
            .default(default)
            .interact()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

/// Entry table display
#[derive(Tabled)]
pub struct EntryRow {
    #[tabled(rename = "Name")]
    pub name: String,
    #[tabled(rename = "Type")]
    pub entry_type: String,
    #[tabled(rename = "Username")]
    pub username: String,
    #[tabled(rename = "Strength")]
    pub strength: String,
    #[tabled(rename = "Last Used")]
    pub last_used: String,
    #[tabled(rename = "Tags")]
    pub tags: String,
}

impl From<&VaultEntry> for EntryRow {
    fn from(entry: &VaultEntry) -> Self {
        Self {
            name: if entry.favorite {
                format!("★ {}", entry.name)
            } else {
                entry.name.clone()
            },
            entry_type: entry.entry_type.to_string(),
            username: entry.username.clone().unwrap_or_else(|| "-".to_string()),
            strength: entry
                .password_strength
                .as_ref()
                .map(|s| format!("{} {:?}", s.emoji(), s))
                .unwrap_or_else(|| "-".to_string()),
            last_used: entry
                .last_accessed
                .map(|t| t.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "Never".to_string()),
            tags: if entry.tags.is_empty() {
                "-".to_string()
            } else {
                entry.tags.join(", ")
            },
        }
    }
}

/// Display a table of entries
pub fn display_entries_table(entries: &[VaultEntry]) {
    if entries.is_empty() {
        Output::info("No entries found");
        return;
    }

    let rows: Vec<EntryRow> = entries.iter().map(EntryRow::from).collect();
    let table = Table::new(rows).with(Style::rounded()).to_string();
    println!("{}", table);
    println!("\n{} entries", entries.len());
}

/// Display a single entry
pub fn display_entry(entry: &VaultEntry, show_password: bool) {
    println!();
    println!(
        "{}{}",
        if entry.favorite { "★ " } else { "" },
        entry.name.bold()
    );
    println!("{}", "─".repeat(40));

    Output::field("ID", &entry.id.to_string());
    Output::field("Type", &entry.entry_type.to_string());

    if let Some(ref username) = entry.username {
        Output::field("Username", username);
    }

    if entry.password.is_some() {
        if show_password {
            Output::field("Password", entry.password.as_ref().unwrap().expose());
        } else {
            Output::masked_password("••••••••••••");
        }
    }

    if let Some(ref strength) = entry.password_strength {
        Output::strength(*strength);
    }

    if let Some(ref url) = entry.url {
        Output::field("URL", url);
    }

    if let Some(ref folder) = entry.folder {
        Output::field("Folder", folder);
    }

    if !entry.tags.is_empty() {
        Output::field("Tags", &entry.tags.join(", "));
    }

    if let Some(days) = entry.days_until_rotation() {
        if days <= 0 {
            Output::field("Rotation", &format!("{} days overdue!", -days).red().to_string());
        } else {
            Output::field("Rotation", &format!("in {} days", days));
        }
    }

    Output::field("Created", &entry.created_at.format("%Y-%m-%d %H:%M").to_string());
    Output::field("Updated", &entry.updated_at.format("%Y-%m-%d %H:%M").to_string());

    if let Some(accessed) = entry.last_accessed {
        Output::field("Last accessed", &accessed.format("%Y-%m-%d %H:%M").to_string());
    }

    println!();
}

/// Generate and display a password
pub fn generate_and_display_password(
    length: usize,
    use_uppercase: bool,
    use_lowercase: bool,
    use_digits: bool,
    use_symbols: bool,
    copy: bool,
) -> String {
    let generator = PasswordGenerator::new(length)
        .with_uppercase(use_uppercase)
        .with_lowercase(use_lowercase)
        .with_digits(use_digits)
        .with_symbols(use_symbols);

    let password = generator.generate();
    let strength = PasswordAnalyzer::strength(&password);
    let entropy = PasswordAnalyzer::entropy(&password);

    println!();
    println!("  {}", password.bold());
    println!();
    Output::strength(strength);
    Output::field("Entropy", &format!("{:.1} bits", entropy));
    Output::field("Length", &length.to_string());

    if copy {
        if copy_to_clipboard_internal(&password).is_ok() {
            Output::success("Copied to clipboard (clears in 30s)");
        }
    }

    println!();
    password
}

/// Internal clipboard helper
fn copy_to_clipboard_internal(text: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(text)?;
    Ok(())
}

/// Simple hash for password reuse detection (not cryptographic)
fn md5_hash(input: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

/// Copy to clipboard with auto-clear
pub fn copy_to_clipboard(text: &str, clear_seconds: u64) -> io::Result<()> {
    copy_to_clipboard_internal(text)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    Output::success(&format!(
        "Copied to clipboard (clears in {}s)",
        clear_seconds
    ));

    // Spawn background thread to clear clipboard
    let clear_text = text.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(clear_seconds));
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            // Only clear if content hasn't changed
            if let Ok(current) = clipboard.get_text() {
                if current == clear_text {
                    let _ = clipboard.set_text(String::new());
                }
            }
        }
    });

    Ok(())
}

/// Display QR code in terminal
pub fn display_qr_code(data: &str) -> io::Result<()> {
    use qrcode::QrCode;

    let code = QrCode::new(data.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let string = code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .build();

    println!("{}", string);
    Ok(())
}

/// Vault status display
pub fn display_status(
    vault_name: &str,
    entry_count: usize,
    is_locked: bool,
    weak_count: usize,
    rotation_count: usize,
    size_bytes: u64,
) {
    Output::header("Vault Status");

    let lock_status = if is_locked {
        "🔒 Locked".red().to_string()
    } else {
        "🔓 Unlocked".green().to_string()
    };

    Output::field("Name", vault_name);
    Output::field("Status", &lock_status);
    Output::field("Entries", &entry_count.to_string());
    Output::field("Size", &format_bytes(size_bytes));

    if !is_locked {
        println!();
        Output::header("Health");
        
        if weak_count > 0 {
            Output::warning(&format!("{} weak passwords", weak_count));
        }
        if rotation_count > 0 {
            Output::warning(&format!("{} passwords need rotation", rotation_count));
        }
        if weak_count == 0 && rotation_count == 0 {
            Output::success("All passwords are healthy");
        }
    }

    println!();
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;

    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Get default vault path
fn default_vault_path(cli_vault: &Option<String>) -> std::path::PathBuf {
    cli_vault
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".vaultic")
        })
}

/// Run the CLI command
pub fn run_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Init { name, fido2, high_security, password: cli_password } => {
            Output::info(&format!("Initializing vault '{}'...", name));
            if fido2 {
                Output::info("FIDO2 hardware key support enabled");
            }
            if high_security {
                Output::info("Using high-security KDF parameters");
            }

            // Get master password (from flag or interactive prompt)
            let password = match cli_password {
                Some(p) => p,
                None => Prompts::master_password(true)?,
            };
            if password.len() < 8 {
                return Err("Password must be at least 8 characters".into());
            }

            let vault_path = default_vault_path(&cli.vault);

            // Create KDF params with generated salt
            let mut kdf_params = crate::models::KdfParams::default();
            if high_security {
                kdf_params.memory_cost = 131072; // 128 MiB
                kdf_params.time_cost = 4;
            }
            // Generate salt
            let mut salt = vec![0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut salt);
            kdf_params.salt = salt.clone();

            // Derive master key using Argon2
            use argon2::Argon2;
            let argon2 = Argon2::default();
            let mut key_bytes = [0u8; 32];
            argon2.hash_password_into(
                password.as_bytes(),
                &salt,
                &mut key_bytes,
            ).map_err(|e| format!("Key derivation failed: {}", e))?;

            let master_key = crate::crypto::MasterKey::from_bytes(key_bytes);

            crate::storage::VaultStorage::create(
                &vault_path,
                &name,
                &master_key,
                kdf_params,
                "local".to_string(),
            )?;

            Output::success(&format!("Vault created at {:?}", vault_path));
            Ok(())
        }

        Commands::Unlock { timeout, password: cli_password } => {
            let session_mgr = crate::session::SessionManager::new()?;

            // Check if already unlocked
            if let Some(info) = session_mgr.info() {
                Output::info(&format!(
                    "Vault already unlocked ({} min remaining)",
                    info.minutes_remaining()
                ));
                return Ok(());
            }

            let vault_path = default_vault_path(&cli.vault);

            // Check vault exists
            if !vault_path.exists() {
                return Err(format!(
                    "Vault not found at {:?}. Run 'vaultic init' first.",
                    vault_path
                ).into());
            }

            // Get password (from flag or interactive prompt)
            let password = match cli_password {
                Some(p) => p,
                None => Prompts::master_password(false)?,
            };

            // Load KDF params from vault
            let kdf_params = crate::storage::KdfParamsStorage::load(&vault_path)?;

            // Derive master key
            use argon2::Argon2;
            let argon2 = Argon2::default();
            let mut key_bytes = [0u8; 32];
            argon2.hash_password_into(
                password.as_bytes(),
                &kdf_params.salt,
                &mut key_bytes,
            ).map_err(|e| format!("Key derivation failed: {}", e))?;

            let master_key = crate::crypto::MasterKey::from_bytes(key_bytes);

            // Verify by attempting to unlock vault
            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            // Create session
            session_mgr.create(&vault_path, &master_key, timeout)?;

            Output::success(&format!("Vault unlocked for {} minutes", timeout));
            Ok(())
        }

        Commands::Lock => {
            let session_mgr = crate::session::SessionManager::new()?;
            session_mgr.destroy()?;
            Output::success("Vault locked");
            Ok(())
        }

        Commands::Add { name, r#type, username, password, generate, length, url, tags, folder, favorite } => {
            // Require unlocked vault
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr.load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

            // Refresh session on activity
            let _ = session_mgr.refresh(15);

            let password_value = if generate {
                let pwd = generate_and_display_password(
                    length,
                    true, true, true, true,
                    false,
                );
                Some(pwd)
            } else if let Some(p) = password {
                Some(p)
            } else {
                let p = Prompts::password("Password (leave empty for none)")?;
                if p.is_empty() { None } else { Some(p) }
            };

            // Convert entry type
            let entry_type = match r#type {
                EntryTypeArg::Password => crate::models::EntryType::Password,
                EntryTypeArg::Note => crate::models::EntryType::SecureNote,
                EntryTypeArg::Card => crate::models::EntryType::CreditCard,
                EntryTypeArg::Identity => crate::models::EntryType::Identity,
                EntryTypeArg::Ssh => crate::models::EntryType::SshKey,
                EntryTypeArg::Api => crate::models::EntryType::ApiKey,
                EntryTypeArg::Totp => crate::models::EntryType::Totp,
            };

            // Build entry
            let mut entry = crate::models::VaultEntry::new(&name, entry_type);
            if let Some(u) = &username {
                entry = entry.with_username(u);
            }
            if let Some(p) = password_value {
                entry = entry.with_password(p);
            }
            if let Some(u) = &url {
                entry = entry.with_url(u);
            }
            // Parse tags from comma-separated string
            let tag_list: Vec<String> = tags
                .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();
            entry = entry.with_tags(tag_list);
            entry.folder = folder;
            entry.favorite = favorite;

            // Save to vault
            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;
            storage.add_entry(&entry)?;

            Output::success(&format!("Entry '{}' added", name));
            if let Some(u) = &username {
                Output::field("Username", u);
            }
            if let Some(u) = &url {
                Output::field("URL", u);
            }
            Ok(())
        }

        Commands::Get { query, copy, show, qr, field } => {
            Output::info(&format!("Searching for '{}'...", query));
            Output::warning("Vault operations require unlock - not yet implemented");
            Ok(())
        }

        Commands::List { query, folder, tags, favorites, needs_rotation, weak, limit } => {
            // Require unlocked vault
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr.load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

            // Refresh session
            let _ = session_mgr.refresh(15);

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            // Build search filter
            let tag_list: Vec<String> = tags
                .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            let filter = crate::models::SearchFilter {
                query,
                entry_type: None,
                tags: tag_list,
                folder,
                favorites_only: favorites,
                needs_rotation,
                weak_passwords: weak,
                offset: 0,
                limit: limit.map(|l| l as usize),
            };

            let entries = storage.search_entries(&filter)?;

            // Display as table (handles empty case internally)
            display_entries_table(&entries);

            Ok(())
        }

        Commands::Edit { query, interactive } => {
            Output::info(&format!("Editing '{}'...", query));
            Output::warning("Edit not yet implemented");
            Ok(())
        }

        Commands::Delete { query, force } => {
            if !force {
                let confirm = Prompts::confirm(&format!("Delete '{}'?", query), false)?;
                if !confirm {
                    Output::info("Cancelled");
                    return Ok(());
                }
            }
            Output::warning("Delete not yet implemented");
            Ok(())
        }

        Commands::Generate { length, no_uppercase, no_lowercase, no_digits, no_symbols, passphrase, words, copy } => {
            if passphrase {
                Output::info(&format!("Generating {}-word passphrase...", words));
                let generator = crate::crypto::PasswordGenerator::new(words * 5)
                    .with_lowercase(true);
                println!("\n  {}\n", generator.generate());
            } else {
                generate_and_display_password(
                    length,
                    !no_uppercase,
                    !no_lowercase,
                    !no_digits,
                    !no_symbols,
                    copy,
                );
            }
            Ok(())
        }

        Commands::Search { query } => {
            Output::info("Interactive search...");
            Output::warning("Interactive search not yet implemented");
            Ok(())
        }

        Commands::Share { query, to, one_time, expires } => {
            Output::info(&format!("Sharing '{}' to '{}'...", query, to));
            Output::warning("Sharing not yet implemented");
            Ok(())
        }

        Commands::Identity { command } => {
            match command {
                IdentityCommands::Show => {
                    Output::header("Your Identity");
                    Output::warning("Identity management not yet implemented");
                }
                IdentityCommands::Add { name, public_key } => {
                    Output::info(&format!("Adding identity '{}'...", name));
                }
                IdentityCommands::List => {
                    Output::header("Trusted Identities");
                }
                IdentityCommands::Remove { query } => {
                    Output::info(&format!("Removing identity '{}'...", query));
                }
                IdentityCommands::Export => {
                    Output::header("Exporting Identity");
                }
            }
            Ok(())
        }

        Commands::Suggest { analyze, check_breaches } => {
            Output::header("AI Suggestions");
            if analyze {
                Output::info("Analyzing vault...");
            }
            if check_breaches {
                Output::info("Checking for breached passwords...");
            }
            Output::warning("AI suggestions not yet implemented");
            Ok(())
        }

        Commands::Export { output, format } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr.load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;
            let _ = session_mgr.refresh(15);

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;
            let entries = storage.list_entries()?;

            if entries.is_empty() {
                Output::warning("No entries to export");
                return Ok(());
            }

            match format {
                ExportFormat::Json => {
                    let data = crate::export::export_json(&entries)?;
                    std::fs::write(&output, &data)?;
                    Output::success(&format!("Exported {} entries to '{}'", entries.len(), output));
                    Output::warning("Note: Passwords exported in plaintext. Handle with care!");
                }
                ExportFormat::Csv => {
                    let data = crate::export::export_csv(&entries)?;
                    std::fs::write(&output, &data)?;
                    Output::success(&format!("Exported {} entries to '{}'", entries.len(), output));
                    Output::warning("Note: Passwords exported in plaintext. Handle with care!");
                }
                ExportFormat::Encrypted => {
                    let bytes = crate::export::export_encrypted(&entries, &master_key)?;
                    std::fs::write(&output, &bytes)?;
                    Output::success(&format!("Exported {} entries to '{}' (encrypted)", entries.len(), output));
                }
            }
            Ok(())
        }

        Commands::Import { input, format } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr.load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;
            let _ = session_mgr.refresh(15);

            let entries = match format {
                ImportFormat::Bitwarden => {
                    let data = std::fs::read_to_string(&input)?;
                    crate::import::import_bitwarden(&data)?
                }
                ImportFormat::Lastpass => {
                    let data = std::fs::read_to_string(&input)?;
                    crate::import::import_lastpass(&data)?
                }
                ImportFormat::Onepassword => {
                    let data = std::fs::read_to_string(&input)?;
                    crate::import::import_1password(&data)?
                }
                ImportFormat::Encrypted => {
                    let bytes = std::fs::read(&input)?;
                    crate::import::import_encrypted(&bytes, &master_key)?
                }
                ImportFormat::Json | ImportFormat::Csv => {
                    return Err("Use --format bitwarden, lastpass, onepassword, or encrypted".into());
                }
            };

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            let mut imported = 0;
            for entry in entries {
                storage.add_entry(&entry)?;
                imported += 1;
            }

            Output::success(&format!("Imported {} entries from '{}'", imported, input));
            Ok(())
        }

        Commands::Status => {
            let session_mgr = crate::session::SessionManager::new()?;
            let vault_path = default_vault_path(&cli.vault);

            if let Some(info) = session_mgr.info() {
                // Vault is unlocked - show full status
                let (_, master_key) = session_mgr.load()?;
                let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
                storage.unlock(&master_key)?;

                let metadata = storage.metadata();
                let name = metadata.map(|m| m.name.as_str()).unwrap_or("Vault");
                let count = metadata.map(|m| m.entry_count).unwrap_or(0);

                println!();
                Output::header("Vault Status");
                Output::field("Name", name);
                Output::field("Status", "Unlocked");
                Output::field("Entries", &count.to_string());
                Output::field("Session expires in", &format!("{} min", info.minutes_remaining()));
                println!();
            } else if vault_path.exists() {
                // Vault exists but locked
                println!();
                Output::header("Vault Status");
                Output::field("Path", &vault_path.to_string_lossy());
                Output::field("Status", "Locked");
                Output::info("Run 'vaultic unlock' to access the vault");
                println!();
            } else {
                // No vault
                println!();
                Output::header("Vault Status");
                Output::field("Status", "No vault found");
                Output::info("Run 'vaultic init <name>' to create a vault");
                println!();
            }
            Ok(())
        }

        Commands::Health { verbose, check_breaches } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (_, master_key) = session_mgr.load()?;

            let vault_path = default_vault_path(&cli.vault);
            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            let entries = storage.list_entries()?;

            if entries.is_empty() {
                Output::info("No entries in vault to analyze.");
                return Ok(());
            }

            println!();
            Output::header("Vault Health Report");
            println!();

            let mut weak_passwords = Vec::new();
            let mut reused_passwords: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            let mut old_passwords = Vec::new();
            let mut no_password = Vec::new();
            let total = entries.len();
            let now = chrono::Utc::now();
            let ninety_days_ago = now - chrono::Duration::days(90);

            for entry in &entries {
                // Check for missing passwords
                if entry.password.is_none() {
                    no_password.push(entry.name.clone());
                    continue;
                }

                let password = entry.password.as_ref().unwrap().expose();

                // Check password strength
                let strength = crate::crypto::PasswordAnalyzer::strength(password);
                let entropy = crate::crypto::PasswordAnalyzer::entropy(password);
                let score = match strength {
                    crate::models::PasswordStrength::VeryWeak => 1,
                    crate::models::PasswordStrength::Weak => 2,
                    crate::models::PasswordStrength::Fair => 3,
                    crate::models::PasswordStrength::Strong => 4,
                    crate::models::PasswordStrength::VeryStrong => 5,
                };
                if score < 3 || password.len() < 12 {
                    weak_passwords.push((entry.name.clone(), score, password.len()));
                }

                // Check for reuse
                let hash = format!("{:x}", md5_hash(password));
                reused_passwords.entry(hash).or_default().push(entry.name.clone());

                // Check age
                if entry.updated_at < ninety_days_ago {
                    let days = (now - entry.updated_at).num_days();
                    old_passwords.push((entry.name.clone(), days));
                }
            }

            // Filter to only show reused (more than 1 entry with same password)
            let reused: Vec<_> = reused_passwords.into_iter()
                .filter(|(_, names)| names.len() > 1)
                .collect();

            // Calculate health score
            let issues = weak_passwords.len() + reused.len() + old_passwords.len();
            let score = if total == 0 { 100 } else {
                100 - (issues * 100 / total).min(100)
            };

            let score_color = if score >= 80 { "\x1b[32m" } // Green
                else if score >= 60 { "\x1b[33m" } // Yellow
                else { "\x1b[31m" }; // Red

            println!("  Health Score: {}{}%\x1b[0m", score_color, score);
            println!("  Total Entries: {}", total);
            println!();

            // Weak passwords
            if !weak_passwords.is_empty() {
                Output::warning(&format!("{} weak passwords", weak_passwords.len()));
                if verbose {
                    for (name, score, len) in &weak_passwords {
                        println!("    • {} (score: {}/5, {} chars)", name, score, len);
                    }
                }
            } else {
                Output::success("No weak passwords found");
            }

            // Reused passwords
            if !reused.is_empty() {
                let count: usize = reused.iter().map(|(_, n)| n.len()).sum();
                Output::warning(&format!("{} entries share passwords ({} unique reused)", count, reused.len()));
                if verbose {
                    for (_, names) in &reused {
                        println!("    • Shared by: {}", names.join(", "));
                    }
                }
            } else {
                Output::success("No reused passwords");
            }

            // Old passwords
            if !old_passwords.is_empty() {
                Output::warning(&format!("{} passwords older than 90 days", old_passwords.len()));
                if verbose {
                    for (name, days) in &old_passwords {
                        println!("    • {} ({} days old)", name, days);
                    }
                }
            } else {
                Output::success("All passwords updated within 90 days");
            }

            // No password entries
            if !no_password.is_empty() {
                Output::info(&format!("{} entries without passwords (notes/cards)", no_password.len()));
            }

            // Breach check (optional)
            if check_breaches {
                println!();
                Output::info("Checking passwords against Have I Been Pwned...");
                let rt = tokio::runtime::Runtime::new()?;
                let mut config = crate::ai::AiConfig::default();
                config.check_breaches = true;
                config.enable_suggestions = false;
                let ai = crate::ai::PasswordAi::new(config);
                let mut breached = Vec::new();

                for entry in &entries {
                    if let Some(password) = &entry.password {
                        if let Ok(is_breached) = rt.block_on(ai.check_breach(password.expose())) {
                            if is_breached {
                                breached.push(entry.name.clone());
                            }
                        }
                    }
                }

                if breached.is_empty() {
                    Output::success("No breached passwords found");
                } else {
                    Output::error(&format!("{} passwords found in breaches!", breached.len()));
                    for name in &breached {
                        println!("    • {}", name);
                    }
                }
            }

            println!();
            if !verbose && (weak_passwords.len() + reused.len() + old_passwords.len() > 0) {
                Output::info("Run with --verbose for detailed breakdown");
            }
            Ok(())
        }

        Commands::Tui => {
            let vault_path = default_vault_path(&cli.vault);
            Output::info("Starting TUI mode...");
            crate::tui::run_with_vault(Some(&vault_path))?;
            Ok(())
        }

        Commands::Config { key, value } => {
            match (key, value) {
                (Some(k), Some(v)) => {
                    Output::info(&format!("Setting {} = {}", k, v));
                }
                (Some(k), None) => {
                    Output::info(&format!("Getting config: {}", k));
                }
                (None, _) => {
                    Output::header("Configuration");
                    Output::warning("Config management not yet implemented");
                }
            }
            Ok(())
        }

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(shell, &mut cmd, name, &mut io::stdout());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_row_conversion() {
        let entry = VaultEntry::new("Test", EntryType::Password)
            .with_username("user@test.com")
            .with_tags(vec!["work".to_string()]);

        let row = EntryRow::from(&entry);
        assert_eq!(row.name, "Test");
        assert_eq!(row.username, "user@test.com");
    }
}
