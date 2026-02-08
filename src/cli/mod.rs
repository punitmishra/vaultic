//! Beautiful CLI interface for Vaultic
//!
//! Features:
//! - Fuzzy search
//! - Interactive TUI mode
//! - Quick commands
//! - Clipboard integration
//! - QR code generation for sharing

use std::io::{self, IsTerminal};
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Confirm, FuzzySelect, Input, Password, Select};
use indicatif::{ProgressBar, ProgressStyle};
use tabled::{settings::Style, Table, Tabled};

use crate::crypto::{PasswordAnalyzer, PasswordGenerator};
use crate::models::{EntryType, PasswordStrength, VaultEntry};

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

        /// Custom field (format: key=value, can be used multiple times)
        #[arg(long = "field", value_name = "KEY=VALUE")]
        fields: Vec<String>,

        /// Notes
        #[arg(short, long)]
        notes: Option<String>,

        /// Auto-suggest tags based on entry name, URL, and type
        #[arg(long)]
        auto_tag: bool,
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

        /// Auto-tag entries based on URL, name, and type
        #[arg(long)]
        auto_tag: bool,

        /// Apply suggested tags without confirmation
        #[arg(long)]
        apply: bool,
    },

    /// Run a command with vault secrets as environment variables
    Exec {
        /// Entry name or ID to use for environment variables
        entry: String,

        /// Command to run (everything after --)
        #[arg(last = true, required = true)]
        command: Vec<String>,

        /// Custom env var mapping (format: ENV_VAR=field_name, can be used multiple times)
        #[arg(short = 'e', long = "env", value_name = "ENV_VAR=field")]
        env_mappings: Vec<String>,

        /// Only show the environment variables without running command
        #[arg(long)]
        dry_run: bool,
    },

    /// Generate shell integration script
    ShellInit {
        /// Shell type
        #[arg(value_enum)]
        shell: ShellType,

        /// Include FZF integration for fuzzy search
        #[arg(long)]
        fzf: bool,
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

    /// View password history for an entry
    History {
        /// Entry name or ID
        query: String,

        /// Show passwords in plain text
        #[arg(short, long)]
        show: bool,

        /// Restore password from history by index (1-based)
        #[arg(short, long)]
        restore: Option<usize>,
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

    /// Batch operations on multiple entries
    Batch {
        #[command(subcommand)]
        command: BatchCommands,
    },

    /// Git credential helper (use with git config credential.helper)
    #[command(name = "credential")]
    Credential {
        #[command(subcommand)]
        command: CredentialCommands,
    },

    /// Migrate vault from v1 to v2 format (multi-method unlock)
    Migrate {
        /// Preview migration without making changes
        #[arg(long)]
        dry_run: bool,

        /// Master password (for non-interactive use)
        #[arg(long, env = "VAULTIC_PASSWORD", hide = true)]
        password: Option<String>,
    },

    /// Manage unlock methods (password, recovery key, hardware key)
    #[command(name = "unlock-method")]
    UnlockMethod {
        #[command(subcommand)]
        command: UnlockMethodCommands,
    },

    /// Manage BIP39 recovery keys
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommands,
    },
}

/// Batch operation subcommands
#[derive(Subcommand)]
pub enum BatchCommands {
    /// Add tags to matching entries
    Tag {
        /// Filter by name (fuzzy match)
        #[arg(long)]
        filter: Option<String>,

        /// Filter by folder
        #[arg(long)]
        folder: Option<String>,

        /// Tags to add (comma-separated)
        #[arg(long)]
        add: Option<String>,

        /// Tags to remove (comma-separated)
        #[arg(long)]
        remove: Option<String>,
    },

    /// Delete matching entries
    Delete {
        /// Filter by name (fuzzy match)
        #[arg(long)]
        filter: Option<String>,

        /// Filter by tags (comma-separated)
        #[arg(long)]
        tags: Option<String>,

        /// Filter by folder
        #[arg(long)]
        folder: Option<String>,

        /// Skip confirmation
        #[arg(long)]
        yes: bool,
    },

    /// Move entries to a folder
    Move {
        /// Filter by name (fuzzy match)
        #[arg(long)]
        filter: Option<String>,

        /// Filter by tags (comma-separated)
        #[arg(long)]
        tags: Option<String>,

        /// Target folder
        #[arg(long)]
        to: String,
    },

    /// Mark/unmark entries as favorites
    Favorite {
        /// Filter by name (fuzzy match)
        #[arg(long)]
        filter: Option<String>,

        /// Filter by folder
        #[arg(long)]
        folder: Option<String>,

        /// Set favorite status (true/false)
        #[arg(long)]
        set: bool,
    },
}

/// Git credential helper subcommands
#[derive(Subcommand)]
pub enum CredentialCommands {
    /// Get credentials for a URL
    Get,
    /// Store credentials for a URL
    Store,
    /// Erase credentials for a URL
    Erase,
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

/// Unlock method management subcommands
#[derive(Subcommand)]
pub enum UnlockMethodCommands {
    /// List all configured unlock methods
    List,

    /// Add a new unlock method
    Add {
        /// Method type to add
        #[arg(value_enum)]
        method: UnlockMethodType,

        /// Label for this unlock method
        #[arg(short, long)]
        label: Option<String>,

        /// Master password (for non-interactive use)
        #[arg(long, env = "VAULTIC_PASSWORD", hide = true)]
        password: Option<String>,
    },

    /// Remove an unlock method
    Remove {
        /// Method ID or label to remove
        id: String,

        /// Master password (for non-interactive use)
        #[arg(long, env = "VAULTIC_PASSWORD", hide = true)]
        password: Option<String>,
    },

    /// Test an unlock method
    Test {
        /// Method type to test
        #[arg(value_enum)]
        method: UnlockMethodType,
    },
}

#[derive(Clone, ValueEnum)]
pub enum UnlockMethodType {
    /// Master password (Argon2id)
    Password,
    /// BIP39 24-word recovery key
    Recovery,
    /// YubiKey HMAC-SHA1
    Yubikey,
    /// GPG/OpenPGP key
    Gpg,
}

impl std::fmt::Display for UnlockMethodType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnlockMethodType::Password => write!(f, "password"),
            UnlockMethodType::Recovery => write!(f, "recovery"),
            UnlockMethodType::Yubikey => write!(f, "yubikey"),
            UnlockMethodType::Gpg => write!(f, "gpg"),
        }
    }
}

/// Recovery key management subcommands
#[derive(Subcommand)]
pub enum RecoveryCommands {
    /// Generate a new BIP39 recovery key
    Generate {
        /// Show QR code for backup
        #[arg(long)]
        qr: bool,

        /// Label for this recovery key
        #[arg(short, long)]
        label: Option<String>,

        /// Master password (for non-interactive use)
        #[arg(long, env = "VAULTIC_PASSWORD", hide = true)]
        password: Option<String>,
    },

    /// Verify a recovery phrase
    Verify {
        /// The recovery phrase to verify (or will prompt)
        phrase: Option<String>,
    },

    /// Show recovery key info (if configured)
    Show,

    /// Unlock vault using recovery key
    Unlock {
        /// The recovery phrase (or will prompt)
        phrase: Option<String>,

        /// Session timeout in minutes
        #[arg(short, long, default_value = "15")]
        timeout: u32,
    },
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
pub enum ShellType {
    Bash,
    Zsh,
    Fish,
    Powershell,
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
            .map_err(|e| io::Error::other(e.to_string()))?;

        if confirm {
            let confirm_pwd = Password::with_theme(&theme)
                .with_prompt("Confirm password")
                .interact()
                .map_err(|e| io::Error::other(e.to_string()))?;

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
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Confirm an action
    pub fn confirm(prompt: &str, default: bool) -> io::Result<bool> {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .default(default)
            .interact()
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Get text input
    pub fn input(prompt: &str, default: Option<&str>) -> io::Result<String> {
        let theme = ColorfulTheme::default();
        let mut input = Input::with_theme(&theme).with_prompt(prompt);

        if let Some(d) = default {
            input = input.default(d.to_string());
        }

        input
            .interact_text()
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Get password input (hidden)
    pub fn password(prompt: &str) -> io::Result<String> {
        Password::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .allow_empty_password(true)
            .interact()
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Select from options
    pub fn select(prompt: &str, options: &[&str], default: usize) -> io::Result<usize> {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(options)
            .default(default)
            .interact()
            .map_err(|e| io::Error::other(e.to_string()))
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
            Output::field(
                "Rotation",
                &format!("{} days overdue!", -days).red().to_string(),
            );
        } else {
            Output::field("Rotation", &format!("in {} days", days));
        }
    }

    Output::field(
        "Created",
        &entry.created_at.format("%Y-%m-%d %H:%M").to_string(),
    );
    Output::field(
        "Updated",
        &entry.updated_at.format("%Y-%m-%d %H:%M").to_string(),
    );

    if let Some(accessed) = entry.last_accessed {
        Output::field(
            "Last accessed",
            &accessed.format("%Y-%m-%d %H:%M").to_string(),
        );
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

    if copy && copy_to_clipboard_internal(&password).is_ok() {
        Output::success("Copied to clipboard (clears in 30s)");
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
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

/// Copy to clipboard with auto-clear
pub fn copy_to_clipboard(text: &str, clear_seconds: u64) -> io::Result<()> {
    copy_to_clipboard_internal(text).map_err(|e| io::Error::other(e.to_string()))?;

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

    let code = QrCode::new(data.as_bytes()).map_err(|e| io::Error::other(e.to_string()))?;

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
        Commands::Init {
            name,
            fido2,
            high_security,
            password: cli_password,
        } => {
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
            argon2
                .hash_password_into(password.as_bytes(), &salt, &mut key_bytes)
                .map_err(|e| format!("Key derivation failed: {}", e))?;

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

        Commands::Unlock {
            timeout,
            password: cli_password,
        } => {
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
                )
                .into());
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
            argon2
                .hash_password_into(password.as_bytes(), &kdf_params.salt, &mut key_bytes)
                .map_err(|e| format!("Key derivation failed: {}", e))?;

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

        Commands::Add {
            name,
            r#type,
            username,
            password,
            generate,
            length,
            url,
            tags,
            folder,
            favorite,
            fields,
            notes,
            auto_tag,
        } => {
            // Require unlocked vault
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

            // Refresh session on activity
            let _ = session_mgr.refresh(15);

            let password_value = if generate {
                let pwd = generate_and_display_password(length, true, true, true, true, false);
                Some(pwd)
            } else if let Some(p) = password {
                Some(p)
            } else {
                let p = Prompts::password("Password (leave empty for none)")?;
                if p.is_empty() {
                    None
                } else {
                    Some(p)
                }
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
            let mut tag_list: Vec<String> = tags
                .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            // Auto-suggest tags if enabled
            if auto_tag {
                entry = entry.with_tags(tag_list.clone());
                let suggested_tags = crate::ai::PasswordAi::suggest_tags(&entry);
                if !suggested_tags.is_empty() {
                    Output::info(&format!(
                        "Auto-suggested tags: {}",
                        suggested_tags.join(", ")
                    ));
                    tag_list.extend(suggested_tags);
                }
            }

            entry = entry.with_tags(tag_list.clone());
            entry.folder = folder;
            entry.favorite = favorite;

            // Add notes
            if let Some(n) = notes {
                entry.notes = Some(crate::models::SensitiveString::new(n));
            }

            // Parse and add custom fields
            for field_str in fields {
                if let Some((key, value)) = field_str.split_once('=') {
                    entry.custom_fields.push(crate::models::CustomField {
                        name: key.trim().to_string(),
                        value: crate::models::SensitiveString::new(value.trim()),
                        is_hidden: true, // Default to hidden for security
                    });
                } else {
                    Output::warning(&format!(
                        "Invalid field format '{}', expected key=value",
                        field_str
                    ));
                }
            }

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
            if !tag_list.is_empty() {
                Output::field("Tags", &tag_list.join(", "));
            }
            if !entry.custom_fields.is_empty() {
                Output::field("Custom fields", &entry.custom_fields.len().to_string());
            }
            Ok(())
        }

        Commands::Get {
            query,
            copy,
            show,
            qr,
            field,
        } => {
            // Require unlocked vault
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

            // Refresh session
            let _ = session_mgr.refresh(15);

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            // Search for the entry
            let filter = crate::models::SearchFilter {
                query: Some(query.clone()),
                entry_type: None,
                tags: vec![],
                folder: None,
                favorites_only: false,
                needs_rotation: false,
                weak_passwords: false,
                offset: 0,
                limit: Some(10),
            };

            let entries = storage.search_entries(&filter)?;

            if entries.is_empty() {
                Output::error(&format!("No entry found matching '{}'", query));
                return Ok(());
            }

            // If multiple matches, let user choose
            let entry = if entries.len() == 1 {
                entries.into_iter().next().unwrap()
            } else {
                let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
                let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
                    .with_prompt("Multiple matches found. Select one:")
                    .items(&names)
                    .default(0)
                    .interact()?;
                entries.into_iter().nth(selection).unwrap()
            };

            // Handle specific field request
            if let Some(ref field_name) = field {
                let value = match field_name.to_lowercase().as_str() {
                    "password" | "pass" | "p" => entry
                        .password
                        .as_ref()
                        .map(|p| p.expose().to_string())
                        .unwrap_or_else(|| "(no password)".to_string()),
                    "username" | "user" | "u" => entry
                        .username
                        .clone()
                        .unwrap_or_else(|| "(no username)".to_string()),
                    "url" => entry.url.clone().unwrap_or_else(|| "(no url)".to_string()),
                    "notes" => entry
                        .notes
                        .as_ref()
                        .map(|n| n.expose().to_string())
                        .unwrap_or_else(|| "(no notes)".to_string()),
                    "totp" | "otp" => {
                        if let Some(ref secret) = entry.totp_secret {
                            match crate::totp::Totp::new(secret.expose()) {
                                Ok(totp) => match totp.generate() {
                                    Ok(code) => code,
                                    Err(_) => "(failed to generate TOTP)".to_string(),
                                },
                                Err(_) => "(invalid TOTP secret)".to_string(),
                            }
                        } else {
                            "(no TOTP configured)".to_string()
                        }
                    }
                    _ => {
                        // Try custom fields
                        entry
                            .custom_fields
                            .iter()
                            .find(|f| f.name.to_lowercase() == field_name.to_lowercase())
                            .map(|f| f.value.expose().to_string())
                            .unwrap_or_else(|| format!("(field '{}' not found)", field_name))
                    }
                };

                if copy {
                    copy_to_clipboard(&value, 30)?;
                } else {
                    println!("{}", value);
                }
                return Ok(());
            }

            // Show QR code if requested
            if qr {
                if let Some(ref password) = entry.password {
                    use qrcode::render::unicode;
                    use qrcode::QrCode;

                    match QrCode::new(password.expose()) {
                        Ok(code) => {
                            let qr_string = code
                                .render::<unicode::Dense1x2>()
                                .dark_color(unicode::Dense1x2::Light)
                                .light_color(unicode::Dense1x2::Dark)
                                .build();
                            println!("\n{}", qr_string);
                        }
                        Err(e) => Output::error(&format!("Failed to generate QR: {}", e)),
                    }
                } else {
                    Output::warning("No password to display as QR");
                }
                return Ok(());
            }

            // Display the entry
            display_entry(&entry, show);

            // Copy password to clipboard if requested
            if copy {
                if let Some(ref password) = entry.password {
                    copy_to_clipboard(password.expose(), 30)?;
                } else {
                    Output::warning("No password to copy");
                }
            }

            Ok(())
        }

        Commands::List {
            query,
            folder,
            tags,
            favorites,
            needs_rotation,
            weak,
            limit,
        } => {
            // Require unlocked vault
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
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
                limit,
            };

            let entries = storage.search_entries(&filter)?;

            // Display as table (handles empty case internally)
            display_entries_table(&entries);

            Ok(())
        }

        Commands::Edit {
            query,
            interactive: _,
        } => {
            // Require unlocked vault
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

            // Refresh session
            let _ = session_mgr.refresh(15);

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            // Search for the entry
            let filter = crate::models::SearchFilter {
                query: Some(query.clone()),
                entry_type: None,
                tags: vec![],
                folder: None,
                favorites_only: false,
                needs_rotation: false,
                weak_passwords: false,
                offset: 0,
                limit: Some(10),
            };

            let entries = storage.search_entries(&filter)?;

            if entries.is_empty() {
                Output::error(&format!("No entry found matching '{}'", query));
                return Ok(());
            }

            // If multiple matches, let user choose
            let mut entry = if entries.len() == 1 {
                entries.into_iter().next().unwrap()
            } else {
                let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
                let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
                    .with_prompt("Multiple matches found. Select one to edit:")
                    .items(&names)
                    .default(0)
                    .interact()?;
                entries.into_iter().nth(selection).unwrap()
            };

            // Show current values and allow editing
            Output::info(&format!(
                "Editing '{}' (press Enter to keep current value)",
                entry.name
            ));
            println!();

            // Edit name
            let new_name: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Name")
                .default(entry.name.clone())
                .interact_text()?;
            entry.name = new_name;

            // Edit username
            let current_username = entry.username.clone().unwrap_or_default();
            let new_username: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Username")
                .default(current_username)
                .allow_empty(true)
                .interact_text()?;
            entry.username = if new_username.is_empty() {
                None
            } else {
                Some(new_username)
            };

            // Edit password
            if Prompts::confirm("Change password?", false)? {
                let new_password = Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("New password")
                    .allow_empty_password(true)
                    .interact()?;
                if !new_password.is_empty() {
                    // Save old password to history
                    if let Some(ref old_password) = entry.password {
                        entry
                            .password_history
                            .push(crate::models::PasswordHistoryEntry {
                                password: old_password.clone(),
                                changed_at: chrono::Utc::now(),
                            });
                    }
                    entry.password = Some(crate::models::SensitiveString::new(new_password));
                    entry.password_changed_at = Some(chrono::Utc::now());
                }
            }

            // Edit URL
            let current_url = entry.url.clone().unwrap_or_default();
            let new_url: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("URL")
                .default(current_url)
                .allow_empty(true)
                .interact_text()?;
            entry.url = if new_url.is_empty() {
                None
            } else {
                Some(new_url)
            };

            // Edit tags
            let current_tags = entry.tags.join(", ");
            let new_tags: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Tags (comma-separated)")
                .default(current_tags)
                .allow_empty(true)
                .interact_text()?;
            entry.tags = new_tags
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            // Edit folder
            let current_folder = entry.folder.clone().unwrap_or_default();
            let new_folder: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Folder")
                .default(current_folder)
                .allow_empty(true)
                .interact_text()?;
            entry.folder = if new_folder.is_empty() {
                None
            } else {
                Some(new_folder)
            };

            // Toggle favorite
            entry.favorite = Prompts::confirm("Favorite?", entry.favorite)?;

            // Update timestamp
            entry.updated_at = chrono::Utc::now();

            // Save the entry
            storage.update_entry(&entry)?;
            Output::success(&format!("Updated '{}'", entry.name));
            Ok(())
        }

        Commands::Delete { query, force } => {
            // Require unlocked vault
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

            // Refresh session
            let _ = session_mgr.refresh(15);

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            // Search for the entry
            let filter = crate::models::SearchFilter {
                query: Some(query.clone()),
                entry_type: None,
                tags: vec![],
                folder: None,
                favorites_only: false,
                needs_rotation: false,
                weak_passwords: false,
                offset: 0,
                limit: Some(10),
            };

            let entries = storage.search_entries(&filter)?;

            if entries.is_empty() {
                Output::error(&format!("No entry found matching '{}'", query));
                return Ok(());
            }

            // If multiple matches, let user choose
            let entry = if entries.len() == 1 {
                entries.into_iter().next().unwrap()
            } else {
                let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
                let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
                    .with_prompt("Multiple matches found. Select one to delete:")
                    .items(&names)
                    .default(0)
                    .interact()?;
                entries.into_iter().nth(selection).unwrap()
            };

            // Confirm deletion
            if !force {
                let confirm = Prompts::confirm(&format!("Delete '{}'?", entry.name), false)?;
                if !confirm {
                    Output::info("Cancelled");
                    return Ok(());
                }
            }

            // Delete the entry
            storage.delete_entry(&entry.id)?;
            Output::success(&format!("Deleted '{}'", entry.name));
            Ok(())
        }

        Commands::Generate {
            length,
            no_uppercase,
            no_lowercase,
            no_digits,
            no_symbols,
            passphrase,
            words,
            copy,
        } => {
            if passphrase {
                Output::info(&format!("Generating {}-word passphrase...", words));
                let generator =
                    crate::crypto::PasswordGenerator::new(words * 5).with_lowercase(true);
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
            // Require unlocked vault
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

            // Refresh session
            let _ = session_mgr.refresh(15);

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            // Get all entries or search with query
            let filter = crate::models::SearchFilter {
                query: query.clone(),
                entry_type: None,
                tags: vec![],
                folder: None,
                favorites_only: false,
                needs_rotation: false,
                weak_passwords: false,
                offset: 0,
                limit: None,
            };

            let entries = storage.search_entries(&filter)?;

            if entries.is_empty() {
                if let Some(ref q) = query {
                    Output::warning(&format!("No entries found matching '{}'", q));
                } else {
                    Output::warning("No entries in vault");
                }
                return Ok(());
            }

            // Interactive fuzzy search
            let names: Vec<String> = entries
                .iter()
                .map(|e| {
                    let username = e.username.as_deref().unwrap_or("-");
                    format!("{} ({})", e.name, username)
                })
                .collect();

            let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
                .with_prompt("Search entries")
                .items(&names)
                .default(0)
                .interact()?;

            let entry = &entries[selection];
            display_entry(entry, false);

            // Offer to copy password
            if entry.password.is_some()
                && Prompts::confirm("Copy password to clipboard?", true)? {
                    copy_to_clipboard(entry.password.as_ref().unwrap().expose(), 30)?;
                }

            Ok(())
        }

        Commands::Share {
            query,
            to,
            one_time,
            expires,
        } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;
            let _ = session_mgr.refresh(15);

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            // Get our own keypair
            let own_keypair = storage
                .get_own_keypair()?
                .ok_or("No identity set up. Run 'vaultic identity show' first to create one.")?;
            let owner_name = storage
                .get_owner_name()?
                .unwrap_or_else(|| "Unknown".to_string());
            let sharing_manager = crate::sharing::SharingManager::new(own_keypair, owner_name);

            // Find the entry to share
            let entries = storage.list_entries()?;
            let entry = entries
                .iter()
                .find(|e| e.name.to_lowercase().contains(&query.to_lowercase()))
                .ok_or_else(|| format!("Entry '{}' not found", query))?;

            // Find the recipient
            let recipient = storage
                .get_identity_by_fingerprint(&to)?
                .or_else(|| {
                    storage
                        .list_identities()
                        .ok()
                        .and_then(|ids| ids.into_iter().find(|i| i.name.to_lowercase() == to.to_lowercase()))
                })
                .ok_or_else(|| format!("Recipient '{}' not found. Add their identity first with 'vaultic identity add'.", to))?;

            // Create the share
            let share = sharing_manager.create_share(
                entry,
                &recipient,
                one_time,
                expires,
                if one_time { Some(1) } else { None },
            )?;

            // Store the share
            storage.add_shared_secret(&share)?;

            Output::success(&format!("Shared '{}' with {}", entry.name, recipient.name));
            println!();
            Output::info("Share details:");
            println!("  Share ID:    {}", share.id);
            println!(
                "  Recipient:   {} ({})",
                recipient.name,
                &recipient.fingerprint[..16]
            );
            if let Some(exp) = share.expires_at {
                println!("  Expires:     {}", exp.format("%Y-%m-%d %H:%M UTC"));
            } else {
                println!("  Expires:     Never");
            }
            println!("  One-time:    {}", if one_time { "Yes" } else { "No" });

            // Generate share link
            let link = sharing_manager.create_share_link(&share);
            println!();
            Output::info(&format!("Share link: {}", link));

            Ok(())
        }

        Commands::Identity { command } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;
            let _ = session_mgr.refresh(15);

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            match command {
                IdentityCommands::Show => {
                    Output::header("Your Identity");

                    // Check if we have a keypair, create one if not
                    let (keypair, owner_name) = if let Some(kp) = storage.get_own_keypair()? {
                        let name = storage
                            .get_owner_name()?
                            .unwrap_or_else(|| "Unknown".to_string());
                        (kp, name)
                    } else {
                        // Create new identity
                        Output::info("Creating your identity...");
                        let keypair = crate::crypto::IdentityKeyPair::generate();

                        // Prompt for name
                        let name = if std::io::stdin().is_terminal() {
                            print!("Enter your name: ");
                            std::io::Write::flush(&mut std::io::stdout())?;
                            let mut input = String::new();
                            std::io::stdin().read_line(&mut input)?;
                            input.trim().to_string()
                        } else {
                            "Vaultic User".to_string()
                        };

                        storage.store_own_keypair(&keypair)?;
                        storage.store_owner_name(&name)?;
                        Output::success("Identity created!");
                        println!();
                        (keypair, name)
                    };

                    let fingerprint = keypair.fingerprint();

                    println!("  Name:        {}", owner_name);
                    println!("  Fingerprint: {}", fingerprint);
                    println!();
                    Output::info("Share your identity with 'vaultic identity export'");
                }

                IdentityCommands::Add { name, public_key } => {
                    // Import identity from exported string
                    let identity = crate::sharing::SharingManager::import_identity(&public_key)
                        .map_err(|_| "Invalid identity format. Make sure you're using the full exported string.")?;

                    // Override the imported name with the provided name
                    let mut identity = identity;
                    if !name.is_empty() {
                        identity.name = name.clone();
                    }

                    // Check for duplicates
                    if storage
                        .get_identity_by_fingerprint(&identity.fingerprint)?
                        .is_some()
                    {
                        Output::warning(&format!(
                            "Identity '{}' already exists",
                            identity.fingerprint
                        ));
                        return Ok(());
                    }

                    storage.add_identity(&identity)?;
                    Output::success(&format!("Added identity '{}'", identity.name));
                    println!("  Fingerprint: {}", identity.fingerprint);
                }

                IdentityCommands::List => {
                    Output::header("Trusted Identities");

                    let identities = storage.list_identities()?;
                    if identities.is_empty() {
                        Output::info("No trusted identities. Add one with 'vaultic identity add <name> <public_key>'");
                    } else {
                        for identity in identities {
                            println!("  {} ({})", identity.name, &identity.fingerprint[..16]);
                            if let Some(email) = &identity.email {
                                println!("    Email: {}", email);
                            }
                            println!("    Added: {}", identity.created_at.format("%Y-%m-%d"));
                            println!(
                                "    Trusted: {}",
                                if identity.trusted { "Yes" } else { "No" }
                            );
                            println!();
                        }
                    }
                }

                IdentityCommands::Remove { query } => {
                    // Find identity by fingerprint or name
                    let identity = storage
                        .get_identity_by_fingerprint(&query)?
                        .or_else(|| {
                            storage.list_identities().ok().and_then(|ids| {
                                ids.into_iter()
                                    .find(|i| i.name.to_lowercase() == query.to_lowercase())
                            })
                        })
                        .ok_or_else(|| format!("Identity '{}' not found", query))?;

                    storage.delete_identity(&identity.id)?;
                    Output::success(&format!("Removed identity '{}'", identity.name));
                }

                IdentityCommands::Export => {
                    Output::header("Export Your Identity");

                    let keypair = storage
                        .get_own_keypair()?
                        .ok_or("No identity set up. Run 'vaultic identity show' first.")?;
                    let owner_name = storage
                        .get_owner_name()?
                        .unwrap_or_else(|| "Unknown".to_string());
                    let sharing_manager = crate::sharing::SharingManager::new(keypair, owner_name);

                    let exported = sharing_manager.export_identity();
                    println!();
                    Output::info("Share this with others so they can send you entries:");
                    println!();
                    println!("{}", exported);
                    println!();
                    Output::info("They can add you with: vaultic identity add \"Your Name\" \"<the above string>\"");
                }
            }
            Ok(())
        }

        Commands::Suggest {
            analyze,
            check_breaches,
            auto_tag,
            apply,
        } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;
            let _ = session_mgr.refresh(15);

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;
            let entries = storage.list_entries()?;

            if entries.is_empty() {
                Output::info("Vault is empty. Add some entries first.");
                return Ok(());
            }

            Output::header("AI Suggestions");

            // Auto-tagging analysis
            if auto_tag {
                Output::info("Analyzing entries for tag suggestions...");
                println!();

                let mut entries_to_update: Vec<(crate::models::VaultEntry, Vec<String>)> =
                    Vec::new();

                for entry in &entries {
                    let suggested_tags = crate::ai::PasswordAi::suggest_tags(entry);
                    if !suggested_tags.is_empty() {
                        entries_to_update.push((entry.clone(), suggested_tags));
                    }
                }

                if entries_to_update.is_empty() {
                    Output::success("All entries are already well-tagged!");
                } else {
                    Output::info(&format!(
                        "Found {} entries that could use additional tags:",
                        entries_to_update.len()
                    ));
                    println!();

                    for (entry, suggested_tags) in &entries_to_update {
                        println!(
                            "  {} {} → {}",
                            "•".bright_blue(),
                            entry.name.bright_white(),
                            suggested_tags.join(", ").bright_cyan()
                        );
                        if !entry.tags.is_empty() {
                            println!("    Current tags: {}", entry.tags.join(", ").dimmed());
                        }
                    }

                    println!();

                    // Apply if requested or prompt
                    let should_apply = apply
                        || Prompts::confirm(
                            &format!("Apply tags to {} entries?", entries_to_update.len()),
                            false,
                        )?;

                    if should_apply {
                        let mut updated_count = 0;
                        for (mut entry, suggested_tags) in entries_to_update {
                            for tag in suggested_tags {
                                if !entry.tags.iter().any(|t| t.eq_ignore_ascii_case(&tag)) {
                                    entry.tags.push(tag);
                                }
                            }
                            entry.updated_at = chrono::Utc::now();
                            storage.update_entry(&entry)?;
                            updated_count += 1;
                        }
                        Output::success(&format!("Updated tags on {} entries", updated_count));
                    } else {
                        Output::info("No changes applied.");
                    }
                }
            }

            // Run general analysis if requested
            if analyze {
                println!();
                Output::info("Running vault analysis...");

                let ai = crate::ai::PasswordAi::new(crate::ai::AiConfig {
                    check_breaches,
                    ..Default::default()
                });

                // Use tokio runtime for async operations
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to create runtime: {}", e))?;

                let suggestions = rt.block_on(ai.analyze_vault(&entries));

                if suggestions.is_empty() {
                    Output::success("No issues found. Your vault looks great!");
                } else {
                    println!();
                    Output::warning(&format!("Found {} suggestions:", suggestions.len()));
                    println!();

                    for suggestion in suggestions {
                        let priority_color = match suggestion.priority {
                            crate::models::SuggestionPriority::Critical => "red",
                            crate::models::SuggestionPriority::High => "yellow",
                            crate::models::SuggestionPriority::Medium => "cyan",
                            crate::models::SuggestionPriority::Low => "dimmed",
                        };
                        let priority_str = format!("[{:?}]", suggestion.priority);
                        println!(
                            "  {} {} {}",
                            "•".bright_blue(),
                            match priority_color {
                                "red" => priority_str.bright_red().to_string(),
                                "yellow" => priority_str.bright_yellow().to_string(),
                                "cyan" => priority_str.bright_cyan().to_string(),
                                _ => priority_str.dimmed().to_string(),
                            },
                            suggestion.message
                        );
                    }
                }
            }

            // Check breaches if requested (and not already done by analyze)
            if check_breaches && !analyze {
                println!();
                Output::info("Checking passwords against breach databases...");

                let ai = crate::ai::PasswordAi::new(crate::ai::AiConfig {
                    check_breaches: true,
                    ..Default::default()
                });

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to create runtime: {}", e))?;

                let mut breached_count = 0;
                for entry in &entries {
                    if let Some(ref password) = entry.password {
                        if let Ok(is_breached) = rt.block_on(ai.check_breach(password.expose())) {
                            if is_breached {
                                breached_count += 1;
                                println!(
                                    "  {} {} - Password found in data breaches!",
                                    "⚠".bright_red(),
                                    entry.name.bright_white()
                                );
                            }
                        }
                    }
                }

                if breached_count == 0 {
                    Output::success("No breached passwords found!");
                } else {
                    println!();
                    Output::warning(&format!(
                        "{} password(s) found in breach databases. Change them immediately!",
                        breached_count
                    ));
                }
            }

            if !auto_tag && !analyze && !check_breaches {
                Output::info("Use --auto-tag, --analyze, or --check-breaches to get suggestions");
            }

            Ok(())
        }

        Commands::Exec {
            entry,
            command,
            env_mappings,
            dry_run,
        } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;
            let _ = session_mgr.refresh(15);

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            // Find the entry
            let entries = storage.list_entries()?;
            let vault_entry = entries
                .iter()
                .find(|e| {
                    e.name.to_lowercase() == entry.to_lowercase() || e.id.to_string() == entry
                })
                .ok_or_else(|| format!("Entry '{}' not found", entry))?;

            // Build environment variables
            let mut env_vars: Vec<(String, String)> = Vec::new();

            // Default mappings based on entry fields
            if let Some(ref username) = vault_entry.username {
                env_vars.push(("VAULTIC_USERNAME".to_string(), username.clone()));
            }
            if let Some(ref password) = vault_entry.password {
                env_vars.push((
                    "VAULTIC_PASSWORD".to_string(),
                    password.expose().to_string(),
                ));
            }
            if let Some(ref url) = vault_entry.url {
                env_vars.push(("VAULTIC_URL".to_string(), url.clone()));
            }

            // Add custom fields
            for field in &vault_entry.custom_fields {
                let env_name = format!(
                    "VAULTIC_{}",
                    field.name.to_uppercase().replace([' ', '-'], "_")
                );
                env_vars.push((env_name, field.value.expose().to_string()));
            }

            // Add entry's env mappings
            for mapping in &vault_entry.env_mappings {
                let value = match mapping.field.as_str() {
                    "password" => vault_entry
                        .password
                        .as_ref()
                        .map(|p| p.expose().to_string()),
                    "username" => vault_entry.username.clone(),
                    "url" => vault_entry.url.clone(),
                    field_name => vault_entry
                        .custom_fields
                        .iter()
                        .find(|f| f.name == field_name)
                        .map(|f| f.value.expose().to_string()),
                };
                if let Some(val) = value {
                    env_vars.push((mapping.env_var.clone(), val));
                }
            }

            // Add CLI-specified mappings (override defaults)
            for mapping in &env_mappings {
                if let Some((env_var, field_name)) = mapping.split_once('=') {
                    let value = match field_name {
                        "password" => vault_entry
                            .password
                            .as_ref()
                            .map(|p| p.expose().to_string()),
                        "username" => vault_entry.username.clone(),
                        "url" => vault_entry.url.clone(),
                        field_name => vault_entry
                            .custom_fields
                            .iter()
                            .find(|f| f.name == field_name)
                            .map(|f| f.value.expose().to_string()),
                    };
                    if let Some(val) = value {
                        env_vars.push((env_var.to_string(), val));
                    } else {
                        Output::warning(&format!("Field '{}' not found in entry", field_name));
                    }
                } else {
                    Output::warning(&format!(
                        "Invalid env mapping format '{}', expected ENV_VAR=field",
                        mapping
                    ));
                }
            }

            if dry_run {
                Output::header("Environment Variables");
                for (name, value) in &env_vars {
                    // Mask passwords in output
                    let display_value = if name.contains("PASSWORD")
                        || name.contains("SECRET")
                        || name.contains("KEY")
                    {
                        format!("{}...", &value.chars().take(4).collect::<String>())
                    } else {
                        value.clone()
                    };
                    Output::field(name, &display_value);
                }
                Output::info(&format!("Command: {}", command.join(" ")));
                return Ok(());
            }

            if command.is_empty() {
                return Err("No command specified. Use: vaultic exec <entry> -- <command>".into());
            }

            // Run the command with environment variables
            let mut cmd = std::process::Command::new(&command[0]);
            cmd.args(&command[1..]);
            for (name, value) in &env_vars {
                cmd.env(name, value);
            }

            let status = cmd
                .status()
                .map_err(|e| format!("Failed to run command: {}", e))?;

            if !status.success() {
                if let Some(code) = status.code() {
                    std::process::exit(code);
                } else {
                    return Err("Command terminated by signal".into());
                }
            }

            Ok(())
        }

        Commands::ShellInit { shell, fzf } => {
            let script = match shell {
                ShellType::Bash => generate_bash_init(fzf),
                ShellType::Zsh => generate_zsh_init(fzf),
                ShellType::Fish => generate_fish_init(fzf),
                ShellType::Powershell => generate_powershell_init(fzf),
            };
            println!("{}", script);
            Ok(())
        }

        Commands::Export { output, format } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
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
                    Output::success(&format!(
                        "Exported {} entries to '{}'",
                        entries.len(),
                        output
                    ));
                    Output::warning("Note: Passwords exported in plaintext. Handle with care!");
                }
                ExportFormat::Csv => {
                    let data = crate::export::export_csv(&entries)?;
                    std::fs::write(&output, &data)?;
                    Output::success(&format!(
                        "Exported {} entries to '{}'",
                        entries.len(),
                        output
                    ));
                    Output::warning("Note: Passwords exported in plaintext. Handle with care!");
                }
                ExportFormat::Encrypted => {
                    let bytes = crate::export::export_encrypted(&entries, &master_key)?;
                    std::fs::write(&output, &bytes)?;
                    Output::success(&format!(
                        "Exported {} entries to '{}' (encrypted)",
                        entries.len(),
                        output
                    ));
                }
            }
            Ok(())
        }

        Commands::Import { input, format } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
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
                    return Err(
                        "Use --format bitwarden, lastpass, onepassword, or encrypted".into(),
                    );
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
                Output::field(
                    "Session expires in",
                    &format!("{} min", info.minutes_remaining()),
                );
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

        Commands::Health {
            verbose,
            check_breaches,
        } => {
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
            let mut reused_passwords: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
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
                let _entropy = crate::crypto::PasswordAnalyzer::entropy(password);
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
                reused_passwords
                    .entry(hash)
                    .or_default()
                    .push(entry.name.clone());

                // Check age
                if entry.updated_at < ninety_days_ago {
                    let days = (now - entry.updated_at).num_days();
                    old_passwords.push((entry.name.clone(), days));
                }
            }

            // Filter to only show reused (more than 1 entry with same password)
            let reused: Vec<_> = reused_passwords
                .into_iter()
                .filter(|(_, names)| names.len() > 1)
                .collect();

            // Calculate health score
            let issues = weak_passwords.len() + reused.len() + old_passwords.len();
            let score = if total == 0 {
                100
            } else {
                100 - (issues * 100 / total).min(100)
            };

            let score_color = if score >= 80 {
                "\x1b[32m"
            }
            // Green
            else if score >= 60 {
                "\x1b[33m"
            }
            // Yellow
            else {
                "\x1b[31m"
            }; // Red

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
                Output::warning(&format!(
                    "{} entries share passwords ({} unique reused)",
                    count,
                    reused.len()
                ));
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
                Output::warning(&format!(
                    "{} passwords older than 90 days",
                    old_passwords.len()
                ));
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
                Output::info(&format!(
                    "{} entries without passwords (notes/cards)",
                    no_password.len()
                ));
            }

            // Breach check (optional)
            if check_breaches {
                println!();
                Output::info("Checking passwords against Have I Been Pwned...");
                let rt = tokio::runtime::Runtime::new()?;
                let config = crate::ai::AiConfig {
                    check_breaches: true,
                    enable_suggestions: false,
                    ..Default::default()
                };
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

        Commands::History {
            query,
            show,
            restore,
        } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            // Find entry
            let entries = storage.list_entries()?;
            let entry = entries
                .iter()
                .find(|e| {
                    e.name.to_lowercase().contains(&query.to_lowercase())
                        || e.id.to_string() == query
                })
                .ok_or_else(|| format!("Entry '{}' not found", query))?;

            let history = entry.get_password_history();

            if let Some(index) = restore {
                if index == 0 || index > history.len() {
                    return Err(
                        format!("Invalid history index. Available: 1-{}", history.len()).into(),
                    );
                }

                // Get a mutable copy
                let mut entry_clone = entry.clone();
                entry_clone.restore_password(index - 1);
                storage.update_entry(&entry_clone)?;

                Output::success(&format!(
                    "Restored password #{} for '{}'",
                    index, entry.name
                ));
                return Ok(());
            }

            if history.is_empty() {
                Output::info(&format!("No password history for '{}'", entry.name));
                return Ok(());
            }

            println!();
            Output::header(&format!("Password History: {}", entry.name));
            println!();

            for (i, hist) in history.iter().enumerate() {
                let age = chrono::Utc::now() - hist.changed_at;
                let age_str = if age.num_days() > 0 {
                    format!("{} days ago", age.num_days())
                } else if age.num_hours() > 0 {
                    format!("{} hours ago", age.num_hours())
                } else {
                    format!("{} minutes ago", age.num_minutes())
                };

                if show {
                    println!("  {}. {} ({})", i + 1, hist.password.expose(), age_str);
                } else {
                    let masked = "*".repeat(hist.password.len().min(12));
                    println!(
                        "  {}. {} ({} chars, {})",
                        i + 1,
                        masked,
                        hist.password.len(),
                        age_str
                    );
                }
            }

            println!();
            if !show {
                Output::info("Use --show to reveal passwords");
            }
            Output::info("Use --restore <N> to restore a password from history");

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

        Commands::Batch { command } => {
            let session_mgr = crate::session::SessionManager::new()?;
            let (vault_path, master_key) = session_mgr
                .load()
                .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

            let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
            storage.unlock(&master_key)?;

            let all_entries = storage.list_entries()?;

            match command {
                BatchCommands::Tag {
                    filter,
                    folder,
                    add,
                    remove,
                } => {
                    // Filter entries
                    let matches: Vec<_> = all_entries
                        .iter()
                        .filter(|e| {
                            let name_match = filter
                                .as_ref()
                                .map(|f| e.name.to_lowercase().contains(&f.to_lowercase()))
                                .unwrap_or(true);
                            let folder_match = folder
                                .as_ref()
                                .map(|f| e.folder.as_ref().map(|ef| ef == f).unwrap_or(false))
                                .unwrap_or(true);
                            name_match && folder_match
                        })
                        .collect();

                    if matches.is_empty() {
                        Output::warning("No entries match the filter");
                        return Ok(());
                    }

                    let add_tags: Vec<String> = add
                        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                        .unwrap_or_default();
                    let remove_tags: Vec<String> = remove
                        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                        .unwrap_or_default();

                    let mut updated = 0;
                    for entry in matches {
                        let mut entry_clone = entry.clone();
                        let mut changed = false;

                        for tag in &add_tags {
                            if !entry_clone.tags.contains(tag) {
                                entry_clone.tags.push(tag.clone());
                                changed = true;
                            }
                        }

                        for tag in &remove_tags {
                            if let Some(pos) = entry_clone.tags.iter().position(|t| t == tag) {
                                entry_clone.tags.remove(pos);
                                changed = true;
                            }
                        }

                        if changed {
                            entry_clone.updated_at = chrono::Utc::now();
                            storage.update_entry(&entry_clone)?;
                            updated += 1;
                        }
                    }

                    Output::success(&format!("Updated tags on {} entries", updated));
                    Ok(())
                }

                BatchCommands::Delete {
                    filter,
                    tags,
                    folder,
                    yes,
                } => {
                    let tag_list: Vec<String> = tags
                        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                        .unwrap_or_default();

                    let matches: Vec<_> = all_entries
                        .iter()
                        .filter(|e| {
                            let name_match = filter
                                .as_ref()
                                .map(|f| e.name.to_lowercase().contains(&f.to_lowercase()))
                                .unwrap_or(true);
                            let folder_match = folder
                                .as_ref()
                                .map(|f| e.folder.as_ref().map(|ef| ef == f).unwrap_or(false))
                                .unwrap_or(true);
                            let tag_match = if tag_list.is_empty() {
                                true
                            } else {
                                tag_list.iter().any(|t| e.tags.contains(t))
                            };
                            name_match && folder_match && tag_match
                        })
                        .collect();

                    if matches.is_empty() {
                        Output::warning("No entries match the filter");
                        return Ok(());
                    }

                    println!("Entries to delete:");
                    for entry in &matches {
                        println!("  • {} ({})", entry.name, entry.id);
                    }
                    println!();

                    if !yes {
                        let confirm = Prompts::confirm(
                            &format!("Delete {} entries? This cannot be undone", matches.len()),
                            false,
                        )?;
                        if !confirm {
                            Output::info("Cancelled");
                            return Ok(());
                        }
                    }

                    for entry in &matches {
                        storage.delete_entry(&entry.id)?;
                    }

                    Output::success(&format!("Deleted {} entries", matches.len()));
                    Ok(())
                }

                BatchCommands::Move { filter, tags, to } => {
                    let tag_list: Vec<String> = tags
                        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                        .unwrap_or_default();

                    let matches: Vec<_> = all_entries
                        .iter()
                        .filter(|e| {
                            let name_match = filter
                                .as_ref()
                                .map(|f| e.name.to_lowercase().contains(&f.to_lowercase()))
                                .unwrap_or(true);
                            let tag_match = if tag_list.is_empty() {
                                true
                            } else {
                                tag_list.iter().any(|t| e.tags.contains(t))
                            };
                            name_match && tag_match
                        })
                        .collect();

                    if matches.is_empty() {
                        Output::warning("No entries match the filter");
                        return Ok(());
                    }

                    for entry in &matches {
                        let mut entry_clone = (*entry).clone();
                        entry_clone.folder = Some(to.clone());
                        entry_clone.updated_at = chrono::Utc::now();
                        storage.update_entry(&entry_clone)?;
                    }

                    Output::success(&format!(
                        "Moved {} entries to folder '{}'",
                        matches.len(),
                        to
                    ));
                    Ok(())
                }

                BatchCommands::Favorite {
                    filter,
                    folder,
                    set,
                } => {
                    let matches: Vec<_> = all_entries
                        .iter()
                        .filter(|e| {
                            let name_match = filter
                                .as_ref()
                                .map(|f| e.name.to_lowercase().contains(&f.to_lowercase()))
                                .unwrap_or(true);
                            let folder_match = folder
                                .as_ref()
                                .map(|f| e.folder.as_ref().map(|ef| ef == f).unwrap_or(false))
                                .unwrap_or(true);
                            name_match && folder_match
                        })
                        .collect();

                    if matches.is_empty() {
                        Output::warning("No entries match the filter");
                        return Ok(());
                    }

                    let mut updated = 0;
                    for entry in &matches {
                        if entry.favorite != set {
                            let mut entry_clone = (*entry).clone();
                            entry_clone.favorite = set;
                            entry_clone.updated_at = chrono::Utc::now();
                            storage.update_entry(&entry_clone)?;
                            updated += 1;
                        }
                    }

                    let action = if set { "favorited" } else { "unfavorited" };
                    Output::success(&format!(
                        "{} {} entries",
                        action
                            .to_string()
                            .chars()
                            .next()
                            .unwrap()
                            .to_uppercase()
                            .to_string()
                            + &action[1..],
                        updated
                    ));
                    Ok(())
                }
            }
        }

        Commands::Credential { command } => {
            // Git credential helper
            // Used with: git config credential.helper '!vaultic credential'
            match command {
                CredentialCommands::Get => {
                    // Read credential request from stdin
                    let mut input = String::new();
                    loop {
                        let mut line = String::new();
                        if io::stdin().read_line(&mut line)? == 0 || line.trim().is_empty() {
                            break;
                        }
                        input.push_str(&line);
                    }

                    // Parse the input
                    let mut protocol = String::new();
                    let mut host = String::new();
                    let mut path = String::new();

                    for line in input.lines() {
                        if let Some((key, value)) = line.split_once('=') {
                            match key {
                                "protocol" => protocol = value.to_string(),
                                "host" => host = value.to_string(),
                                "path" => path = value.to_string(),
                                _ => {}
                            }
                        }
                    }

                    if host.is_empty() {
                        return Ok(()); // No host, nothing to do
                    }

                    // Look for matching entry
                    let session_mgr = crate::session::SessionManager::new()?;
                    let (vault_path, master_key) = session_mgr
                        .load()
                        .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

                    let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
                    storage.unlock(&master_key)?;
                    let entries = storage.list_entries()?;

                    // Search for entries matching the host
                    let _url_to_match = if path.is_empty() {
                        format!("{}://{}", protocol, host)
                    } else {
                        format!("{}://{}/{}", protocol, host, path)
                    };

                    // Find best match - first try exact URL match, then host match
                    let matching_entry = entries
                        .iter()
                        .filter(|e| e.url.is_some() && e.username.is_some() && e.password.is_some())
                        .find(|e| {
                            let entry_url = e.url.as_ref().unwrap().to_lowercase();
                            entry_url.contains(&host.to_lowercase())
                        });

                    if let Some(entry) = matching_entry {
                        if let (Some(username), Some(password)) = (&entry.username, &entry.password)
                        {
                            println!("username={}", username);
                            println!("password={}", password.expose());
                        }
                    }

                    Ok(())
                }

                CredentialCommands::Store => {
                    // Read credential data from stdin
                    let mut input = String::new();
                    loop {
                        let mut line = String::new();
                        if io::stdin().read_line(&mut line)? == 0 || line.trim().is_empty() {
                            break;
                        }
                        input.push_str(&line);
                    }

                    // Parse the input
                    let mut protocol = String::new();
                    let mut host = String::new();
                    let mut username = String::new();
                    let mut password = String::new();
                    let mut path = String::new();

                    for line in input.lines() {
                        if let Some((key, value)) = line.split_once('=') {
                            match key {
                                "protocol" => protocol = value.to_string(),
                                "host" => host = value.to_string(),
                                "username" => username = value.to_string(),
                                "password" => password = value.to_string(),
                                "path" => path = value.to_string(),
                                _ => {}
                            }
                        }
                    }

                    if host.is_empty() || username.is_empty() || password.is_empty() {
                        return Ok(()); // Not enough info
                    }

                    // Check if entry already exists
                    let session_mgr = crate::session::SessionManager::new()?;
                    let (vault_path, master_key) = session_mgr
                        .load()
                        .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

                    let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
                    storage.unlock(&master_key)?;
                    let entries = storage.list_entries()?;

                    let url = if path.is_empty() {
                        format!("{}://{}", protocol, host)
                    } else {
                        format!("{}://{}/{}", protocol, host, path)
                    };

                    let existing = entries.iter().find(|e| {
                        e.url
                            .as_ref()
                            .map(|u| u.to_lowercase().contains(&host.to_lowercase()))
                            .unwrap_or(false)
                            && e.username.as_ref().map(|u| u == &username).unwrap_or(false)
                    });

                    if let Some(entry) = existing {
                        // Update existing entry
                        let mut updated = entry.clone();
                        updated.set_password(password);
                        storage.update_entry(&updated)?;
                    } else {
                        // Create new entry
                        let entry_name = format!("git:{}", host);
                        let entry = VaultEntry::new(&entry_name, EntryType::Password)
                            .with_username(&username)
                            .with_password(password)
                            .with_url(&url)
                            .with_tags(vec!["git".to_string()]);
                        storage.add_entry(&entry)?;
                    }

                    Ok(())
                }

                CredentialCommands::Erase => {
                    // Read credential data from stdin
                    let mut input = String::new();
                    loop {
                        let mut line = String::new();
                        if io::stdin().read_line(&mut line)? == 0 || line.trim().is_empty() {
                            break;
                        }
                        input.push_str(&line);
                    }

                    // Parse the input
                    let mut host = String::new();
                    let mut username = String::new();

                    for line in input.lines() {
                        if let Some((key, value)) = line.split_once('=') {
                            match key {
                                "host" => host = value.to_string(),
                                "username" => username = value.to_string(),
                                _ => {}
                            }
                        }
                    }

                    if host.is_empty() {
                        return Ok(());
                    }

                    // Find and delete matching entry
                    let session_mgr = crate::session::SessionManager::new()?;
                    let (vault_path, master_key) = session_mgr
                        .load()
                        .map_err(|_| "Vault is locked. Run 'vaultic unlock' first.")?;

                    let mut storage = crate::storage::VaultStorage::open(&vault_path)?;
                    storage.unlock(&master_key)?;
                    let entries = storage.list_entries()?;

                    let matching_entry = entries.iter().find(|e| {
                        let url_match = e
                            .url
                            .as_ref()
                            .map(|u| u.to_lowercase().contains(&host.to_lowercase()))
                            .unwrap_or(false);
                        let user_match = if username.is_empty() {
                            true
                        } else {
                            e.username.as_ref().map(|u| u == &username).unwrap_or(false)
                        };
                        url_match && user_match
                    });

                    if let Some(entry) = matching_entry {
                        storage.delete_entry(&entry.id)?;
                    }

                    Ok(())
                }
            }
        }

        Commands::Migrate { dry_run, password } => {
            let vault_path = default_vault_path(&cli.vault);

            use crate::migration::VaultMigrator;
            use crate::storage::keyring::VaultVersion;

            let migrator = VaultMigrator::new(&vault_path);

            // Check if migration is needed
            if !migrator.needs_migration() {
                let version = migrator.current_version();
                match version {
                    VaultVersion::V2 => {
                        Output::info("Vault is already using v2 format (multi-method unlock)");
                        return Ok(());
                    }
                    VaultVersion::Unknown => {
                        Output::error("Not a valid vault directory");
                        return Ok(());
                    }
                    VaultVersion::V1 => {
                        // Should not happen since needs_migration returned false
                        Output::error("Unexpected vault state");
                        return Ok(());
                    }
                }
            }

            Output::header("Vault Migration v1 → v2");
            Output::info("This will upgrade your vault to support multiple unlock methods");
            Output::info("(password, recovery key, YubiKey, GPG)");
            println!();

            // Get password
            let password = match password {
                Some(p) => p,
                None => Prompts::master_password(false)?,
            };

            if dry_run {
                let spinner = Output::spinner("Checking migration compatibility...");
                match migrator.dry_run(&password) {
                    Ok(report) => {
                        spinner.finish_with_message("Compatible".green().to_string());
                        println!();
                        Output::field("Entries", &report.entry_count.to_string());
                        Output::field("Vault ID", &report.vault_id.to_string());
                        Output::info("Run without --dry-run to perform the migration");
                    }
                    Err(e) => {
                        spinner.finish_with_message("Failed".red().to_string());
                        Output::error(&format!("Migration check failed: {}", e));
                    }
                }
            } else {
                // Confirm migration
                if !Prompts::confirm("Proceed with migration?", true)? {
                    Output::info("Migration cancelled");
                    return Ok(());
                }

                let spinner = Output::spinner("Migrating vault...");
                match migrator.migrate(&password) {
                    Ok(report) => {
                        spinner.finish_with_message("Complete".green().to_string());
                        println!();
                        Output::success("Vault migrated to v2 format!");
                        Output::field("Entries", &report.entry_count.to_string());
                        if let Some(backup_path) = &report.backup_path {
                            Output::field("Backup", &backup_path.display().to_string());
                        }
                        println!();
                        Output::info("You can now add additional unlock methods with:");
                        Output::info("  vaultic unlock-method add recovery");
                        Output::info("  vaultic unlock-method add yubikey");
                    }
                    Err(e) => {
                        spinner.finish_with_message("Failed".red().to_string());
                        Output::error(&format!("Migration failed: {}", e));
                    }
                }
            }

            Ok(())
        }

        Commands::UnlockMethod { command } => {
            let vault_path = default_vault_path(&cli.vault);

            use crate::storage::keyring::{detect_vault_version, KeyringStorage, VaultVersion};

            // Check vault version
            let version = detect_vault_version(&vault_path);
            if version == VaultVersion::V1 {
                Output::error("This vault uses the v1 format. Run 'vaultic migrate' first.");
                return Ok(());
            }
            if version == VaultVersion::Unknown {
                Output::error("Not a valid vault directory");
                return Ok(());
            }

            match command {
                UnlockMethodCommands::List => {
                    let keyring_storage = KeyringStorage::new(&vault_path);
                    if !keyring_storage.exists() {
                        Output::error("No keyring found. Run 'vaultic migrate' first.");
                        return Ok(());
                    }

                    let keyring = keyring_storage.load()?;

                    Output::header("Configured Unlock Methods");
                    println!();

                    if keyring.keys.is_empty() {
                        Output::info("No unlock methods configured");
                    } else {
                        for key in keyring.list_methods() {
                            let method_str = key.method.to_string();
                            let label = key.label.as_deref().unwrap_or("-");
                            let last_used = key
                                .last_used
                                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                                .unwrap_or_else(|| "never".to_string());

                            println!(
                                "  {} {} ({}) - Last used: {}",
                                "•".bright_blue(),
                                method_str.bright_white(),
                                label.dimmed(),
                                last_used.dimmed()
                            );
                        }
                    }
                    println!();
                    Output::field("Total methods", &keyring.method_count().to_string());
                }

                UnlockMethodCommands::Add {
                    method,
                    label,
                    password,
                } => match method {
                    UnlockMethodType::Password => {
                        Output::info("Password method is configured during 'vaultic init' or 'vaultic migrate'");
                    }
                    UnlockMethodType::Recovery => {
                        use crate::crypto::keys::UnlockMethod;
                        use crate::crypto::wrap::unwrap_vault_key;
                        use crate::recovery::RecoveryKey;
                        use crate::storage::keyring::{
                            detect_vault_version, KeyringStorage, VaultVersion,
                        };
                        use crate::storage::KdfParamsStorage;

                        // Check vault version
                        let version = detect_vault_version(&vault_path);
                        if version == VaultVersion::V1 {
                            Output::error(
                                "This vault uses the v1 format. Run 'vaultic migrate' first.",
                            );
                            return Ok(());
                        }
                        if version == VaultVersion::Unknown {
                            Output::error("Not a valid vault directory. Run 'vaultic init' first.");
                            return Ok(());
                        }

                        // Check if recovery key already exists
                        let keyring_storage = KeyringStorage::new(&vault_path);
                        let mut keyring = keyring_storage.load()?;

                        if keyring.has_recovery() {
                            Output::warning("A recovery key is already configured for this vault.");
                            if !Prompts::confirm(
                                "Do you want to replace it with a new recovery key?",
                                false,
                            )? {
                                return Ok(());
                            }
                            // Remove old recovery key
                            if let Some(old_key) =
                                keyring.find_by_method(&UnlockMethod::RecoveryKey)
                            {
                                let old_id = old_key.id;
                                keyring.remove_key(&old_id)?;
                            }
                        }

                        // Get master password to unlock vault and get vault key
                        let master_password = if let Some(p) = password {
                            p
                        } else {
                            Prompts::master_password(false)?
                        };

                        // Derive KEK from password
                        let kdf_params = KdfParamsStorage::load(&vault_path)?;
                        let password_kek = crate::crypto::kek::derive_from_password(
                            master_password.as_bytes(),
                            &kdf_params,
                        )?;

                        // Get the password encrypted vault key and unwrap it
                        let password_encrypted =
                            match keyring.find_by_method(&UnlockMethod::Password) {
                                Some(key) => key,
                                None => {
                                    Output::error("Password unlock method not found in keyring.");
                                    return Ok(());
                                }
                            };

                        let vault_key = unwrap_vault_key(password_encrypted, &password_kek)?;

                        // Generate new recovery key
                        let recovery_key = RecoveryKey::generate()?;

                        Output::header("Recovery Key Generated");
                        println!();
                        Output::warning(
                            "IMPORTANT: Write down these 24 words and store them safely!",
                        );
                        Output::warning(
                            "This is the ONLY way to recover your vault if you forget your password.",
                        );
                        Output::warning("Anyone with these words can access your vault!");
                        println!();

                        // Display formatted recovery key
                        println!("{}", recovery_key.display_formatted());

                        // Wrap vault key with recovery key
                        let recovery_label = label.unwrap_or_else(|| "Recovery Key".to_string());
                        let (encrypted_key, _salt) =
                            recovery_key.wrap_vault_key(&vault_key, Some(recovery_label))?;

                        // Add to keyring and save
                        keyring.add_key(encrypted_key);
                        keyring_storage.save(&keyring)?;

                        println!();
                        Output::success("Recovery key has been added to your vault.");
                        Output::info(&format!("Fingerprint: {}", recovery_key.fingerprint()));
                        Output::info(&format!("Checksum: {}", recovery_key.checksum()));
                        Output::info(
                            "Tip: Use 'vaultic recovery generate --qr' to display a QR code.",
                        );
                    }
                    UnlockMethodType::Yubikey => {
                        Output::warning("YubiKey setup will be implemented in Phase 3");
                        Output::info("Coming soon: vaultic setup hardware");
                    }
                    UnlockMethodType::Gpg => {
                        Output::warning("GPG unlock method will be implemented in Phase 5");
                        Output::info("Coming soon: vaultic unlock-method add gpg --key-id <KEY>");
                    }
                },

                UnlockMethodCommands::Remove { id, password: _ } => {
                    Output::warning(&format!(
                        "Remove unlock method '{}' - to be implemented",
                        id
                    ));
                    Output::info("This will require master password verification");
                }

                UnlockMethodCommands::Test { method } => {
                    Output::info(&format!("Testing {} unlock method...", method));
                    Output::warning("Test functionality will be implemented with each method");
                }
            }

            Ok(())
        }

        Commands::Recovery { command } => {
            let vault_path = default_vault_path(&cli.vault);

            use crate::crypto::keys::UnlockMethod;
            use crate::crypto::wrap::unwrap_vault_key;
            use crate::crypto::MasterKey;
            use crate::recovery::RecoveryKey;
            use crate::storage::keyring::{detect_vault_version, KeyringStorage, VaultVersion};
            use crate::storage::KdfParamsStorage;

            match command {
                RecoveryCommands::Generate {
                    qr,
                    label,
                    password,
                } => {
                    // Check vault version
                    let version = detect_vault_version(&vault_path);
                    if version == VaultVersion::V1 {
                        Output::error(
                            "This vault uses the v1 format. Run 'vaultic migrate' first.",
                        );
                        return Ok(());
                    }
                    if version == VaultVersion::Unknown {
                        Output::error("Not a valid vault directory. Run 'vaultic init' first.");
                        return Ok(());
                    }

                    // Check if recovery key already exists
                    let keyring_storage = KeyringStorage::new(&vault_path);
                    let mut keyring = keyring_storage.load()?;

                    if keyring.has_recovery() {
                        Output::warning("A recovery key is already configured for this vault.");
                        if !Prompts::confirm(
                            "Do you want to replace it with a new recovery key?",
                            false,
                        )? {
                            return Ok(());
                        }
                        // Remove old recovery key
                        if let Some(old_key) = keyring.find_by_method(&UnlockMethod::RecoveryKey) {
                            let old_id = old_key.id;
                            keyring.remove_key(&old_id)?;
                        }
                    }

                    // Get master password to unlock vault and get vault key
                    let master_password = if let Some(p) = password {
                        p
                    } else {
                        Prompts::master_password(false)?
                    };

                    // Derive KEK from password
                    let kdf_params = KdfParamsStorage::load(&vault_path)?;
                    let password_kek = crate::crypto::kek::derive_from_password(
                        master_password.as_bytes(),
                        &kdf_params,
                    )?;

                    // Get the password encrypted vault key and unwrap it
                    let password_encrypted = match keyring.find_by_method(&UnlockMethod::Password) {
                        Some(key) => key,
                        None => {
                            Output::error("Password unlock method not found in keyring.");
                            return Ok(());
                        }
                    };

                    let vault_key = unwrap_vault_key(password_encrypted, &password_kek)?;

                    // Generate new recovery key
                    let recovery_key = RecoveryKey::generate()?;

                    Output::header("Recovery Key Generated");
                    println!();
                    Output::warning(
                        "⚠️  IMPORTANT: Write down these 24 words and store them safely!",
                    );
                    Output::warning("⚠️  This is the ONLY way to recover your vault if you forget your password.");
                    Output::warning("⚠️  Anyone with these words can access your vault!");
                    println!();

                    // Display formatted recovery key
                    println!("{}", recovery_key.display_formatted());

                    // Show QR code if requested
                    if qr {
                        println!();
                        Output::info("QR Code (for backup scanning):");
                        println!();
                        println!("{}", recovery_key.generate_qr()?);
                    }

                    // Wrap vault key with recovery key
                    let recovery_label = label.unwrap_or_else(|| "Recovery Key".to_string());
                    let (encrypted_key, _salt) =
                        recovery_key.wrap_vault_key(&vault_key, Some(recovery_label))?;

                    // Add to keyring and save
                    keyring.add_key(encrypted_key);
                    keyring_storage.save(&keyring)?;

                    println!();
                    Output::success("Recovery key has been added to your vault.");
                    Output::info(&format!("Fingerprint: {}", recovery_key.fingerprint()));
                    Output::info(&format!("Checksum: {}", recovery_key.checksum()));

                    Ok(())
                }

                RecoveryCommands::Verify { phrase } => {
                    // Get phrase from argument or prompt
                    let recovery_phrase = if let Some(p) = phrase {
                        p
                    } else {
                        Output::info("Enter your 24-word recovery phrase:");
                        dialoguer::Input::<String>::new()
                            .with_prompt("Recovery phrase")
                            .interact()?
                    };

                    // Validate the phrase
                    match RecoveryKey::from_phrase(&recovery_phrase) {
                        Ok(recovery_key) => {
                            Output::success("✓ Valid BIP39 recovery phrase!");
                            println!();
                            Output::info(&format!("Fingerprint: {}", recovery_key.fingerprint()));
                            Output::info(&format!("Checksum: {}", recovery_key.checksum()));

                            // Check if it matches the configured recovery key
                            let version = detect_vault_version(&vault_path);
                            if version == VaultVersion::V2 {
                                let keyring_storage = KeyringStorage::new(&vault_path);
                                if let Ok(keyring) = keyring_storage.load() {
                                    if let Some(configured) =
                                        keyring.find_by_method(&UnlockMethod::RecoveryKey)
                                    {
                                        if let crate::crypto::keys::MethodData::Recovery {
                                            fingerprint,
                                            ..
                                        } = &configured.method_data
                                        {
                                            if *fingerprint == recovery_key.fingerprint() {
                                                println!();
                                                Output::success("✓ This recovery key matches the configured vault recovery key!");
                                            } else {
                                                println!();
                                                Output::warning("⚠ This recovery key does NOT match the configured vault recovery key.");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            Output::error(&format!("✗ Invalid recovery phrase: {}", e));
                            Output::info("Make sure you entered all 24 words correctly.");
                        }
                    }

                    Ok(())
                }

                RecoveryCommands::Show => {
                    let version = detect_vault_version(&vault_path);
                    if version != VaultVersion::V2 {
                        Output::error("This vault doesn't support recovery keys. Run 'vaultic migrate' first.");
                        return Ok(());
                    }

                    let keyring_storage = KeyringStorage::new(&vault_path);
                    let keyring = keyring_storage.load()?;

                    if let Some(recovery) = keyring.find_by_method(&UnlockMethod::RecoveryKey) {
                        Output::header("Recovery Key Information");
                        println!();

                        if let Some(label) = &recovery.label {
                            println!("  Label:       {}", label);
                        }
                        if let crate::crypto::keys::MethodData::Recovery { fingerprint, .. } =
                            &recovery.method_data
                        {
                            println!("  Fingerprint: {} ...", fingerprint);
                        }
                        println!(
                            "  Created:     {}",
                            recovery.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                        if let Some(last_used) = recovery.last_used {
                            println!(
                                "  Last used:   {}",
                                last_used.format("%Y-%m-%d %H:%M:%S UTC")
                            );
                        } else {
                            println!("  Last used:   Never");
                        }
                        println!("  ID:          {}", recovery.id);
                    } else {
                        Output::warning("No recovery key configured for this vault.");
                        Output::info("Run 'vaultic recovery generate' to create one.");
                    }

                    Ok(())
                }

                RecoveryCommands::Unlock { phrase, timeout } => {
                    let version = detect_vault_version(&vault_path);
                    if version != VaultVersion::V2 {
                        Output::error("This vault doesn't support recovery key unlock. Run 'vaultic migrate' first.");
                        return Ok(());
                    }

                    let keyring_storage = KeyringStorage::new(&vault_path);
                    let mut keyring = keyring_storage.load()?;

                    // Check if recovery key is configured
                    let recovery_encrypted =
                        match keyring.find_by_method(&UnlockMethod::RecoveryKey) {
                            Some(key) => key,
                            None => {
                                Output::error("No recovery key configured for this vault.");
                                Output::info("Run 'vaultic recovery generate' to create one.");
                                return Ok(());
                            }
                        };

                    // Get recovery phrase
                    let recovery_phrase = if let Some(p) = phrase {
                        p
                    } else {
                        Output::info("Enter your 24-word recovery phrase:");
                        dialoguer::Input::<String>::new()
                            .with_prompt("Recovery phrase")
                            .interact()?
                    };

                    // Parse and derive KEK from recovery phrase
                    let recovery_key = RecoveryKey::from_phrase(&recovery_phrase)?;

                    // Get salt from method data
                    let salt =
                        if let crate::crypto::keys::MethodData::Recovery { salt, fingerprint } =
                            &recovery_encrypted.method_data
                        {
                            // Verify fingerprint matches
                            if *fingerprint != recovery_key.fingerprint() {
                                Output::error(
                                    "Recovery phrase does not match the configured recovery key.",
                                );
                                return Ok(());
                            }
                            salt.clone()
                        } else {
                            Output::error("Invalid recovery key data format");
                            return Ok(());
                        };

                    let kek = recovery_key.derive_kek(&salt)?;

                    // Unwrap vault key
                    let vault_key = match unwrap_vault_key(recovery_encrypted, &kek) {
                        Ok(key) => key,
                        Err(_) => {
                            Output::error("Failed to unlock vault. Invalid recovery phrase.");
                            return Ok(());
                        }
                    };

                    // Convert VaultKey to MasterKey for session
                    let master_key = MasterKey::from_bytes(*vault_key.expose());

                    // Create session
                    let session_mgr = crate::session::SessionManager::new()?;
                    session_mgr.create(&vault_path, &master_key, timeout)?;

                    // Update last_used timestamp
                    if let Some(recovery_mut) =
                        keyring.find_by_method_mut(&UnlockMethod::RecoveryKey)
                    {
                        recovery_mut.mark_used();
                        keyring_storage.save(&keyring)?;
                    }

                    Output::success(&format!(
                        "Vault unlocked with recovery key (expires in {} minutes)",
                        timeout
                    ));

                    Ok(())
                }
            }
        }
    }
}

/// Generate bash shell init script
fn generate_bash_init(fzf: bool) -> String {
    let mut script = r#"# Vaultic shell integration for Bash
# Add this to your ~/.bashrc:
#   eval "$(vaultic shell-init bash)"

# Aliases
alias vu='vaultic unlock'
alias vl='vaultic lock'
alias vs='vaultic status'
alias va='vaultic add'
alias vg='vaultic get'
alias vls='vaultic list'
alias ve='vaultic exec'

# Quick copy password to clipboard
vcp() {
    vaultic get "$1" --copy
}

# Quick search
vsearch() {
    vaultic search "$@"
}

# Run command with entry credentials
vrun() {
    local entry="$1"
    shift
    vaultic exec "$entry" -- "$@"
}
"#
    .to_string();

    if fzf {
        script.push_str(
            r#"
# FZF integration (requires fzf)
vf() {
    local entry
    entry=$(vaultic list --json 2>/dev/null | jq -r '.[].name' | fzf --prompt="Select entry: ")
    if [ -n "$entry" ]; then
        vaultic get "$entry" --copy
        echo "Password copied for: $entry"
    fi
}

# FZF exec
vfe() {
    local entry
    entry=$(vaultic list --json 2>/dev/null | jq -r '.[].name' | fzf --prompt="Select entry: ")
    if [ -n "$entry" ]; then
        shift
        vaultic exec "$entry" -- "$@"
    fi
}
"#,
        );
    }

    script
}

/// Generate zsh shell init script
fn generate_zsh_init(fzf: bool) -> String {
    let mut script = r#"# Vaultic shell integration for Zsh
# Add this to your ~/.zshrc:
#   eval "$(vaultic shell-init zsh)"

# Aliases
alias vu='vaultic unlock'
alias vl='vaultic lock'
alias vs='vaultic status'
alias va='vaultic add'
alias vg='vaultic get'
alias vls='vaultic list'
alias ve='vaultic exec'

# Quick copy password to clipboard
vcp() {
    vaultic get "$1" --copy
}

# Quick search
vsearch() {
    vaultic search "$@"
}

# Run command with entry credentials
vrun() {
    local entry="$1"
    shift
    vaultic exec "$entry" -- "$@"
}

# Completion
if type compdef &>/dev/null; then
    _vaultic_entries() {
        local entries
        entries=(${(f)"$(vaultic list --json 2>/dev/null | jq -r '.[].name' 2>/dev/null)"})
        _describe 'entries' entries
    }
    compdef _vaultic_entries vg vcp vrun
fi
"#
    .to_string();

    if fzf {
        script.push_str(
            r#"
# FZF integration (requires fzf)
vf() {
    local entry
    entry=$(vaultic list --json 2>/dev/null | jq -r '.[].name' | fzf --prompt="Select entry: ")
    if [[ -n "$entry" ]]; then
        vaultic get "$entry" --copy
        echo "Password copied for: $entry"
    fi
}

# FZF exec
vfe() {
    local entry
    entry=$(vaultic list --json 2>/dev/null | jq -r '.[].name' | fzf --prompt="Select entry: ")
    if [[ -n "$entry" ]]; then
        shift
        vaultic exec "$entry" -- "$@"
    fi
}
"#,
        );
    }

    script
}

/// Generate fish shell init script
fn generate_fish_init(fzf: bool) -> String {
    let mut script = r#"# Vaultic shell integration for Fish
# Add this to your ~/.config/fish/config.fish:
#   vaultic shell-init fish | source

# Aliases
alias vu='vaultic unlock'
alias vl='vaultic lock'
alias vs='vaultic status'
alias va='vaultic add'
alias vg='vaultic get'
alias vls='vaultic list'
alias ve='vaultic exec'

# Quick copy password to clipboard
function vcp
    vaultic get $argv[1] --copy
end

# Quick search
function vsearch
    vaultic search $argv
end

# Run command with entry credentials
function vrun
    set entry $argv[1]
    set -e argv[1]
    vaultic exec $entry -- $argv
end
"#
    .to_string();

    if fzf {
        script.push_str(
            r#"
# FZF integration (requires fzf)
function vf
    set entry (vaultic list --json 2>/dev/null | jq -r '.[].name' | fzf --prompt="Select entry: ")
    if test -n "$entry"
        vaultic get "$entry" --copy
        echo "Password copied for: $entry"
    end
end

# FZF exec
function vfe
    set entry (vaultic list --json 2>/dev/null | jq -r '.[].name' | fzf --prompt="Select entry: ")
    if test -n "$entry"
        set -e argv[1]
        vaultic exec "$entry" -- $argv
    end
end
"#,
        );
    }

    script
}

/// Generate PowerShell init script
fn generate_powershell_init(fzf: bool) -> String {
    let mut script = r#"# Vaultic shell integration for PowerShell
# Add this to your $PROFILE:
#   Invoke-Expression (vaultic shell-init powershell)

# Aliases
Set-Alias -Name vu -Value { vaultic unlock }
Set-Alias -Name vl -Value { vaultic lock }
Set-Alias -Name vs -Value { vaultic status }
Set-Alias -Name va -Value { vaultic add }
Set-Alias -Name vg -Value { vaultic get }
Set-Alias -Name vls -Value { vaultic list }
Set-Alias -Name ve -Value { vaultic exec }

# Quick copy password to clipboard
function vcp {
    param([string]$Entry)
    vaultic get $Entry --copy
}

# Quick search
function vsearch {
    vaultic search @args
}

# Run command with entry credentials
function vrun {
    param(
        [string]$Entry,
        [Parameter(ValueFromRemainingArguments)]
        [string[]]$Command
    )
    vaultic exec $Entry -- @Command
}
"#
    .to_string();

    if fzf {
        script.push_str(r#"
# FZF integration (requires fzf)
function vf {
    $entry = vaultic list --json 2>$null | ConvertFrom-Json | ForEach-Object { $_.name } | fzf --prompt="Select entry: "
    if ($entry) {
        vaultic get $entry --copy
        Write-Host "Password copied for: $entry"
    }
}
"#);
    }

    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_entry_row_conversion() {
        let entry = VaultEntry::new("Test", EntryType::Password)
            .with_username("user@test.com")
            .with_tags(vec!["work".to_string()]);

        let row = EntryRow::from(&entry);
        assert_eq!(row.name, "Test");
        assert_eq!(row.username, "user@test.com");
    }

    #[test]
    fn test_cli_add_with_fields() {
        let cli = Cli::try_parse_from([
            "vaultic",
            "add",
            "MyEntry",
            "--username",
            "user@example.com",
            "--password",
            "secret",
            "--field",
            "key1=value1",
            "--field",
            "key2=value2",
            "--notes",
            "Some notes",
            "--favorite",
        ])
        .unwrap();

        match cli.command {
            Commands::Add {
                name,
                fields,
                notes,
                favorite,
                ..
            } => {
                assert_eq!(name, "MyEntry");
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0], "key1=value1");
                assert_eq!(fields[1], "key2=value2");
                assert_eq!(notes, Some("Some notes".to_string()));
                assert!(favorite);
            }
            _ => panic!("Expected Add command"),
        }
    }

    #[test]
    fn test_cli_batch_delete() {
        let cli = Cli::try_parse_from([
            "vaultic",
            "batch",
            "delete",
            "--filter",
            "test",
            "--tags",
            "old,unused",
            "--yes",
        ])
        .unwrap();

        match cli.command {
            Commands::Batch {
                command:
                    BatchCommands::Delete {
                        filter, tags, yes, ..
                    },
            } => {
                assert_eq!(filter, Some("test".to_string()));
                assert_eq!(tags, Some("old,unused".to_string()));
                assert!(yes);
            }
            _ => panic!("Expected Batch Delete command"),
        }
    }

    #[test]
    fn test_cli_batch_move() {
        let cli = Cli::try_parse_from([
            "vaultic",
            "batch",
            "move",
            "--filter",
            "github",
            "--to",
            "work/development",
        ])
        .unwrap();

        match cli.command {
            Commands::Batch {
                command: BatchCommands::Move { filter, to, .. },
            } => {
                assert_eq!(filter, Some("github".to_string()));
                assert_eq!(to, "work/development");
            }
            _ => panic!("Expected Batch Move command"),
        }
    }

    #[test]
    fn test_cli_credential_get() {
        let cli = Cli::try_parse_from(["vaultic", "credential", "get"]).unwrap();

        match cli.command {
            Commands::Credential {
                command: CredentialCommands::Get,
            } => {}
            _ => panic!("Expected Credential Get command"),
        }
    }

    #[test]
    fn test_cli_credential_store() {
        let cli = Cli::try_parse_from(["vaultic", "credential", "store"]).unwrap();

        match cli.command {
            Commands::Credential {
                command: CredentialCommands::Store,
            } => {}
            _ => panic!("Expected Credential Store command"),
        }
    }

    #[test]
    fn test_cli_history() {
        let cli = Cli::try_parse_from(["vaultic", "history", "github", "--show"]).unwrap();

        match cli.command {
            Commands::History {
                query,
                show,
                restore,
            } => {
                assert_eq!(query, "github");
                assert!(show);
                assert_eq!(restore, None);
            }
            _ => panic!("Expected History command"),
        }
    }
}
