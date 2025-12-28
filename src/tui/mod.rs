//! Terminal User Interface for Vaultic
//!
//! Interactive TUI mode using ratatui for a full-screen terminal experience.

use thiserror::Error;

/// TUI module errors
#[derive(Debug, Error)]
pub enum TuiError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Terminal error: {0}")]
    Terminal(String),

    #[error("Vault error: {0}")]
    Vault(String),
}

pub type TuiResult<T> = Result<T, TuiError>;

/// Application mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Viewing entry list
    List,
    /// Searching entries
    Search,
    /// Viewing entry details
    Detail,
    /// Editing an entry
    Edit,
    /// Sharing an entry
    Share,
    /// Help screen
    Help,
}

impl Default for Mode {
    fn default() -> Self {
        Self::List
    }
}

/// TUI Application state
pub struct App {
    /// Current mode
    pub mode: Mode,
    /// Selected entry index
    pub selected: usize,
    /// Search query
    pub search_query: String,
    /// Whether the app should quit
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            selected: 0,
            search_query: String::new(),
            should_quit: false,
        }
    }
}

impl App {
    /// Create a new App instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle key input
    pub fn handle_key(&mut self, _key: char) {
        // TODO: Implement key handling
    }

    /// Move selection up
    pub fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Move selection down
    pub fn select_next(&mut self, max: usize) {
        if self.selected < max.saturating_sub(1) {
            self.selected += 1;
        }
    }
}

/// Run the TUI application
pub fn run() -> TuiResult<()> {
    // TODO: Implement full TUI with ratatui
    println!("TUI mode is not yet implemented.");
    println!("Use the CLI commands instead:");
    println!("  vaultic list     - List all entries");
    println!("  vaultic search   - Search entries");
    println!("  vaultic add      - Add a new entry");
    println!("  vaultic get      - Get an entry");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_default() {
        let app = App::new();
        assert_eq!(app.mode, Mode::List);
        assert_eq!(app.selected, 0);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_select_navigation() {
        let mut app = App::new();
        app.select_next(10);
        assert_eq!(app.selected, 1);
        app.select_previous();
        assert_eq!(app.selected, 0);
        app.select_previous();
        assert_eq!(app.selected, 0); // Should not go below 0
    }
}
