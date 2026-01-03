//! Terminal User Interface for Vaultic
//!
//! Interactive TUI mode using ratatui for a full-screen terminal experience.

use std::io::stdout;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use thiserror::Error;

use crate::models::VaultEntry;
use crate::session::SessionManager;
use crate::storage::VaultStorage;

/// TUI module errors
#[derive(Debug, Error)]
pub enum TuiError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Terminal error: {0}")]
    Terminal(String),

    #[error("Vault error: {0}")]
    Vault(String),

    #[error("Session error: {0}")]
    Session(String),
}

pub type TuiResult<T> = Result<T, TuiError>;

/// Application mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Viewing entry list
    #[default]
    List,
    /// Searching entries
    Search,
    /// Viewing entry details
    Detail,
    /// Help screen
    Help,
    /// Confirm delete
    ConfirmDelete,
}

/// TUI Application state
pub struct App {
    /// Current mode
    pub mode: Mode,
    /// Vault storage
    pub storage: VaultStorage,
    /// All entries
    pub entries: Vec<VaultEntry>,
    /// Filtered entries (for search)
    pub filtered_entries: Vec<usize>,
    /// List state for selection
    pub list_state: ListState,
    /// Search query
    pub search_query: String,
    /// Whether the app should quit
    pub should_quit: bool,
    /// Status message
    pub status_message: Option<String>,
    /// Show password in detail view
    pub show_password: bool,
}

impl App {
    /// Create a new App instance
    pub fn new(storage: VaultStorage) -> TuiResult<Self> {
        let entries = storage
            .list_entries()
            .map_err(|e| TuiError::Vault(e.to_string()))?;

        let filtered_entries: Vec<usize> = (0..entries.len()).collect();

        let mut list_state = ListState::default();
        if !entries.is_empty() {
            list_state.select(Some(0));
        }

        Ok(Self {
            mode: Mode::default(),
            storage,
            entries,
            filtered_entries,
            list_state,
            search_query: String::new(),
            should_quit: false,
            status_message: None,
            show_password: false,
        })
    }

    /// Refresh entries from storage
    pub fn refresh_entries(&mut self) -> TuiResult<()> {
        self.entries = self
            .storage
            .list_entries()
            .map_err(|e| TuiError::Vault(e.to_string()))?;
        self.apply_filter();
        Ok(())
    }

    /// Apply search filter
    fn apply_filter(&mut self) {
        if self.search_query.is_empty() {
            self.filtered_entries = (0..self.entries.len()).collect();
        } else {
            let query = self.search_query.to_lowercase();
            self.filtered_entries = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| {
                    e.name.to_lowercase().contains(&query)
                        || e.username
                            .as_ref()
                            .map(|u| u.to_lowercase().contains(&query))
                            .unwrap_or(false)
                        || e.tags.iter().any(|t| t.to_lowercase().contains(&query))
                })
                .map(|(i, _)| i)
                .collect();
        }

        // Adjust selection
        if self.filtered_entries.is_empty() {
            self.list_state.select(None);
        } else if let Some(selected) = self.list_state.selected() {
            if selected >= self.filtered_entries.len() {
                self.list_state
                    .select(Some(self.filtered_entries.len() - 1));
            }
        } else {
            self.list_state.select(Some(0));
        }
    }

    /// Get currently selected entry
    fn selected_entry(&self) -> Option<&VaultEntry> {
        self.list_state
            .selected()
            .and_then(|i| self.filtered_entries.get(i))
            .and_then(|&idx| self.entries.get(idx))
    }

    /// Move selection up
    pub fn select_previous(&mut self) {
        if let Some(selected) = self.list_state.selected() {
            if selected > 0 {
                self.list_state.select(Some(selected - 1));
            }
        }
    }

    /// Move selection down
    pub fn select_next(&mut self) {
        if let Some(selected) = self.list_state.selected() {
            if selected < self.filtered_entries.len().saturating_sub(1) {
                self.list_state.select(Some(selected + 1));
            }
        } else if !self.filtered_entries.is_empty() {
            self.list_state.select(Some(0));
        }
    }

    /// Go to first entry
    pub fn select_first(&mut self) {
        if !self.filtered_entries.is_empty() {
            self.list_state.select(Some(0));
        }
    }

    /// Go to last entry
    pub fn select_last(&mut self) {
        if !self.filtered_entries.is_empty() {
            self.list_state
                .select(Some(self.filtered_entries.len() - 1));
        }
    }

    /// Copy password to clipboard
    pub fn copy_password(&mut self) -> TuiResult<()> {
        if let Some(entry) = self.selected_entry() {
            if let Some(password) = &entry.password {
                let mut clipboard = arboard::Clipboard::new()
                    .map_err(|e| TuiError::Terminal(format!("Clipboard error: {}", e)))?;
                clipboard
                    .set_text(password.expose().to_string())
                    .map_err(|e| TuiError::Terminal(format!("Clipboard error: {}", e)))?;

                self.status_message =
                    Some(format!("Password for '{}' copied to clipboard", entry.name));
            } else {
                self.status_message = Some("No password for this entry".to_string());
            }
        }
        Ok(())
    }

    /// Delete selected entry
    pub fn delete_selected(&mut self) -> TuiResult<()> {
        if let Some(entry) = self.selected_entry().cloned() {
            self.storage
                .delete_entry(&entry.id)
                .map_err(|e| TuiError::Vault(e.to_string()))?;
            self.status_message = Some(format!("Deleted '{}'", entry.name));
            self.refresh_entries()?;
            self.mode = Mode::List;
        }
        Ok(())
    }

    /// Handle key input based on current mode
    pub fn handle_key(&mut self, key: KeyCode) -> TuiResult<()> {
        match self.mode {
            Mode::List => self.handle_list_key(key)?,
            Mode::Search => self.handle_search_key(key)?,
            Mode::Detail => self.handle_detail_key(key)?,
            Mode::Help => self.handle_help_key(key)?,
            Mode::ConfirmDelete => self.handle_confirm_delete_key(key)?,
        }
        Ok(())
    }

    fn handle_list_key(&mut self, key: KeyCode) -> TuiResult<()> {
        match key {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('j') | KeyCode::Down => self.select_next(),
            KeyCode::Char('k') | KeyCode::Up => self.select_previous(),
            KeyCode::Char('g') => self.select_first(),
            KeyCode::Char('G') => self.select_last(),
            KeyCode::Char('/') => {
                self.mode = Mode::Search;
                self.search_query.clear();
            }
            KeyCode::Enter => {
                if self.selected_entry().is_some() {
                    self.mode = Mode::Detail;
                    self.show_password = false;
                }
            }
            KeyCode::Char('y') => self.copy_password()?,
            KeyCode::Char('d') => {
                if self.selected_entry().is_some() {
                    self.mode = Mode::ConfirmDelete;
                }
            }
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Char('r') => {
                self.refresh_entries()?;
                self.status_message = Some("Entries refreshed".to_string());
            }
            KeyCode::Esc => {
                self.search_query.clear();
                self.apply_filter();
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_search_key(&mut self, key: KeyCode) -> TuiResult<()> {
        match key {
            KeyCode::Esc => {
                self.mode = Mode::List;
                self.search_query.clear();
                self.apply_filter();
            }
            KeyCode::Enter => {
                self.mode = Mode::List;
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.apply_filter();
            }
            KeyCode::Char(c) => {
                self.search_query.push(c);
                self.apply_filter();
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_detail_key(&mut self, key: KeyCode) -> TuiResult<()> {
        match key {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = Mode::List;
                self.show_password = false;
            }
            KeyCode::Char('y') => self.copy_password()?,
            KeyCode::Char('p') => self.show_password = !self.show_password,
            KeyCode::Char('d') => self.mode = Mode::ConfirmDelete,
            _ => {}
        }
        Ok(())
    }

    fn handle_help_key(&mut self, key: KeyCode) -> TuiResult<()> {
        match key {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => {
                self.mode = Mode::List;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_confirm_delete_key(&mut self, key: KeyCode) -> TuiResult<()> {
        match key {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                self.delete_selected()?;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.mode = Mode::List;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Run the TUI application
pub fn run() -> TuiResult<()> {
    run_with_vault(None)
}

/// Run the TUI with optional vault path
pub fn run_with_vault(vault_path: Option<&std::path::Path>) -> TuiResult<()> {
    // Load session to verify vault is unlocked
    let session_mgr = SessionManager::new().map_err(|e| TuiError::Session(e.to_string()))?;

    let (session_vault_path, master_key) = session_mgr.load().map_err(|e| {
        TuiError::Session(format!(
            "Vault is locked: {}. Run 'vaultic unlock' first.",
            e
        ))
    })?;

    // Use provided path or session's vault path
    let vault_dir = vault_path
        .map(|p| p.to_path_buf())
        .unwrap_or(session_vault_path);

    // Open storage and unlock with master key
    let mut storage = VaultStorage::open(&vault_dir).map_err(|e| TuiError::Vault(e.to_string()))?;

    storage
        .unlock(&master_key)
        .map_err(|e| TuiError::Vault(e.to_string()))?;

    // Verify we can list entries
    let _ = storage
        .list_entries()
        .map_err(|e| TuiError::Vault(e.to_string()))?;

    // Create app
    let mut app = App::new(storage)?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run main loop
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> TuiResult<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key.code)?;
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Footer/status
        ])
        .split(f.area());

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "  Vaultic",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" - Password Manager"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(header, chunks[0]);

    // Main content
    match app.mode {
        Mode::List | Mode::Search => render_list(f, app, chunks[1]),
        Mode::Detail => render_detail(f, app, chunks[1]),
        Mode::Help => render_help(f, chunks[1]),
        Mode::ConfirmDelete => {
            render_list(f, app, chunks[1]);
            render_confirm_delete(f, app, chunks[1]);
        }
    }

    // Footer
    let status = if let Some(msg) = &app.status_message {
        msg.clone()
    } else {
        match app.mode {
            Mode::List => {
                "j/k:nav  /:search  Enter:view  y:copy  d:delete  ?:help  q:quit".to_string()
            }
            Mode::Search => format!("Search: {}█", app.search_query),
            Mode::Detail => "y:copy  p:toggle password  d:delete  q/Esc:back".to_string(),
            Mode::Help => "Press q or ? to close help".to_string(),
            Mode::ConfirmDelete => "Delete? y:yes  n:no".to_string(),
        }
    };

    let footer = Paragraph::new(status)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[2]);
}

fn render_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .filtered_entries
        .iter()
        .map(|&idx| {
            let entry = &app.entries[idx];
            let username = entry.username.as_deref().unwrap_or("-");
            let tags = if entry.tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", entry.tags.join(", "))
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    &entry.name,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(username, Style::default().fg(Color::Gray)),
                Span::styled(tags, Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();

    let title = if app.search_query.is_empty() {
        format!(" Entries ({}) ", app.entries.len())
    } else {
        format!(
            " Search: \"{}\" ({} matches) ",
            app.search_query,
            app.filtered_entries.len()
        )
    };

    let list = List::new(items)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.list_state.clone());
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let entry = match app.selected_entry() {
        Some(e) => e,
        None => return,
    };

    let password_display: &str = if app.show_password {
        entry.password.as_ref().map(|p| p.expose()).unwrap_or("-")
    } else {
        "••••••••••••"
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Name:     ", Style::default().fg(Color::Gray)),
            Span::styled(
                &entry.name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Username: ", Style::default().fg(Color::Gray)),
            Span::raw(entry.username.as_deref().unwrap_or("-")),
        ]),
        Line::from(vec![
            Span::styled("Password: ", Style::default().fg(Color::Gray)),
            Span::styled(
                password_display,
                Style::default().fg(if app.show_password {
                    Color::Yellow
                } else {
                    Color::DarkGray
                }),
            ),
            Span::styled(
                if app.show_password {
                    " (visible)"
                } else {
                    " (hidden, press p to show)"
                },
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    if let Some(url) = &entry.url {
        lines.push(Line::from(vec![
            Span::styled("URL:      ", Style::default().fg(Color::Gray)),
            Span::styled(url, Style::default().fg(Color::Blue)),
        ]));
    }

    if !entry.tags.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Tags:     ", Style::default().fg(Color::Gray)),
            Span::raw(entry.tags.join(", ")),
        ]));
    }

    if let Some(folder) = &entry.folder {
        lines.push(Line::from(vec![
            Span::styled("Folder:   ", Style::default().fg(Color::Gray)),
            Span::raw(folder),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Created:  ", Style::default().fg(Color::Gray)),
        Span::raw(entry.created_at.format("%Y-%m-%d %H:%M").to_string()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Updated:  ", Style::default().fg(Color::Gray)),
        Span::raw(entry.updated_at.format("%Y-%m-%d %H:%M").to_string()),
    ]));

    if let Some(notes) = &entry.notes {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Notes:",
            Style::default().fg(Color::Gray),
        )]));
        for line in notes.expose().lines() {
            lines.push(Line::from(format!("  {}", line)));
        }
    }

    let detail = Paragraph::new(lines).block(
        Block::default()
            .title(" Entry Details ")
            .borders(Borders::ALL),
    );
    f.render_widget(detail, area);
}

fn render_help(f: &mut Frame, area: Rect) {
    let help_text = vec![
        Line::from(Span::styled(
            "Navigation",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("  j / ↓     Move down"),
        Line::from("  k / ↑     Move up"),
        Line::from("  g         Go to first entry"),
        Line::from("  G         Go to last entry"),
        Line::from("  Enter     View entry details"),
        Line::from(""),
        Line::from(Span::styled(
            "Actions",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("  /         Search entries"),
        Line::from("  y         Copy password to clipboard"),
        Line::from("  p         Toggle password visibility (in detail view)"),
        Line::from("  d         Delete entry"),
        Line::from("  r         Refresh entries"),
        Line::from(""),
        Line::from(Span::styled(
            "General",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("  ?         Show/hide this help"),
        Line::from("  Esc       Cancel / go back"),
        Line::from("  q         Quit"),
    ];

    let help =
        Paragraph::new(help_text).block(Block::default().title(" Help ").borders(Borders::ALL));
    f.render_widget(help, area);
}

fn render_confirm_delete(f: &mut Frame, app: &App, area: Rect) {
    let entry_name = app.selected_entry().map(|e| e.name.as_str()).unwrap_or("");

    let popup_width = 50;
    let popup_height = 5;
    let popup_area = Rect {
        x: area.x + (area.width.saturating_sub(popup_width)) / 2,
        y: area.y + (area.height.saturating_sub(popup_height)) / 2,
        width: popup_width.min(area.width),
        height: popup_height.min(area.height),
    };

    let text = vec![
        Line::from(""),
        Line::from(format!("Delete '{}'?", entry_name)),
        Line::from(""),
    ];

    f.render_widget(Clear, popup_area);
    let popup = Paragraph::new(text)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .title(" Confirm Delete ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        );
    f.render_widget(popup, popup_area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_default() {
        assert_eq!(Mode::default(), Mode::List);
    }
}
