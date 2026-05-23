//! TUI color themes.

use ratatui::style::{Color, Modifier, Style};

/// Built-in theme names supported by `Theme::from_name`.
pub const THEME_NAMES: &[&str] = &["default", "dracula", "solarized-dark", "monochrome"];

/// Resolved styles used across the TUI.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub border: Style,
    pub header: Style,
    pub title: Style,
    pub normal: Style,
    pub label: Style,
    pub muted: Style,
    pub selection: Style,
    pub accent: Style,
    pub link: Style,
    pub error: Style,
}

impl Default for Theme {
    fn default() -> Self {
        Self::default_theme()
    }
}

impl Theme {
    /// Default theme — preserves the original Vaultic look.
    pub fn default_theme() -> Self {
        Self {
            border: Style::default().fg(Color::Cyan),
            header: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            title: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            normal: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            label: Style::default().fg(Color::Gray),
            muted: Style::default().fg(Color::DarkGray),
            selection: Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
            accent: Style::default().fg(Color::Yellow),
            link: Style::default().fg(Color::Blue),
            error: Style::default().fg(Color::Red),
        }
    }

    /// Dracula — popular dark theme with vivid pinks, purples, and yellows.
    pub fn dracula() -> Self {
        let fg = Color::Rgb(0xf8, 0xf8, 0xf2);
        let comment = Color::Rgb(0x62, 0x72, 0xa4);
        let purple = Color::Rgb(0xbd, 0x93, 0xf9);
        let pink = Color::Rgb(0xff, 0x79, 0xc6);
        let cyan = Color::Rgb(0x8b, 0xe9, 0xfd);
        let yellow = Color::Rgb(0xf1, 0xfa, 0x8c);
        let red = Color::Rgb(0xff, 0x55, 0x55);

        Self {
            border: Style::default().fg(purple),
            header: Style::default().fg(pink).add_modifier(Modifier::BOLD),
            title: Style::default().fg(pink).add_modifier(Modifier::BOLD),
            normal: Style::default().fg(fg).add_modifier(Modifier::BOLD),
            label: Style::default().fg(comment),
            muted: Style::default().fg(comment),
            selection: Style::default()
                .bg(comment)
                .fg(fg)
                .add_modifier(Modifier::BOLD),
            accent: Style::default().fg(yellow),
            link: Style::default().fg(cyan),
            error: Style::default().fg(red),
        }
    }

    /// Solarized Dark — Ethan Schoonover's restrained palette.
    pub fn solarized_dark() -> Self {
        let base0 = Color::Rgb(0x83, 0x94, 0x96);
        let base1 = Color::Rgb(0x93, 0xa1, 0xa1);
        let base02 = Color::Rgb(0x07, 0x36, 0x42);
        let blue = Color::Rgb(0x26, 0x8b, 0xd2);
        let cyan = Color::Rgb(0x2a, 0xa1, 0x98);
        let yellow = Color::Rgb(0xb5, 0x89, 0x00);
        let red = Color::Rgb(0xdc, 0x32, 0x2f);

        Self {
            border: Style::default().fg(blue),
            header: Style::default().fg(cyan).add_modifier(Modifier::BOLD),
            title: Style::default().fg(cyan).add_modifier(Modifier::BOLD),
            normal: Style::default().fg(base1).add_modifier(Modifier::BOLD),
            label: Style::default().fg(base0),
            muted: Style::default().fg(base0),
            selection: Style::default()
                .bg(base02)
                .fg(base1)
                .add_modifier(Modifier::BOLD),
            accent: Style::default().fg(yellow),
            link: Style::default().fg(blue),
            error: Style::default().fg(red),
        }
    }

    /// Monochrome — no color, distinctions via bold/reverse/underline.
    pub fn monochrome() -> Self {
        Self {
            border: Style::default().fg(Color::Gray),
            header: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            title: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            normal: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            label: Style::default().fg(Color::Gray),
            muted: Style::default().fg(Color::DarkGray),
            selection: Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            accent: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::REVERSED),
            link: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::UNDERLINED),
            error: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
        }
    }

    /// Look up a theme by canonical name. Names are case-insensitive; both
    /// `solarized-dark` and `solarized_dark` are accepted.
    pub fn from_name(name: &str) -> Option<Self> {
        let normalized = name.trim().to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "default" => Some(Self::default_theme()),
            "dracula" => Some(Self::dracula()),
            "solarized-dark" => Some(Self::solarized_dark()),
            "monochrome" => Some(Self::monochrome()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_name_resolves_all_built_ins() {
        for name in THEME_NAMES {
            assert!(
                Theme::from_name(name).is_some(),
                "expected theme '{}' to resolve",
                name
            );
        }
    }

    #[test]
    fn from_name_is_case_insensitive_and_underscore_tolerant() {
        assert!(Theme::from_name("Dracula").is_some());
        assert!(Theme::from_name("SOLARIZED-DARK").is_some());
        assert!(Theme::from_name("solarized_dark").is_some());
    }

    #[test]
    fn from_name_unknown_returns_none() {
        assert!(Theme::from_name("nope").is_none());
        assert!(Theme::from_name("").is_none());
    }

    #[test]
    fn themes_are_distinct() {
        let d = Theme::default_theme();
        let dr = Theme::dracula();
        let sd = Theme::solarized_dark();
        let mc = Theme::monochrome();

        assert_ne!(d.border, dr.border);
        assert_ne!(d.border, sd.border);
        assert_ne!(d.border, mc.border);
        assert_ne!(dr.accent, sd.accent);
        assert_ne!(dr.accent, mc.accent);
    }

    #[test]
    fn monochrome_uses_no_rgb_colors() {
        let mc = Theme::monochrome();
        for s in [
            mc.border,
            mc.header,
            mc.title,
            mc.normal,
            mc.label,
            mc.muted,
            mc.selection,
            mc.accent,
            mc.link,
            mc.error,
        ] {
            if let Some(Color::Rgb(..)) = s.fg {
                panic!("monochrome theme contains an RGB foreground: {:?}", s);
            }
            if let Some(Color::Rgb(..)) = s.bg {
                panic!("monochrome theme contains an RGB background: {:?}", s);
            }
        }
    }

    #[test]
    fn default_trait_matches_default_theme() {
        let a: Theme = Default::default();
        let b = Theme::default_theme();
        assert_eq!(a.border, b.border);
        assert_eq!(a.accent, b.accent);
    }
}
