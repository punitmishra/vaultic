//! GUI color themes.
//!
//! Mirrors the API in `src/tui/theme.rs` so the same name (`default`,
//! `dracula`, `solarized-dark`, `monochrome`) produces a coherent look in
//! both the terminal and the desktop GUI. The data is different — egui
//! styles the whole `Visuals` struct rather than per-widget styles — but
//! the four palettes are intentionally derived from the same source colors.
//!
//! Each theme is applied via [`Theme::apply`], which mutates an
//! `egui::Visuals` in place. Spacing tokens are public constants used by
//! `screens.rs` to keep layout consistent across themes.

use eframe::egui::{Color32, Stroke, Visuals};

/// Built-in theme names supported by `Theme::from_name`. Same list as the
/// TUI's `THEME_NAMES`.
pub const THEME_NAMES: &[&str] = &["default", "dracula", "solarized-dark", "monochrome"];

// ============ Spacing tokens ============
//
// Layout magic numbers were scattered across screens.rs. Centralising them
// here means changing the visual rhythm in one place.

pub const SPACE_XS: f32 = 2.0;
pub const SPACE_SM: f32 = 4.0;
pub const SPACE_MD: f32 = 8.0;
pub const SPACE_LG: f32 = 12.0;
pub const SPACE_XL: f32 = 16.0;

/// Resolved styling for the GUI. Held by `VaulticGui` and passed by
/// reference to draw functions.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// Background of the whole window.
    pub bg: Color32,
    /// Subtly lifted background for cards / popups.
    pub bg_elevated: Color32,
    /// Primary text color.
    pub fg: Color32,
    /// De-emphasized text (labels, hints, footnotes).
    pub fg_muted: Color32,
    /// Stroke for borders and separators.
    pub stroke: Stroke,
    /// Accent color for primary actions / highlights.
    pub accent: Color32,
    /// Color for "good" / success states (vault unlocked, copy ok).
    pub success: Color32,
    /// Color for "warning" states (vault locked).
    pub warning: Color32,
    /// Color for "bad" states (offline, errors).
    pub error: Color32,
    /// Selection highlight in lists.
    pub selection: Color32,
    /// Whether this theme is best paired with egui's dark mode chrome.
    pub dark: bool,
}

impl Default for Theme {
    fn default() -> Self {
        Self::default_theme()
    }
}

impl Theme {
    /// Default — neutral, system-native, restrained. Pairs with egui dark.
    pub fn default_theme() -> Self {
        Self {
            bg: Color32::from_rgb(0x1B, 0x1D, 0x21),
            bg_elevated: Color32::from_rgb(0x24, 0x26, 0x2B),
            fg: Color32::from_rgb(0xE6, 0xE6, 0xEB),
            fg_muted: Color32::from_rgb(0x8A, 0x8E, 0x99),
            stroke: Stroke::new(1.0, Color32::from_rgb(0x35, 0x38, 0x40)),
            accent: Color32::from_rgb(0x6E, 0xA8, 0xFE),
            success: Color32::from_rgb(0x55, 0xC4, 0x88),
            warning: Color32::from_rgb(0xE6, 0xB0, 0x55),
            error: Color32::from_rgb(0xE0, 0x6C, 0x6C),
            selection: Color32::from_rgba_unmultiplied(0x6E, 0xA8, 0xFE, 0x33),
            dark: true,
        }
    }

    /// Dracula — vivid pinks, purples, comment-blue mutes.
    pub fn dracula() -> Self {
        Self {
            bg: Color32::from_rgb(0x28, 0x2A, 0x36),
            bg_elevated: Color32::from_rgb(0x33, 0x36, 0x44),
            fg: Color32::from_rgb(0xF8, 0xF8, 0xF2),
            fg_muted: Color32::from_rgb(0x62, 0x72, 0xA4),
            stroke: Stroke::new(1.0, Color32::from_rgb(0x44, 0x47, 0x5A)),
            accent: Color32::from_rgb(0xBD, 0x93, 0xF9),
            success: Color32::from_rgb(0x50, 0xFA, 0x7B),
            warning: Color32::from_rgb(0xF1, 0xFA, 0x8C),
            error: Color32::from_rgb(0xFF, 0x55, 0x55),
            selection: Color32::from_rgba_unmultiplied(0xFF, 0x79, 0xC6, 0x40),
            dark: true,
        }
    }

    /// Solarized Dark — restrained, low-contrast, professional.
    pub fn solarized_dark() -> Self {
        Self {
            bg: Color32::from_rgb(0x00, 0x2B, 0x36),
            bg_elevated: Color32::from_rgb(0x07, 0x36, 0x42),
            fg: Color32::from_rgb(0x93, 0xA1, 0xA1),
            fg_muted: Color32::from_rgb(0x58, 0x6E, 0x75),
            stroke: Stroke::new(1.0, Color32::from_rgb(0x07, 0x36, 0x42)),
            accent: Color32::from_rgb(0x26, 0x8B, 0xD2),
            success: Color32::from_rgb(0x85, 0x99, 0x00),
            warning: Color32::from_rgb(0xB5, 0x89, 0x00),
            error: Color32::from_rgb(0xDC, 0x32, 0x2F),
            selection: Color32::from_rgba_unmultiplied(0x26, 0x8B, 0xD2, 0x44),
            dark: true,
        }
    }

    /// Monochrome — no color. Distinctions via stroke contrast and weight.
    pub fn monochrome() -> Self {
        Self {
            bg: Color32::from_rgb(0x10, 0x10, 0x10),
            bg_elevated: Color32::from_rgb(0x1C, 0x1C, 0x1C),
            fg: Color32::from_rgb(0xE0, 0xE0, 0xE0),
            fg_muted: Color32::from_rgb(0x80, 0x80, 0x80),
            stroke: Stroke::new(1.0, Color32::from_rgb(0x40, 0x40, 0x40)),
            // Same monotone for accent/success/warning/error: differences
            // come from icons, weight, and position rather than hue.
            accent: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            success: Color32::from_rgb(0xD0, 0xD0, 0xD0),
            warning: Color32::from_rgb(0xB0, 0xB0, 0xB0),
            error: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            selection: Color32::from_rgba_unmultiplied(0xFF, 0xFF, 0xFF, 0x22),
            dark: true,
        }
    }

    /// Look up a theme by canonical name. Case-insensitive; underscore is
    /// accepted in place of dash (`solarized_dark` works).
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

    /// Apply this theme's colors to an egui [`Visuals`]. Call once on
    /// startup and again whenever the user picks a different theme.
    pub fn apply(&self, visuals: &mut Visuals) {
        if self.dark {
            *visuals = Visuals::dark();
        } else {
            *visuals = Visuals::light();
        }
        visuals.panel_fill = self.bg;
        visuals.window_fill = self.bg_elevated;
        visuals.window_stroke = self.stroke;
        visuals.faint_bg_color = self.bg_elevated;
        visuals.extreme_bg_color = self.bg;
        visuals.override_text_color = Some(self.fg);
        visuals.hyperlink_color = self.accent;
        visuals.selection.bg_fill = self.selection;
        visuals.selection.stroke = Stroke::new(1.0, self.accent);
        visuals.widgets.noninteractive.bg_stroke = self.stroke;
        visuals.widgets.inactive.bg_stroke = self.stroke;
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, self.accent);
        visuals.widgets.active.bg_stroke = Stroke::new(1.0, self.accent);
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
        assert!(Theme::from_name("not-a-theme").is_none());
        assert!(Theme::from_name("").is_none());
    }

    #[test]
    fn themes_are_distinct() {
        let d = Theme::default_theme();
        let dr = Theme::dracula();
        let sd = Theme::solarized_dark();
        let mc = Theme::monochrome();
        assert_ne!(d.bg, dr.bg);
        assert_ne!(d.bg, sd.bg);
        assert_ne!(d.bg, mc.bg);
        assert_ne!(dr.accent, sd.accent);
    }

    #[test]
    fn apply_to_visuals_does_not_panic() {
        for name in THEME_NAMES {
            let theme = Theme::from_name(name).unwrap();
            let mut v = Visuals::dark();
            theme.apply(&mut v);
        }
    }
}
