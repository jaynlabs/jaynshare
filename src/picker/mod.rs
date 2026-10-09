//! The account picker: per section, an **automatic** row (named after the
//! section's heading, if any), then the section's catalogue rows in the
//! server's order, each a display name, its five-hour and weekly
//! utilisation, and whether it can be chosen now. Two
//! implementations: a keyboard picker when the controlling
//! terminal can be put in raw mode, a numbered prompt otherwise.
//! Both draw on the terminal, never on standard output.

/// The refusal when the picker is cancelled — shared with
/// `src/launch/intent.rs` so they cannot drift. The trailing marker is part
/// of the observable message (the acceptance test matches it verbatim).
pub const CANCELLED: &str = "the account picker was cancelled; nothing was launched. Launch without the picker with --account <reference> or --auto";

pub mod keyboard;
pub mod mode;
pub mod numbered;
pub mod render;
pub mod tty;

use crate::client::{CatalogueEntry, Window};

/// One catalogue entry as the picker shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub handle: String,
    pub display_name: String,
    pub selectable: bool,
    pub five_hour: Window,
    pub weekly: Window,
}

impl From<&CatalogueEntry> for Row {
    fn from(entry: &CatalogueEntry) -> Self {
        Self {
            handle: entry.handle.clone(),
            display_name: entry.display_name.clone(),
            selectable: entry.selectable,
            five_hour: entry.five_hour,
            weekly: entry.weekly,
        }
    }
}

/// Rows after their own automatic row; a heading names that row and
/// indents the rows under it.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    pub heading: Option<&'static str>,
    pub rows: Vec<Row>,
}

/// What the engineer chose: the automatic row, or one account by handle
/// (the handle, never the display name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Automatic,
    Account(String),
}

/// One drawn line: section `section`'s automatic row, or one of its
/// accounts.
struct Line<'a> {
    section: usize,
    heading: Option<&'a str>,
    /// `None` on the automatic row.
    row: Option<&'a Row>,
}

impl Line<'_> {
    /// The section and choice this line confirms: none for an unselectable
    /// row.
    fn choice(&self) -> Option<(usize, Choice)> {
        match self.row {
            None => Some((self.section, Choice::Automatic)),
            Some(row) => row
                .selectable
                .then(|| (self.section, Choice::Account(row.handle.clone()))),
        }
    }

    /// A blank line goes before every section's automatic row but the first.
    fn opens_section(&self) -> bool {
        self.row.is_none() && self.section > 0
    }

    /// Before the marker or number: an account sits under a headed
    /// section's automatic row.
    fn indent(&self) -> &'static str {
        if self.heading.is_some() && self.row.is_some() {
            "  "
        } else {
            ""
        }
    }
}

fn lines(sections: &[Section]) -> Vec<Line<'_>> {
    sections
        .iter()
        .enumerate()
        .flat_map(|(index, section)| {
            std::iter::once(None)
                .chain(section.rows.iter().map(Some))
                .map(move |row| Line {
                    section: index,
                    heading: section.heading,
                    row,
                })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickError {
    /// The cancel key, an interrupt or end of input.
    Cancelled,
    /// No usable terminal.
    NoTerminal,
    /// A drawing or reading failure; the terminal is restored first.
    Io(String),
}

/// The two pickers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Keyboard,
    Numbered,
}

/// The picker this launch can run — `forced` is `--picker`, which
/// wins over `JAYNSHARE_PICKER` — or `None` when there is no usable terminal.
/// `Err` is a `JAYNSHARE_PICKER` value outside its closed set, whose
/// message names the variable and the two values.
pub fn choose(forced: Option<Kind>) -> Result<Option<Kind>, String> {
    mode::choose(forced)
}

/// Show `sections` and return the engineer's choice with its section's index.
pub fn pick(sections: &[Section], kind: Kind) -> Result<(usize, Choice), PickError> {
    let lines = lines(sections);
    match kind {
        Kind::Keyboard => keyboard::pick(&lines),
        Kind::Numbered => numbered::pick(&lines),
    }
}

/// After the row in use in `listing`.
const IN_USE: &str = "in use";

/// The line of `handle`'s row; `None` is the automatic row.
fn position(lines: &[Line], handle: Option<&str>) -> Option<usize> {
    lines
        .iter()
        .position(|line| line.row.map(|row| row.handle.as_str()) == handle)
}

/// The keyboard picker's table without its title or keys, for a picker
/// that stays on screen: the marker on `cursor`'s row and `in use` after
/// `active`'s, each the automatic row when `None`.
pub fn listing(section: &Section, active: Option<&str>, cursor: Option<&str>) -> Vec<String> {
    let lines = lines(std::slice::from_ref(section));
    let table = render::Table::for_terminal(&lines, 3 + IN_USE.len());
    let marker = render::marker(table.charset());
    let mut screen = keyboard::screen(&lines, &table, marker, position(&lines, cursor));
    if let Some(at) = position(&lines, active) {
        // One section: the header, then a screen line per row.
        screen[1 + at].push_str(&table.dim(&format!(" {IN_USE}")));
    }
    screen
}

/// The row the keyboard picker's marker reaches from `from`'s, down or up,
/// skipping what cannot be chosen; from a row that is gone, it starts at the
/// automatic row.
pub fn step(section: &Section, from: Option<&str>, down: bool) -> Option<String> {
    let lines = lines(std::slice::from_ref(section));
    let by = if down { 1 } else { lines.len() - 1 };
    let at = keyboard::step(&lines, position(&lines, from).unwrap_or(0), by);
    lines[at].row.map(|row| row.handle.clone())
}

/// Whether `handle`'s row can be chosen now; the automatic row always can.
pub fn choosable(section: &Section, handle: Option<&str>) -> bool {
    handle.is_none_or(|handle| {
        section
            .rows
            .iter()
            .any(|row| row.handle == handle && row.selectable)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section() -> Section {
        let row = |handle: &str, selectable| Row {
            handle: handle.into(),
            display_name: handle.into(),
            selectable,
            five_hour: Window::default(),
            weekly: Window::default(),
        };
        Section {
            heading: None,
            rows: vec![row("a", true), row("held", false), row("b", true)],
        }
    }

    #[test]
    fn the_marker_skips_what_cannot_be_chosen_and_wraps() {
        let section = section();
        assert_eq!(step(&section, None, true).as_deref(), Some("a"));
        assert_eq!(step(&section, Some("a"), true).as_deref(), Some("b"));
        assert_eq!(step(&section, Some("b"), true), None);
        assert_eq!(step(&section, None, false).as_deref(), Some("b"));
        assert_eq!(step(&section, Some("gone"), true).as_deref(), Some("a"));
        assert!(choosable(&section, None) && choosable(&section, Some("b")));
        assert!(!choosable(&section, Some("held")) && !choosable(&section, Some("gone")));
    }

    #[test]
    fn the_listing_marks_the_cursor_and_the_row_in_use_apart() {
        // The header, then the automatic row, `a`, `held` and `b`.
        let screen = listing(&section(), Some("held"), Some("b"));
        let marker = render::marker(render::charset());
        assert!(screen[3].contains("held") && screen[3].contains(IN_USE));
        assert!(screen[4].starts_with(marker) && !screen[4].contains(IN_USE));
        for line in &screen[1..3] {
            assert!(!line.starts_with(marker) && !line.contains(IN_USE));
        }
    }
}
