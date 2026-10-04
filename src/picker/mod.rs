//! The account picker: per section, an optional heading, an **automatic**
//! row, then the section's catalogue rows in the server's order, each a
//! display name, its five-hour and weekly utilisation, and whether it can be
//! chosen now. Two
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

/// One catalogue entry as the picker shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub handle: String,
    pub display_name: String,
    pub selectable: bool,
    pub five_hour: Option<f64>,
    pub weekly: Option<f64>,
}

/// Rows under an optional heading, after their own automatic row.
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

/// One drawn line; a choice carries its section's index.
enum Line<'a> {
    Heading(&'a str),
    Automatic(usize),
    Account(usize, &'a Row),
}

impl Line<'_> {
    /// The section and choice this line confirms: none for a heading or an
    /// unselectable row.
    fn choice(&self) -> Option<(usize, Choice)> {
        match self {
            Line::Heading(_) => None,
            Line::Automatic(section) => Some((*section, Choice::Automatic)),
            Line::Account(section, row) => row
                .selectable
                .then(|| (*section, Choice::Account(row.handle.clone()))),
        }
    }
}

fn lines(sections: &[Section]) -> Vec<Line<'_>> {
    sections
        .iter()
        .enumerate()
        .flat_map(|(index, section)| {
            section
                .heading
                .map(Line::Heading)
                .into_iter()
                .chain(std::iter::once(Line::Automatic(index)))
                .chain(
                    section
                        .rows
                        .iter()
                        .map(move |row| Line::Account(index, row)),
                )
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
