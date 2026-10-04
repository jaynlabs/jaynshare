//! What a picker line reads: the automatic row, after its section's heading
//! if any, and each display name with control characters removed and truncated to its
//! column, its five-hour and weekly utilisation, and whether it can be chosen
//! now. The
//! character set is ASCII on Windows and wherever the locale names
//! no UTF-8.

use super::{Line, Row};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    Unicode,
    Ascii,
}

/// The automatic row's text.
pub const AUTOMATIC: &str = "Automatic (the pool chooses)";
/// Appended to an unselectable row, and nothing more.
pub const UNAVAILABLE: &str = "(cannot be chosen now)";

/// The console's character set — ASCII on Windows, and elsewhere
/// unless the first set of `LC_ALL`, `LC_CTYPE`, `LANG` names UTF-8.
pub fn charset() -> Charset {
    if cfg!(windows) {
        return Charset::Ascii;
    }
    let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if locale.contains("utf-8") || locale.contains("utf8") {
        Charset::Unicode
    } else {
        Charset::Ascii
    }
}

/// The keyboard picker's marker on the chosen row.
pub fn marker(charset: Charset) -> &'static str {
    match charset {
        Charset::Unicode => "❯",
        Charset::Ascii => ">",
    }
}

fn ellipsis(charset: Charset) -> &'static str {
    match charset {
        Charset::Unicode => "…",
        Charset::Ascii => "...",
    }
}

/// The row's width: the terminal's columns less its number and marker, never
/// under 16.
pub fn name_width() -> usize {
    let columns = crossterm::terminal::size().map_or(80, |(c, _)| usize::from(c));
    columns.saturating_sub(8).max(16)
}

/// `name` without control characters (and, in the ASCII set, with
/// every non-ASCII character drawn as `?`), truncated to `width` characters
/// with an ellipsis.
pub fn sanitize(name: &str, width: usize, charset: Charset) -> String {
    let clean: Vec<char> = name
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| {
            if charset == Charset::Ascii && !c.is_ascii() {
                '?'
            } else {
                c
            }
        })
        .collect();
    if clean.len() <= width {
        return clean.into_iter().collect();
    }
    let tail = ellipsis(charset);
    let keep = width.saturating_sub(tail.chars().count());
    let mut out: String = clean[..keep].iter().collect();
    out.push_str(tail);
    out
}

fn percentage(value: Option<f64>) -> String {
    value.map_or_else(|| "?".to_string(), |value| format!("{:.0}%", value * 100.0))
}

pub fn rate_limits(five_hour: Option<f64>, weekly: Option<f64>) -> String {
    format!(
        "5h {} | weekly {}",
        percentage(five_hour),
        percentage(weekly)
    )
}

/// The lines' texts, without indents, markers or numbers, which the
/// pickers add.
pub(super) fn labels(lines: &[Line], width: usize, charset: Charset) -> Vec<String> {
    lines
        .iter()
        .map(|line| match (line.row, line.heading) {
            (None, None) => AUTOMATIC.to_string(),
            (None, Some(heading)) => format!("{heading} - {AUTOMATIC}"),
            (Some(row), _) => label(row, width.saturating_sub(line.indent().len()), charset),
        })
        .collect()
}

fn label(row: &Row, width: usize, charset: Charset) -> String {
    let limits = rate_limits(row.five_hour, row.weekly);
    let unavailable_width = if row.selectable {
        0
    } else {
        UNAVAILABLE.chars().count() + 1
    };
    let reserved = limits.chars().count() + unavailable_width + 3;
    let name = sanitize(
        &row.display_name,
        width.saturating_sub(reserved).max(16),
        charset,
    );
    let label = format!("{name} | {limits}");
    if row.selectable {
        label
    } else {
        format!("{label} {UNAVAILABLE}")
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Section, lines};
    use super::*;

    fn row(name: &str, selectable: bool) -> Row {
        Row {
            handle: "h".into(),
            display_name: name.into(),
            selectable,
            five_hour: Some(0.12),
            weekly: Some(0.34),
        }
    }

    #[test]
    fn control_characters_go_and_long_names_are_cut() {
        assert_eq!(
            sanitize("a\x1b[31mb\u{7}c", 20, Charset::Unicode),
            "a[31mbc"
        );
        assert_eq!(sanitize("abcdefghij", 6, Charset::Unicode), "abcde…");
        assert_eq!(sanitize("abcdefghij", 6, Charset::Ascii), "abc...");
        assert_eq!(sanitize("Zoë", 10, Charset::Ascii), "Zo?");
    }

    #[test]
    fn automatic_first_then_the_catalogue_in_order() {
        let section = Section {
            heading: None,
            rows: vec![row("A", true), row("B", false)],
        };
        let labels = labels(&lines(&[section]), 20, Charset::Ascii);
        assert_eq!(
            labels,
            [
                AUTOMATIC,
                "A | 5h 12% | weekly 34%",
                "B | 5h 12% | weekly 34% (cannot be chosen now)"
            ]
        );
    }

    #[test]
    fn each_section_s_automatic_row_carries_its_heading() {
        let sections = [
            Section {
                heading: Some("Claude Code"),
                rows: vec![row("A", true)],
            },
            Section {
                heading: Some("Codex"),
                rows: vec![row("B", true)],
            },
        ];
        let labels = labels(&lines(&sections), 20, Charset::Ascii);
        assert_eq!(
            labels,
            [
                "Claude Code - Automatic (the pool chooses)",
                "A | 5h 12% | weekly 34%",
                "Codex - Automatic (the pool chooses)",
                "B | 5h 12% | weekly 34%"
            ]
        );
    }
}
