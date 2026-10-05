//! What the pickers draw: under the columns' titles, per section, the
//! automatic row (after the section's heading, if any), then each account's
//! name and its five-hour and weekly bars as `status` draws them, all sized
//! to the terminal. The character set is ASCII on Windows and
//! wherever the locale names no UTF-8.

use time::OffsetDateTime;

use super::{Line, Row};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    Unicode,
    Ascii,
}

/// Appended to an unselectable row.
pub const UNAVAILABLE: &str = "unavailable";
/// `status`'s bar width, in cells; a picker's never exceeds it.
pub const BAR_WIDTH: usize = 18;
/// Narrower bars than this give way to percentages alone.
const MIN_BAR_WIDTH: usize = 6;
/// Names are cut before the bars go, down to this width.
const MIN_NAME_WIDTH: usize = 16;
const ACCOUNT: &str = "Account";
const FIVE_HOUR: &str = "5h used";
const WEEKLY: &str = "Weekly used";

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

/// One cell's colour on a `width`-cell bar's green→yellow→red gradient.
fn gradient(index: usize, width: usize) -> (u8, u8, u8) {
    let t = index as f64 / width.saturating_sub(1).max(1) as f64;
    let (from, to, p) = if t < 0.5 {
        ((35, 209, 96), (245, 185, 40), t * 2.0)
    } else {
        ((245, 185, 40), (239, 68, 68), (t - 0.5) * 2.0)
    };
    let mix = |a: u8, b: u8| (a as f64 + (b as f64 - a as f64) * p).round() as u8;
    (mix(from.0, to.0), mix(from.1, to.1), mix(from.2, to.2))
}

/// The drawing decisions for one rendering: bold, dim and the bar
/// gradient when `colour`, the same characters plain otherwise.
pub struct Paint {
    pub colour: bool,
    pub charset: Charset,
}

impl Paint {
    fn wrap(&self, code: &str, text: &str) -> String {
        if self.colour {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
    pub fn bold(&self, text: &str) -> String {
        self.wrap("1", text)
    }
    pub fn dim(&self, text: &str) -> String {
        self.wrap("2", text)
    }
    /// A diagnostic line's label, dim and padded to the value column.
    pub fn label(&self, text: &str) -> String {
        self.dim(&format!("{text:<9}"))
    }
    pub fn reverse(&self, text: &str) -> String {
        self.wrap("7", text)
    }
    pub fn gray(&self, text: &str) -> String {
        self.wrap("90", text)
    }
    pub fn green(&self, text: &str) -> String {
        self.wrap("32", text)
    }
    pub fn yellow(&self, text: &str) -> String {
        self.wrap("33", text)
    }
    pub fn red(&self, text: &str) -> String {
        self.wrap("31", text)
    }
    fn rgb(&self, (r, g, b): (u8, u8, u8), text: &str) -> String {
        if self.colour {
            format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    /// The bar's filled, empty and pace cells.
    fn cells(&self) -> (&'static str, &'static str, &'static str) {
        match self.charset {
            Charset::Unicode => ("█", "░", "┃"),
            Charset::Ascii => ("#", ".", "|"),
        }
    }

    /// The `width`-cell utilisation bar: filled to `ratio` on the
    /// gradient, `?`s when usage is unknown, with a cyan marker at `pace`.
    pub fn bar(&self, ratio: Option<f64>, pace: Option<f64>, width: usize) -> String {
        let (filled, empty, marker) = self.cells();
        let fill = (ratio.unwrap_or(0.0).clamp(0.0, 1.0) * width as f64).round() as usize;
        let at = pace.map(|pace| (pace * width.saturating_sub(1) as f64).round() as usize);
        let mut bar = String::new();
        for index in 0..width {
            if at == Some(index) {
                bar.push_str(&self.wrap("1;36", marker));
            } else if ratio.is_none() {
                bar.push_str(&self.gray("?"));
            } else if index < fill {
                bar.push_str(&self.rgb(gradient(index, width), filled));
            } else {
                bar.push_str(&self.gray(empty));
            }
        }
        format!("[{bar}]")
    }

    /// A window's cell: its bar, unless `width` is zero, then its percentage.
    pub fn usage(&self, ratio: Option<f64>, pace: Option<f64>, width: usize) -> String {
        let percentage = ratio.map_or_else(|| "?".to_owned(), |r| format!("{:.0}%", r * 100.0));
        if width == 0 {
            return format!("{percentage:>4}");
        }
        format!("{} {percentage:>4}", self.bar(ratio, pace, width))
    }

    /// What the pace marker means, under the bars.
    pub fn legend(&self) -> String {
        let marker = self.cells().2;
        self.dim(&format!("  {marker} = elapsed share of the reset period"))
    }
}

/// The elapsed share of the `name` window that resets at `reset`, while
/// that window runs.
pub fn linear_usage(name: &str, reset: Option<OffsetDateTime>, now: OffsetDateTime) -> Option<f64> {
    let period = match name {
        "session" | "five_hour" => time::Duration::hours(5),
        "weekly" => time::Duration::days(7),
        name if name.starts_with("weekly:") => time::Duration::days(7),
        _ => return None,
    };
    let remaining = reset? - now;
    (remaining > time::Duration::ZERO && remaining <= period)
        .then(|| 1.0 - remaining.as_seconds_f64() / period.as_seconds_f64())
}

/// The automatic row's text: its section's heading, or `Automatic`.
fn automatic(heading: Option<&str>) -> String {
    format!("{} (server decides)", heading.unwrap_or("Automatic"))
}

/// A window column's width: its cell, never narrower than its header.
fn column(bar: usize, header: &str) -> usize {
    cell(bar).max(header.len())
}

/// A window cell's width: the bar and its brackets, then the percentage.
fn cell(bar: usize) -> usize {
    if bar == 0 { 4 } else { bar + 7 }
}

/// The columns one drawing shares, and how it paints them.
pub(super) struct Table {
    name: usize,
    bar: usize,
    room: usize,
    paint: Paint,
    now: OffsetDateTime,
}

impl Table {
    /// For this terminal, after a `margin`-wide marker or number.
    pub(super) fn for_terminal(lines: &[Line], margin: usize) -> Self {
        let columns = crossterm::terminal::size()
            .ok()
            .filter(|&(columns, _)| columns > 0)
            .map_or(80, |(columns, _)| usize::from(columns));
        let paint = Paint {
            colour: std::env::var_os("NO_COLOR").is_none(),
            charset: charset(),
        };
        Self::new(lines, columns.saturating_sub(margin + 1), paint)
    }

    /// The widest names and bars that keep every line within `room`: bars
    /// narrow first, then names are cut, then bars give way to percentages.
    /// An automatic row has no bars, so its text may run over their columns.
    fn new(lines: &[Line], room: usize, paint: Paint) -> Self {
        let widest = lines
            .iter()
            .filter_map(|line| {
                let name = sanitize(&line.row?.display_name, usize::MAX, paint.charset);
                Some(line.indent().len() + name.chars().count())
            })
            .fold(ACCOUNT.len(), usize::max);
        let unavailable = lines
            .iter()
            .any(|line| line.row.is_some_and(|row| !row.selectable));
        let suffix = if unavailable {
            UNAVAILABLE.len() + 1
        } else {
            0
        };
        let rest = |bar| 2 + column(bar, FIVE_HOUR) + 2 + column(bar, WEEKLY) + suffix;
        let fits = |name: usize, bar| name + rest(bar) <= room;
        let bar = (MIN_BAR_WIDTH..=BAR_WIDTH)
            .rev()
            .find(|&bar| fits(widest, bar))
            .or_else(|| fits(MIN_NAME_WIDTH, MIN_BAR_WIDTH).then_some(MIN_BAR_WIDTH))
            .unwrap_or(0);
        Self {
            name: widest.min(room.saturating_sub(rest(bar)).max(MIN_NAME_WIDTH)),
            bar,
            room,
            paint,
            now: OffsetDateTime::now_utc(),
        }
    }

    pub(super) fn charset(&self) -> Charset {
        self.paint.charset
    }

    /// The columns' titles, after a blank marker or number.
    pub(super) fn header(&self) -> String {
        self.paint.bold(&format!(
            "{ACCOUNT:<name$}  {FIVE_HOUR:<five$}  {WEEKLY}",
            name = self.name,
            five = column(self.bar, FIVE_HOUR)
        ))
    }

    /// `line`'s text after its indent and marker or number; `current`
    /// reverses its name.
    pub(super) fn line(&self, line: &Line, current: bool) -> String {
        let width = self.name - line.indent().len();
        let cell = |text: &str, cut: usize| {
            let cell = format!("{:<width$}", sanitize(text, cut, self.paint.charset));
            if current {
                self.paint.reverse(&cell)
            } else {
                cell
            }
        };
        let name = |text: &str| cell(text, width);
        match line.row {
            None => self.paint.bold(&cell(
                &automatic(line.heading),
                self.room.saturating_sub(line.indent().len()),
            )),
            Some(row) if row.selectable => {
                format!(
                    "{}  {}",
                    name(&row.display_name),
                    self.windows(row, &self.paint)
                )
            }
            Some(row) => {
                let plain = Paint {
                    colour: false,
                    charset: self.paint.charset,
                };
                self.paint.dim(&format!(
                    "{}  {} {UNAVAILABLE}",
                    name(&row.display_name),
                    self.windows(row, &plain)
                ))
            }
        }
    }

    /// The row's five-hour and weekly cells, padded to their columns.
    fn windows(&self, row: &Row, paint: &Paint) -> String {
        let usage = |name, window: crate::client::Window| {
            let pace = linear_usage(name, window.reset, self.now);
            paint.usage(window.used, pace, self.bar)
        };
        let gap = column(self.bar, FIVE_HOUR) - cell(self.bar);
        format!(
            "{}{}  {}{}",
            usage("five_hour", row.five_hour),
            " ".repeat(gap),
            usage("weekly", row.weekly),
            " ".repeat(column(self.bar, WEEKLY) - cell(self.bar)),
        )
    }

    /// The pace legend, under bars.
    pub(super) fn legend(&self) -> Option<String> {
        (self.bar > 0).then(|| self.paint.legend())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Section, lines};
    use super::*;
    use crate::client::Window;

    fn row(name: &str, selectable: bool) -> Row {
        let window = |used| Window {
            used: Some(used),
            reset: None,
        };
        Row {
            handle: "h".into(),
            display_name: name.into(),
            selectable,
            five_hour: window(0.12),
            weekly: window(0.34),
        }
    }

    fn plain() -> Paint {
        Paint {
            colour: false,
            charset: Charset::Ascii,
        }
    }

    fn drawn(sections: &[Section], room: usize) -> Vec<String> {
        let lines = lines(sections);
        let table = Table::new(&lines, room, plain());
        std::iter::once(table.header())
            .chain(
                lines
                    .iter()
                    .map(|line| format!("{}{}", line.indent(), table.line(line, false))),
            )
            .map(|text| text.trim_end().to_owned())
            .chain(table.legend())
            .collect()
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
    fn each_section_is_its_automatic_row_over_its_accounts() {
        let sections = [
            Section {
                heading: Some("Claude Code"),
                rows: vec![row("A", true)],
            },
            Section {
                heading: Some("Codex"),
                rows: vec![row("B", false)],
            },
        ];
        assert_eq!(
            drawn(&sections, 80),
            [
                "Account  5h used                    Weekly used",
                "Claude Code (server decides)",
                "  A      [##................]  12%  [######............]  34%",
                "Codex (server decides)",
                "  B      [##................]  12%  [######............]  34% unavailable",
                "  | = elapsed share of the reset period",
            ]
        );
        let unheaded = [Section {
            heading: None,
            rows: vec![row("A", true)],
        }];
        assert_eq!(drawn(&unheaded, 80)[1], "Automatic (server decides)");
    }

    #[test]
    fn a_narrow_terminal_narrows_the_bars_then_cuts_names_then_drops_the_bars() {
        let account = |room| {
            let sections = [Section {
                heading: None,
                rows: vec![row(&"A".repeat(40), true)],
            }];
            let lines = drawn(&sections, room);
            assert!(lines.iter().all(|line| line.chars().count() <= room));
            lines[2].clone()
        };
        let name = |kept| format!("{}...", "A".repeat(kept));
        assert_eq!(
            account(120),
            format!(
                "{}  [##................]  12%  [######............]  34%",
                "A".repeat(40)
            )
        );
        assert_eq!(
            account(64),
            format!("{}  [#.....]  12%  [##....]  34%", name(31))
        );
        assert_eq!(account(40), format!("{}   12%      34%", name(15)));
    }

    #[test]
    fn linear_pace_follows_each_reset_period() {
        let now = time::macros::datetime!(2026-10-05 12:00 UTC);
        for (name, period) in [
            ("session", time::Duration::hours(5)),
            ("five_hour", time::Duration::hours(5)),
            ("weekly", time::Duration::days(7)),
            ("weekly:sonnet", time::Duration::days(7)),
        ] {
            let pace = |at| linear_usage(name, Some(at), now);
            assert_eq!(pace(now + period), Some(0.0));
            assert_eq!(pace(now + period / 2), Some(0.5));
            assert_eq!(pace(now + period * 3 / 4), Some(0.25));
            let last_second = pace(now + time::Duration::seconds(1)).unwrap();
            assert!((0.99..1.0).contains(&last_second));
            for at in [now - period, now, now + period + time::Duration::seconds(1)] {
                assert_eq!(pace(at), None);
            }
            assert_eq!(linear_usage(name, None, now), None);
        }
        assert_eq!(
            linear_usage("tokens", Some(now + time::Duration::hours(1)), now),
            None
        );

        let paint = Paint {
            colour: false,
            charset: Charset::Unicode,
        };
        assert_eq!(
            paint.bar(Some(0.25), Some(0.5), BAR_WIDTH),
            "[█████░░░░┃░░░░░░░░]"
        );
        assert_eq!(
            paint.bar(Some(0.25), None, BAR_WIDTH),
            "[█████░░░░░░░░░░░░░]"
        );
        assert_eq!(paint.bar(None, None, BAR_WIDTH), "[??????????????????]");
        for (pace, position) in [(0.0, 1), (0.5, 10), (1.0, 18)] {
            let bar = paint.bar(Some(0.25), Some(pace), BAR_WIDTH);
            assert_eq!(bar.chars().count(), BAR_WIDTH + 2);
            assert_eq!(
                bar.chars().position(|character| character == '┃'),
                Some(position)
            );
        }
    }
}
