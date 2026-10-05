//! The keyboard picker — a moving marker that skips what cannot be chosen,
//! up/down wrap at both ends, the cancel key and Ctrl-C (a byte in raw mode) cancel. Drawn inline on the controlling
//! terminal (`/dev/tty` where there is one), raw mode and the cursor
//! restored on every exit path by a guard's `Drop`.

use super::render::Table;
use super::{Choice, Line, PickError};
use std::fs::File;
use std::io::Write;

use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, read};
use crossterm::{cursor, execute, queue, style, terminal};

/// Restores raw mode and the cursor when dropped — every return,
/// `?` and panic. The panic and drawing-error paths share this one guard.
struct Restore<'a>(&'a mut File);

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(self.0, cursor::Show, style::Print("\r\n"),);
    }
}

fn io(why: std::io::Error) -> PickError {
    PickError::Io(why.to_string())
}

/// The arrow-key picker; `j` and `k` move like the arrows.
pub(super) fn pick(lines: &[Line]) -> Result<(usize, Choice), PickError> {
    let mut terminal = super::tty::open().map_err(|_| PickError::NoTerminal)?;
    let table = Table::for_terminal(lines, 2);
    let marker = super::render::marker(table.charset());

    terminal::enable_raw_mode().map_err(io)?;
    queue!(terminal.output, cursor::Hide).map_err(io)?;
    let restore = Restore(&mut terminal.output);

    let mut current = step(lines, lines.len() - 1, 1);
    queue!(
        restore.0,
        terminal::Clear(terminal::ClearType::FromCursorDown)
    )
    .map_err(io)?;
    let mut text =
        String::from("Choose the account for this session (up/down or j/k, Enter; Esc cancels):");
    for row in screen(lines, &table, marker, current) {
        text.push_str("\r\n\r");
        text.push_str(&row);
    }
    text.push_str("\r\n");
    write!(restore.0, "{text}").map_err(io)?;
    restore.0.flush().map_err(io)?;

    loop {
        let event = read().map_err(io)?;
        let Event::Key(key) = event else { continue };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        let by = match (key.code, key.modifiers) {
            (KeyCode::Up, _) | (KeyCode::Char('k'), _) => lines.len() - 1,
            (KeyCode::Down, _) | (KeyCode::Char('j'), _) => 1,
            (KeyCode::Enter, _) => {
                return Ok(lines[current].choice().expect("the marker is on a choice"));
            }
            (KeyCode::Esc, _) | (KeyCode::Char('q'), _) => return Err(PickError::Cancelled),
            (KeyCode::Char('c'), KeyModifiers::CONTROL)
            | (KeyCode::Char('d'), KeyModifiers::CONTROL) => return Err(PickError::Cancelled),
            _ => continue,
        };
        current = step(lines, current, by);
        redraw(restore.0, &screen(lines, &table, marker, current))?;
    }
}

/// The next line that can be chosen, `by` lines on from `from`, wrapping.
fn step(lines: &[Line], from: usize, by: usize) -> usize {
    let mut at = from;
    loop {
        at = (at + by) % lines.len();
        if lines[at].choice().is_some() {
            return at;
        }
    }
}

/// The header, every line indented with the marker on `current`'s, then
/// the legend.
fn screen(lines: &[Line], table: &Table, marker: &str, current: usize) -> Vec<String> {
    let rows = lines.iter().enumerate().map(|(i, line)| {
        let marker = if i == current { marker } else { " " };
        format!(
            "{}{marker} {}",
            line.indent(),
            table.line(line, i == current)
        )
    });
    std::iter::once(format!("  {}", table.header()))
        .chain(rows)
        .chain(table.legend())
        .collect()
}

/// Rewrite the lines in place after a move.
fn redraw(out: &mut File, screen: &[String]) -> Result<(), PickError> {
    queue!(out, cursor::MoveUp(screen.len() as u16)).map_err(io)?;
    for row in screen {
        queue!(out, terminal::Clear(terminal::ClearType::CurrentLine)).map_err(io)?;
        write!(out, "{row}\r\n").map_err(io)?;
    }
    out.flush().map_err(io)
}
