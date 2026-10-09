//! The foreground terminal as Desktop's status line: the account in use, the
//! pool's usage, the last message, and the picker's table to switch from.

use std::fs::File;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{self, ClearType};
use crossterm::{cursor, execute, queue};
use tokio::sync::{Notify, mpsc};

use crate::client::{self, CatalogueEntry};
use crate::data_plane::intent::{Intent, encode_token, parse_token};
use crate::picker::render::{self, Charset, Paint, sanitize};
use crate::picker::{self, Section};
use crate::provider::Provider;

use super::transport::Adapter;

/// The pool is read this often, and soon after a message or a switch.
const REFRESH: Duration = Duration::from_secs(30);
/// The least time between two reads.
const SETTLE: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the frame is checked for changes and the keys are read.
const TICK: Duration = Duration::from_millis(250);
const NAME_WIDTH: usize = 48;

/// Where the adapter reports what it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Quiet,
    /// One line per request on standard error.
    Log,
    Monitor,
}

impl Output {
    /// The monitor needs standard error on a terminal that raw mode works on.
    pub fn new(quiet: bool, log: bool) -> Self {
        if quiet {
            Self::Quiet
        } else if log || !std::io::stderr().is_terminal() || !raw() {
            Self::Log
        } else {
            Self::Monitor
        }
    }
}

fn raw() -> bool {
    picker::tty::open().is_ok()
        && terminal::enable_raw_mode().is_ok()
        && terminal::disable_raw_mode().is_ok()
}

/// What the adapter saw and the pool last said.
#[derive(Default)]
pub struct Monitor {
    state: Mutex<State>,
    /// A finished message or a switch: the pool's answer may have moved.
    changed: Notify,
}

#[derive(Default)]
struct State {
    last: Option<Last>,
    messages: u64,
    failed: u64,
    /// The last message's session, to ask which account served it.
    session: Option<String>,
    /// The pool's Anthropic accounts, once read.
    accounts: Option<Vec<CatalogueEntry>>,
    serving: Option<String>,
    problem: Option<String>,
    switch_failure: Option<String>,
}

struct Last {
    operation: &'static str,
    status: u16,
    /// `None` while the answer streams.
    elapsed: Option<Duration>,
    completion: &'static str,
    at: Instant,
}

impl Monitor {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("monitor state")
    }

    /// A message or startup check answered; a message's success streams on.
    pub fn answered(&self, operation: &'static str, status: u16, elapsed: Duration) {
        let mut state = self.state();
        let message = operation == "inference";
        if message {
            state.messages += 1;
            state.failed += u64::from(status >= 400);
        }
        state.last = Some(Last {
            operation,
            status,
            elapsed: (!message || status >= 400).then_some(elapsed),
            completion: "complete",
            at: Instant::now(),
        });
    }

    pub fn session(&self, session: Option<String>) {
        self.state().session = session;
    }

    /// A message's answer ended; a cancelled one is Desktop's choice, not a failure.
    pub fn finished(&self, status: u16, completion: &'static str, elapsed: Duration) {
        {
            let mut state = self.state();
            state.failed += u64::from(completion == "failed" && status < 400);
            state.last = Some(Last {
                operation: "inference",
                status,
                elapsed: Some(elapsed),
                completion,
                at: Instant::now(),
            });
        }
        self.changed.notify_one();
    }

    pub fn switched(&self) {
        self.changed.notify_one();
    }
}

/// Reads the pool now, then every 30 s, or 2 s after a message or switch.
pub async fn refresh(adapter: Arc<Adapter>) {
    loop {
        let read = read(&adapter).await;
        {
            let mut state = adapter.monitor.state();
            match read {
                Ok((accounts, serving)) => {
                    state.accounts = Some(accounts);
                    state.serving = serving.or(state.serving.take());
                    state.problem = None;
                }
                Err(why) => state.problem = Some(why),
            }
        }
        tokio::time::sleep(SETTLE).await;
        tokio::select! {
            _ = tokio::time::sleep(REFRESH - SETTLE) => {}
            _ = adapter.monitor.changed.notified() => {}
        }
    }
}

/// The accounts, and in automatic mode the last message's serving account.
async fn read(adapter: &Adapter) -> Result<(Vec<CatalogueEntry>, Option<String>), String> {
    let installation = &adapter.installation;
    let secret = client::read_secret(installation).map_err(|(_, why)| why)?;
    let mut accounts = client::catalogue(installation, &secret, READ_TIMEOUT)
        .await
        .map_err(|(_, why)| why)?;
    accounts.retain(|account| account.provider == Provider::Anthropic);
    let session = adapter.monitor.state().session.clone();
    let serving = match session {
        Some(session) if adapter.selector().is_none() => {
            // The status line's read: it never rewrites the enrollment under a running adapter.
            client::statusline_snapshot(installation, &secret, Some(&session), READ_TIMEOUT)
                .await
                .ok()
                .and_then(|body| {
                    body["session"]["serving_account_display_name"]
                        .as_str()
                        .map(str::to_owned)
                })
        }
        _ => None,
    };
    Ok((accounts, serving))
}

/// Whether the alternate screen is up; whoever takes it down restores the terminal.
static SHOWN: AtomicBool = AtomicBool::new(false);

fn restore() {
    if SHOWN.swap(false, Ordering::SeqCst) {
        let _ = terminal::disable_raw_mode();
        if let Ok(mut tty) = picker::tty::open() {
            let _ = execute!(tty.output, cursor::Show, terminal::LeaveAlternateScreen);
        }
    }
}

/// Restores the terminal on every exit of the drawing thread, panics included.
struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        restore();
    }
}

/// The monitor on the terminal's alternate screen, drawn by its own thread.
pub struct Screen {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl Screen {
    /// `q` and Ctrl-C send on `quit`.
    pub fn start(adapter: Arc<Adapter>, quit: mpsc::UnboundedSender<()>) -> Result<Self, String> {
        let mut tty = picker::tty::open().map_err(|e| e.to_string())?;
        terminal::enable_raw_mode().map_err(|e| e.to_string())?;
        SHOWN.store(true, Ordering::SeqCst);
        if let Err(e) = execute!(tty.output, terminal::EnterAlternateScreen, cursor::Hide) {
            restore();
            return Err(e.to_string());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let thread = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                let _restore = Restore;
                run(tty.output, &adapter, &stop, &quit);
            }
        });
        Ok(Self { stop, thread })
    }

    /// Stops drawing and restores the terminal.
    pub async fn close(self) {
        self.stop.store(true, Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_secs(1);
        while !self.thread.is_finished() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        restore();
    }
}

fn run(mut out: File, adapter: &Adapter, stop: &AtomicBool, quit: &mpsc::UnboundedSender<()>) {
    // The handle the marker is on; `None` is the automatic row.
    let mut cursor = active(adapter);
    let mut drawn = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let frame = frame(adapter, cursor.as_deref());
        if frame != drawn {
            if draw(&mut out, &frame).is_err() {
                break;
            }
            drawn = frame;
        }
        match event::poll(TICK) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => break,
        }
        let key = match event::read() {
            Ok(Event::Key(key)) if key.kind != KeyEventKind::Release => key,
            Ok(Event::Resize(..)) => {
                drawn.clear();
                continue;
            }
            Ok(_) => continue,
            Err(_) => break,
        };
        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
            (KeyCode::Up | KeyCode::Char('k'), _) => cursor = moved(adapter, cursor, false),
            (KeyCode::Down | KeyCode::Char('j'), _) => cursor = moved(adapter, cursor, true),
            (KeyCode::Esc, _) => cursor = active(adapter),
            (KeyCode::Enter, _) => choose(adapter, cursor.as_deref()),
            _ => {}
        }
    }
    // A terminal that can no longer be drawn on or read from cannot stop the adapter either.
    if !stop.load(Ordering::Relaxed) {
        let _ = quit.send(());
    }
}

fn draw(out: &mut File, frame: &[String]) -> std::io::Result<()> {
    queue!(out, cursor::MoveTo(0, 0))?;
    for line in frame {
        write!(out, "{line}")?;
        queue!(out, terminal::Clear(ClearType::UntilNewLine))?;
        write!(out, "\r\n")?;
    }
    queue!(out, terminal::Clear(ClearType::FromCursorDown))?;
    out.flush()
}

fn section(accounts: &[CatalogueEntry]) -> Section {
    Section {
        heading: None,
        rows: accounts.iter().map(picker::Row::from).collect(),
    }
}

/// The pinned account's handle; `None` is automatic.
fn active(adapter: &Adapter) -> Option<String> {
    adapter.selector().as_deref().and_then(pinned)
}

/// The marker one row down or up; it stays until the pool has been read.
fn moved(adapter: &Adapter, cursor: Option<String>, down: bool) -> Option<String> {
    match &adapter.monitor.state().accounts {
        Some(accounts) => picker::step(&section(accounts), cursor.as_deref(), down),
        None => cursor,
    }
}

/// Switches to the marker's row, unless it is in use or cannot be chosen
/// in the pool's last read.
fn choose(adapter: &Adapter, cursor: Option<&str>) {
    let choosable = adapter
        .monitor
        .state()
        .accounts
        .as_ref()
        .is_some_and(|accounts| picker::choosable(&section(accounts), cursor));
    if !choosable || cursor == active(adapter).as_deref() {
        return;
    }
    let outcome = adapter.switch(cursor.map(|handle| encode_token(true, handle)));
    adapter.monitor.state().switch_failure = outcome.err();
}

fn frame(adapter: &Adapter, cursor: Option<&str>) -> Vec<String> {
    let paint = Paint {
        colour: std::env::var_os("NO_COLOR").is_none(),
        charset: render::charset(),
    };
    let pinned = active(adapter);
    let state = adapter.monitor.state();
    let listing = state
        .accounts
        .as_ref()
        .map(|accounts| picker::listing(&section(accounts), pinned.as_deref(), cursor));
    lines(
        &adapter.integration.origin,
        pinned.as_deref(),
        &state,
        listing,
        &paint,
        Instant::now(),
    )
}

/// The pinned account's handle.
fn pinned(selector: &str) -> Option<String> {
    match parse_token(selector) {
        Ok(Intent::Pin(handle)) => Some(handle),
        _ => None,
    }
}

fn lines(
    origin: &str,
    pinned: Option<&str>,
    state: &State,
    listing: Option<Vec<String>>,
    paint: &Paint,
    now: Instant,
) -> Vec<String> {
    let mut lines = vec![
        paint.bold(&format!("Jaynshare Desktop Gateway at {origin}")),
        paint.dim("Keep this terminal open; closing it disconnects Desktop."),
        String::new(),
        format!(
            "{}{}",
            paint.label("account"),
            account(pinned, state, paint.charset)
        ),
        String::new(),
    ];
    match listing {
        Some(listing) => lines.extend(listing),
        None => lines.push(paint.dim("  reading the pool")),
    }
    lines.push(String::new());
    for (label, problem) in [("pool", &state.problem), ("switch", &state.switch_failure)] {
        if let Some(problem) = problem {
            lines.push(format!("{}{}", paint.label(label), paint.red(problem)));
        }
    }
    lines.extend([
        format!("{}{}", paint.label("last"), last(state.last.as_ref(), now)),
        format!(
            "{}{} since start, {} failed",
            paint.label("messages"),
            state.messages,
            state.failed
        ),
        String::new(),
        paint.dim(match paint.charset {
            Charset::Unicode => "↑/↓ move · enter switch · q quit",
            Charset::Ascii => "up/down move - enter switch - q quit",
        }),
    ]);
    lines
}

fn account(pinned: Option<&str>, state: &State, charset: Charset) -> String {
    let Some(handle) = pinned else {
        return match &state.serving {
            Some(name) => format!(
                "automatic, last served by {}",
                sanitize(name, NAME_WIDTH, charset)
            ),
            None => "automatic (server decides)".into(),
        };
    };
    let Some(accounts) = &state.accounts else {
        return "pinned".into();
    };
    match accounts.iter().find(|account| account.handle == handle) {
        Some(account) => format!(
            "{} (pinned)",
            sanitize(&account.display_name, NAME_WIDTH, charset)
        ),
        None => "pinned to an account no longer in the pool".into(),
    }
}

fn last(last: Option<&Last>, now: Instant) -> String {
    let Some(last) = last else {
        return "no message yet".into();
    };
    let what = match last.operation {
        "inference" => "message",
        "startup" => "startup check",
        other => other,
    };
    let Some(elapsed) = last.elapsed else {
        return format!("{what} {}, streaming", last.status);
    };
    let completion = match last.completion {
        "complete" => String::new(),
        other => format!(" {other}"),
    };
    format!(
        "{what} {}{completion}, {}, {}",
        last.status,
        duration(elapsed),
        ago(now.saturating_duration_since(last.at))
    )
}

fn duration(elapsed: Duration) -> String {
    if elapsed < Duration::from_secs(1) {
        format!("{} ms", elapsed.as_millis())
    } else {
        format!("{:.1} s", elapsed.as_secs_f64())
    }
}

fn ago(elapsed: Duration) -> String {
    match elapsed.as_secs() {
        0 => "just now".into(),
        s if s < 60 => format!("{s} s ago"),
        s if s < 3600 => format!("{} min ago", s / 60),
        s => format!("{} h ago", s / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain() -> Paint {
        Paint {
            colour: false,
            charset: Charset::Ascii,
        }
    }

    fn entry(handle: &str, name: &str) -> CatalogueEntry {
        CatalogueEntry {
            handle: handle.into(),
            display_name: name.into(),
            selectable: true,
            five_hour: Default::default(),
            weekly: Default::default(),
            provider: Provider::Anthropic,
        }
    }

    fn drawn(pinned: Option<&str>, state: &State, now: Instant) -> Vec<String> {
        let listing = state
            .accounts
            .as_ref()
            .map(|_| vec!["  <accounts>".to_string()]);
        lines(
            "http://127.0.0.1:52144",
            pinned,
            state,
            listing,
            &plain(),
            now,
        )
    }

    #[test]
    fn the_account_line_names_the_pin_or_the_last_serving_account() {
        let mut state = State::default();
        let line = |pinned, state: &State| drawn(pinned, state, Instant::now())[3].clone();
        assert_eq!(line(Some("h2"), &state), "account  pinned");
        assert_eq!(line(None, &state), "account  automatic (server decides)");
        state.accounts = Some(vec![entry("h1", "FSUB"), entry("h2", "FSUB2")]);
        assert_eq!(line(Some("h2"), &state), "account  FSUB2 (pinned)");
        assert_eq!(
            line(Some("gone"), &state),
            "account  pinned to an account no longer in the pool"
        );
        state.serving = Some("FSUB\x1b[31m".into());
        assert_eq!(
            line(None, &state),
            "account  automatic, last served by FSUB[31m"
        );
    }

    #[test]
    fn a_message_streams_then_reports_its_end_and_failures_count_once() {
        let monitor = Monitor::default();
        let started = Instant::now();
        let shown = |now| {
            let state = monitor.state();
            let frame = drawn(None, &state, now);
            (
                frame[frame.len() - 4].clone(),
                frame[frame.len() - 3].clone(),
            )
        };
        assert_eq!(
            shown(started),
            (
                "last     no message yet".into(),
                "messages 0 since start, 0 failed".into()
            )
        );
        monitor.answered("inference", 200, Duration::from_millis(80));
        assert_eq!(shown(started).0, "last     message 200, streaming");
        monitor.finished(200, "failed", Duration::from_millis(900));
        assert_eq!(shown(started).1, "messages 1 since start, 1 failed");
        monitor.answered("inference", 200, Duration::from_millis(80));
        monitor.finished(200, "cancelled", Duration::from_millis(4_120));
        assert_eq!(
            shown(Instant::now() + Duration::from_secs(75)),
            (
                "last     message 200 cancelled, 4.1 s, 1 min ago".into(),
                "messages 2 since start, 1 failed".into()
            )
        );
        monitor.answered("inference", 429, Duration::from_millis(12));
        monitor.finished(429, "complete", Duration::from_millis(15));
        assert_eq!(
            shown(Instant::now()),
            (
                "last     message 429, 15 ms, just now".into(),
                "messages 3 since start, 2 failed".into()
            )
        );
        monitor.answered("startup", 200, Duration::from_millis(4_800));
        assert_eq!(
            shown(Instant::now()),
            (
                "last     startup check 200, 4.8 s, just now".into(),
                "messages 3 since start, 2 failed".into()
            )
        );
    }

    #[test]
    fn the_frame_waits_for_the_pool_and_names_its_problems() {
        let mut state = State::default();
        let frame = drawn(None, &state, Instant::now());
        assert_eq!(
            frame[0],
            "Jaynshare Desktop Gateway at http://127.0.0.1:52144"
        );
        assert_eq!(frame[5], "  reading the pool");
        assert_eq!(
            frame.last().unwrap(),
            "up/down move - enter switch - q quit"
        );
        state.accounts = Some(Vec::new());
        state.problem = Some("the server could not be reached".into());
        state.switch_failure = Some("the account picker failed".into());
        let frame = drawn(None, &state, Instant::now());
        assert_eq!(frame[5], "  <accounts>");
        assert_eq!(frame[7], "pool     the server could not be reached");
        assert_eq!(frame[8], "switch   the account picker failed");
    }

    #[test]
    fn only_a_pin_marks_an_account() {
        let token = crate::data_plane::intent::encode_token(true, "h1");
        assert_eq!(pinned(&token).as_deref(), Some("h1"));
        let preference = crate::data_plane::intent::encode_token(false, "h1");
        assert_eq!(pinned(&preference), None);
    }
}
