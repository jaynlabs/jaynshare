//! The numbered picker — numbered rows, the first automatic row is 1, one
//! line read from the controlling terminal per attempt. An unselectable or
//! out-of-range entry is refused with a message and the prompt repeats; the
//! cancel word or end of input cancels, and a closed input never selects.

use super::{CANCELLED, Choice, Line, PickError};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

fn io(why: std::io::Error) -> PickError {
    PickError::Io(why.to_string())
}

/// While the numbered prompt waits, SIGINT/Ctrl-C kills the process
/// (exit 130) instead of cancelling. A watcher thread installs the signal
/// listener *before* the prompt is drawn ("armed") and, on the signal, ends
/// the launch like the cancel key: the cancelled message on standard error
/// and exit 15. `pick` runs inside the launcher's runtime, so the watcher
/// must own its own runtime on another thread. Every return path disarms it
/// by sending "stop" through a guard's `Drop`; the thread then ends itself.
struct Disarm {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Disarm {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

fn spawn_interrupt_watcher(armed: std::sync::mpsc::Sender<()>) -> Disarm {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            #[cfg(unix)]
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .expect("SIGINT listener");
            #[cfg(windows)]
            let mut interrupt = tokio::signal::windows::ctrl_c().expect("Ctrl-C listener");
            let _ = armed.send(());
            #[cfg(unix)]
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = stop_rx => return,
            }
            #[cfg(windows)]
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = stop_rx => return,
            }
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr);
            let _ = writeln!(stderr, "cli_picker_cancelled: {CANCELLED}");
            std::process::exit(15);
        });
    });
    Disarm {
        stop: Some(stop_tx),
    }
}

/// The numbered-list picker.
pub(super) fn pick(lines: &[Line]) -> Result<(usize, Choice), PickError> {
    let (armed_tx, armed_rx) = std::sync::mpsc::channel();
    let _disarm = spawn_interrupt_watcher(armed_tx);
    let terminal = super::tty::open().map_err(|_| PickError::NoTerminal)?;
    let mut input = BufReader::new(terminal.input);
    let mut output = terminal.output;
    let charset = super::render::charset();
    let width = super::render::name_width();
    let labels = super::render::labels(lines, width, charset);
    let last = lines.len();
    let prompt = format!("Enter a number (1-{last}), or q to cancel: ");

    let prompt_once = |output: &mut File| -> Result<(), PickError> {
        write!(output, "{prompt}").map_err(io)?;
        output.flush().map_err(io)
    };

    // The listener is installed before anything is drawn, so an
    // early Ctrl-C cannot slip past.
    armed_rx
        .recv()
        .map_err(|_| PickError::Io("the interrupt watcher ended".into()))?;

    writeln!(output, "Choose the account for this session:").map_err(io)?;
    for (n, (line, label)) in lines.iter().zip(&labels).enumerate() {
        writeln!(output, "  {}{}) {label}", line.indent(), n + 1).map_err(io)?;
    }
    prompt_once(&mut output)?;

    let mut line = String::new();
    loop {
        line.clear();
        let read = input.read_line(&mut line).map_err(io)?;
        if read == 0 {
            return Err(PickError::Cancelled); // End of input never selects
        }
        let answer = line.trim();
        if answer.eq_ignore_ascii_case("q") || answer.eq_ignore_ascii_case("quit") {
            return Err(PickError::Cancelled);
        }
        if let Some(line) = answer
            .parse::<usize>()
            .ok()
            .filter(|&n| (1..=last).contains(&n))
            .map(|n| &lines[n - 1])
        {
            if let Some(choice) = line.choice() {
                return Ok(choice);
            }
            // Only an account row can be unselectable.
            if let Some(row) = line.row {
                let name = super::render::sanitize(&row.display_name, width, charset);
                writeln!(output, "{name} cannot be chosen now; choose another.").map_err(io)?;
            }
            prompt_once(&mut output)?;
            continue;
        }
        writeln!(output, "Enter a number from 1 to {last}, or q to cancel.").map_err(io)?;
        prompt_once(&mut output)?;
    }
}
