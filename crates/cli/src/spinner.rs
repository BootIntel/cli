//! Minimal TTY-aware spinner for long-running server round-trips.
//!
//! Prints a single-line braille spinner on stderr while a background
//! thread ticks it forward every 80ms. Drop the returned `Spinner`
//! to stop the animation and clear the line — RAII, so panics and
//! early returns all clean up.
//!
//! No-ops when stderr is not a TTY (piped, non-interactive CI logs).
//! Emits to stderr not stdout so `bootintel scan --api foo | jq`
//! never gets the animation frames interleaved with the JSON body.
//!
//! Deliberately no `indicatif`: this is ~50 LOC + one thread. The
//! same argument as the `verbose` module — a bespoke primitive costs
//! nothing vs pulling in a full progress-bar crate.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const TICK: Duration = Duration::from_millis(80);

pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    active: bool,
}

impl Spinner {
    /// Start a spinner with the given static label. If stderr is not
    /// a TTY (piped, dumb terminal) returns an inert handle that
    /// prints nothing — callers don't need to branch.
    pub fn start(label: &'static str) -> Self {
        if !std::io::stderr().is_terminal() {
            return Self {
                stop: Arc::new(AtomicBool::new(true)),
                handle: None,
                active: false,
            };
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let handle = thread::spawn(move || {
            let mut i = 0usize;
            let mut err = std::io::stderr().lock();
            while !stop2.load(Ordering::Relaxed) {
                // \r returns to column 0, then overwrite. Trailing
                // space nudges the cursor past the label so it
                // doesn't sit on top of a glyph while ticking.
                let _ = write!(err, "\r{} {} ", FRAMES[i % FRAMES.len()], label);
                let _ = err.flush();
                thread::sleep(TICK);
                i += 1;
            }
            // Clear the whole line with spaces, then return the
            // cursor. Guarantees no residue whether the terminal is
            // narrow or wide.
            let width = FRAMES[0].chars().count() + 1 + label.chars().count() + 2;
            let _ = write!(err, "\r{}\r", " ".repeat(width));
            let _ = err.flush();
        });
        Self {
            stop,
            handle: Some(handle),
            active: true,
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
