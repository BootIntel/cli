//! Terminal raw-mode guard.
//!
//! Enables raw mode on construct, restores on drop. The Drop
//! implementation runs on unwinding too, so a panic in the
//! terminal loop never leaves the user's shell wedged in raw mode
//! (no local echo, no line buffering, no Ctrl-C).
//!
//! Uses crossterm's `enable_raw_mode` / `disable_raw_mode` which
//! wraps the platform-specific termios / SetConsoleMode calls.

use anyhow::{Context, Result};
use crossterm::terminal;

/// RAII guard. Holding one of these means the terminal is in raw
/// mode; dropping it restores cooked mode. Best-effort: if the
/// restore call fails on drop, we print a warning to stderr but
/// can't return an error (Drop can't be fallible in Rust).
pub struct RawModeGuard {
    // Track whether we actually entered raw mode so we don't try to
    // disable it if construction failed halfway through. Also gets
    // set to false by an explicit `restore()` call so Drop doesn't
    // double-disable.
    active: bool,
}

impl RawModeGuard {
    pub fn enter() -> Result<Self> {
        terminal::enable_raw_mode().context("enabling terminal raw mode")?;
        Ok(Self { active: true })
    }

    /// Explicit early restore. Useful when the terminal loop wants
    /// to print something in cooked mode before exiting and doesn't
    /// want to wait for Drop. Idempotent.
    pub fn restore(&mut self) {
        if self.active {
            self.active = false;
            if let Err(e) = terminal::disable_raw_mode() {
                eprintln!("[bootintel] warning: failed to restore terminal mode: {e}");
            }
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        self.restore();
    }
}
