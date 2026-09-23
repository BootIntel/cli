//! Interactive UART terminal (`bootintel term <port>`) support.
//!
//! Design breaks down into four narrowly-scoped modules so each
//! piece is testable in isolation:
//!
//!   * `hotkey` — Ctrl-A state machine + Action enum. Pure. No I/O.
//!     Unit-testable without any terminal or serial.
//!   * `raw_mode` — RAII guard that enables terminal raw mode on
//!     construct and restores it on drop. Handles the panic path too
//!     (via Drop) so a crash never leaves the user's shell wedged in
//!     raw mode.
//!   * `logfile` — thin BufWriter wrapper for `--log-file`. Flushes on
//!     every write (so the capture survives Ctrl-C / an unplugged
//!     adapter and is tailable live); ignores write errors on the
//!     second try so a full disk doesn't crash the terminal.
//!   * `signals` — SIGINT/SIGTERM/SIGHUP handlers that ask the `run`
//!     loop to exit through its normal path, so raw mode is restored
//!     and the log file is flushed instead of the process dying where
//!     it stands.
//!   * `run` — the main terminal loop: two background threads (serial
//!     reader, keyboard reader) both send into one std::sync::mpsc
//!     channel that the main thread drains. Fully synchronous — no
//!     async runtime.

pub mod hotkey;
pub mod logfile;
pub mod macros;
pub mod newline;
pub mod raw_mode;
pub mod run;
pub mod signals;
