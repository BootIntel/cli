//! Shutdown-signal handling for the interactive terminal.
//!
//! `bootintel term` / `bootintel analyze` hold two things the process
//! must not die holding: the user's terminal in raw mode, and (when
//! `--log-file` is in use) a capture the user believes they have.
//!
//! Default dispositions get both wrong. `SIGTERM` (a `kill`, a service
//! manager stopping us, a laptop suspending) and `SIGHUP` (the
//! terminal window closing, the SSH session dropping, the USB adapter's
//! tty going away) terminate the process immediately: no unwinding, no
//! `Drop`, so the raw-mode guard never restores the terminal and the
//! log file is whatever the last flush left behind.
//!
//! So we install handlers that do the only thing a signal handler may
//! safely do — set a flag — and let the terminal's main loop notice it
//! and exit through the normal path. That path drops the `RawMode`
//! guard (terminal restored) and the `LogFile` (final flush), exactly
//! as `Ctrl-A q` does.
//!
//! The loop polls on a 100 ms timeout, so the worst-case latency
//! between the signal and a clean exit is 100 ms.
//!
//! Note that `SIGINT` normally does *not* arrive here: once the
//! terminal is in raw mode, `Ctrl-C` is delivered to us as the byte
//! `0x03`, not as a signal. The handler matters for an explicit
//! `kill -INT`, and for the window between process start and raw mode
//! being entered.

use std::sync::atomic::{AtomicBool, Ordering};

/// Set by the signal handler; read by the terminal loop.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Number (as `c_int`) of the signal that asked us to stop, or 0.
/// Only used to name the signal in the goodbye line.
///
/// Gated because the only reader is the `cfg(unix)` arm of
/// `shutdown_reason` and the only writers are the `cfg(unix)` handler and
/// `reset_for_test`. A Windows release build has neither, so an
/// ungated static is dead code, and this crate denies warnings: it broke
/// `cargo build --release` on windows-latest while every other target
/// stayed green.
#[cfg(any(unix, test))]
static SHUTDOWN_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Whether a shutdown signal has been received.
pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Human-readable name of the signal that requested shutdown.
pub fn shutdown_reason() -> &'static str {
    #[cfg(unix)]
    match SHUTDOWN_SIGNAL.load(Ordering::Relaxed) {
        x if x == libc::SIGINT => "SIGINT (Ctrl-C)",
        x if x == libc::SIGTERM => "SIGTERM",
        x if x == libc::SIGHUP => "SIGHUP (terminal closed)",
        _ => "signal",
    }
    #[cfg(not(unix))]
    "signal"
}

/// Request shutdown from ordinary (non-signal) code. Exposed so tests
/// can drive the same exit path a signal would.
#[cfg(test)]
pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Clear the flag. Tests only — a process only shuts down once.
#[cfg(test)]
pub fn reset_for_test() {
    SHUTDOWN.store(false, Ordering::Relaxed);
    SHUTDOWN_SIGNAL.store(0, Ordering::Relaxed);
}

/// The handler itself. Async-signal-safe: two relaxed atomic stores
/// and nothing else. No allocation, no locking, no I/O — a `println!`
/// here could deadlock against a `print!` interrupted mid-call.
#[cfg(unix)]
extern "C" fn handle(sig: libc::c_int) {
    SHUTDOWN_SIGNAL.store(sig, Ordering::Relaxed);
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Install handlers for SIGINT / SIGTERM / SIGHUP.
///
/// Idempotent, and safe to call when not attached to a terminal.
#[cfg(unix)]
pub fn install() {
    // SAFETY: `signal(2)` with a plain extern "C" fn pointer. The
    // handler touches only atomics, so it is async-signal-safe.
    // Called once, from the terminal command's entry point.
    unsafe {
        let h = handle as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, h);
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGHUP, h);
    }
}

#[cfg(not(unix))]
pub fn install() {
    // Windows: Ctrl-C arrives through crossterm's event stream while
    // the console is in raw mode, and the terminal loop already treats
    // it as a quit request. Nothing to install.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_starts_clear_and_can_be_set() {
        reset_for_test();
        assert!(!shutdown_requested());
        request_shutdown();
        assert!(shutdown_requested());
        reset_for_test();
        assert!(!shutdown_requested());
    }

    #[cfg(unix)]
    #[test]
    fn real_signal_sets_the_flag() {
        reset_for_test();
        install();
        // Raise SIGTERM at ourselves. With the default disposition
        // this would terminate the test binary; the handler makes it
        // a flag flip.
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        assert!(
            shutdown_requested(),
            "SIGTERM did not set the shutdown flag"
        );
        assert_eq!(shutdown_reason(), "SIGTERM");
        reset_for_test();
    }
}
