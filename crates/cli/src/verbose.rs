//! Global verbose-logging state.
//!
//! `-v`/`--verbose` is a top-level clap flag (see `main.rs`). It's
//! repeatable: `-v` = INFO, `-vv` = DEBUG. Level is stored in a
//! process-wide atomic so any code path can gate on it without
//! plumbing a `verbosity: u8` argument through every function.
//!
//! Rendering is stderr with a `[v]` prefix so verbose output never
//! contaminates stdout (which carries the JSON/SARIF/JUnit output
//! that downstream tooling parses). Info lines get `[v]`; debug
//! lines get `[vv]`.
//!
//! Deliberately not `log` / `tracing`: the polish need is "show me
//! the request/response body when --api fails" — a bespoke flag +
//! two macros costs ~40 LOC and one atomic vs a full logging crate
//! + its subscriber wiring, and matches the CLI's zero-magic style.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(0);
static QUIET: AtomicBool = AtomicBool::new(false);

/// Called once from `main` after clap parses `-v` occurrences.
pub fn set_level(level: u8) {
    LEVEL.store(level, Ordering::Relaxed);
}

/// Called once from `main` for the global -q/--quiet flag.
pub fn set_quiet(q: bool) {
    QUIET.store(q, Ordering::Relaxed);
}

/// Current verbosity level (0 = off, 1 = info, 2+ = debug).
pub fn level() -> u8 {
    LEVEL.load(Ordering::Relaxed)
}

/// Whether -q/--quiet was passed. Handlers check this before
/// printing banners / status hints / progress messages. Errors
/// (via anyhow, stderr) are unaffected.
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Emit an INFO line to stderr when -v is on.
#[macro_export]
macro_rules! vinfo {
    ($($arg:tt)*) => {{
        if $crate::verbose::level() >= 1 {
            eprintln!("[v] {}", format_args!($($arg)*));
        }
    }};
}

/// Emit a DEBUG line to stderr when -vv is on.
#[macro_export]
macro_rules! vdebug {
    ($($arg:tt)*) => {{
        if $crate::verbose::level() >= 2 {
            eprintln!("[vv] {}", format_args!($($arg)*));
        }
    }};
}
