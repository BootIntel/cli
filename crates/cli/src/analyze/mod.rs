//! Live analysis layer for `bootintel analyze <port>`.
//!
//! Extends the term loop with the streaming detector chain from
//! `bootintel-detectors`. Serial bytes flow through as before; a
//! second consumer accumulates them into a log-so-far buffer and
//! re-runs the detector chain on a pacer's schedule. New findings
//! (label + value + source not seen before) surface as `[bootintel]`
//! inline status lines interleaved with the raw serial stream.
//!
//! Four narrow modules so each piece is testable in isolation:
//!
//!   * `dedupe` — set-of-seen tuples; decides whether to emit a
//!     finding. Pure. No I/O.
//!   * `pacer` — decides when to re-run the detector chain.
//!     Debounces "every N new lines OR every 500ms." Pure.
//!   * `render` — how a Finding gets printed on a raw-mode terminal
//!     (CRLF, `[bootintel]` prefix, color if the terminal supports it).
//!     Also handles the save-to-file summary format.
//!   * `state` — shared mutable state the analyze loop owns: log-so-far
//!     buffer, dedupe set, pacer, display toggle. Exposed via a small
//!     API the term loop calls into.

pub mod dedupe;
pub mod pacer;
pub mod render;
pub mod state;
