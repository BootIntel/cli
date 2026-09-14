//! Fuzz the detector library's top-level `analyze()`.
//!
//! Goal: prove `analyze(&str)` never panics on arbitrary input.
//! The library processes untrusted UART bytes and must not crash on
//! any string a hostile device could emit (long lines, invalid UTF-8
//! stripped to lossy, mid-word regex boundaries, ANSI escapes, etc.).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Real UART output can contain arbitrary bytes; use lossy decode
    // like the analyzer/state.rs does.
    let s = String::from_utf8_lossy(data);
    // Cap input size to keep libfuzzer cycles fast — an analyze
    // that takes >1s on any input is a bug by itself.
    if s.len() > 1_000_000 {
        return;
    }
    let _ = bootintel_detectors::analyze(&s);
});
