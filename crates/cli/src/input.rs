//! Reading boot logs off disk / stdin.
//!
//! # Why this is not `read_to_string`
//!
//! A UART capture is a byte stream, not a text file, and it is
//! routinely not valid UTF-8:
//!
//!   * bytes received before the baud rate locks are framing garbage;
//!   * a parity or framing error corrupts whatever byte it lands on;
//!   * a vendor bootloader prints a binary splash or a raw memory dump;
//!   * the board resets mid-line and the UART emits a break.
//!
//! `std::fs::read_to_string` rejects the whole file for any one of
//! those, so `bootintel scan` exited 1 with "stream did not contain
//! valid UTF-8" and analyzed nothing — on captures the legacy Node
//! analyzer reads without complaint. Worse, `--log-file` writes raw
//! bytes, so `bootintel analyze --log-file cap.log` followed by
//! `bootintel scan cap.log` could fail on the tool's own output.
//!
//! So: read bytes, convert lossily, and carry on. Every invalid
//! sequence becomes U+FFFD, exactly as `String::from_utf8_lossy` would,
//! but we also count how many bytes were replaced so `-v` can say so.
//!
//! # Line numbers
//!
//! Replacement never merges or splits lines: `\n` (0x0A) and `\r`
//! (0x0D) are single-byte ASCII and can never be part of an invalid
//! UTF-8 sequence, so they survive byte-for-byte. Line numbering over
//! the converted text therefore matches the original capture.

use anyhow::{Context, Result};
use std::io::Read;
use std::path::Path;

/// A log that has been read and made safe to treat as text.
pub struct LoadedLog {
    /// The log as UTF-8, with invalid sequences replaced.
    pub text: String,
    /// How many input bytes were not valid UTF-8 and got replaced.
    pub replaced_bytes: usize,
    /// What to show a user (and put in SARIF) as the input's identity.
    /// The path as given for a file; `stdin` for a pipe.
    pub source_label: String,
}

impl LoadedLog {
    /// Emit the `-v` note about replaced bytes, if there were any.
    /// Goes to stderr like every other verbose line, so JSON/SARIF
    /// consumers on stdout are unaffected.
    pub fn report_replacements(&self) {
        if self.replaced_bytes > 0 {
            crate::vinfo!(
                "{}: {} byte(s) were not valid UTF-8 and were replaced with U+FFFD \
                 (normal for a UART capture: pre-baud-lock noise, framing errors, a binary splash)",
                self.source_label,
                self.replaced_bytes
            );
        }
    }
}

/// Read every byte of stdin, lossily decoded.
pub fn read_stdin() -> Result<LoadedLog> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .context("reading log from stdin")?;
    let (text, replaced_bytes) = from_utf8_lossy_counted(&buf);
    Ok(LoadedLog {
        text,
        replaced_bytes,
        source_label: "stdin".to_string(),
    })
}

/// Read a file's bytes, lossily decoded. Error mapping is the caller's
/// job — `scan` and `batch` want different hints.
pub fn read_file(path: &Path) -> std::io::Result<LoadedLog> {
    let bytes = std::fs::read(path)?;
    let (text, replaced_bytes) = from_utf8_lossy_counted(&bytes);
    Ok(LoadedLog {
        text,
        replaced_bytes,
        source_label: path.display().to_string(),
    })
}

/// `String::from_utf8_lossy`, but it also tells you how many bytes it
/// had to replace.
///
/// Matches `from_utf8_lossy`'s replacement policy exactly: one U+FFFD
/// per maximal invalid subsequence, per the WHATWG Encoding Standard.
/// The count is of input *bytes* dropped, not of replacement chars —
/// "6 bytes were replaced" is what a user debugging a capture wants to
/// know, and it is what distinguishes one stray byte from a megabyte of
/// binary.
pub fn from_utf8_lossy_counted(bytes: &[u8]) -> (String, usize) {
    // Fast path: the overwhelmingly common case allocates once and
    // scans once.
    if let Ok(s) = std::str::from_utf8(bytes) {
        return (s.to_string(), 0);
    }

    let mut out = String::with_capacity(bytes.len());
    let mut replaced = 0usize;
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                // Safe by construction: from_utf8 just told us this
                // prefix is valid.
                out.push_str(std::str::from_utf8(&rest[..valid_up_to]).unwrap_or(""));
                out.push('\u{FFFD}');
                match e.error_len() {
                    // A bad sequence of known length in the middle.
                    Some(len) => {
                        replaced += len;
                        rest = &rest[valid_up_to + len..];
                    }
                    // Truncated sequence at end of input — nothing
                    // follows, so we are done.
                    None => {
                        replaced += rest.len() - valid_up_to;
                        break;
                    }
                }
            }
        }
    }
    (out, replaced)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_utf8_is_unchanged_and_counts_zero() {
        let (s, n) = from_utf8_lossy_counted(b"U-Boot 2020.10\nhello\n");
        assert_eq!(s, "U-Boot 2020.10\nhello\n");
        assert_eq!(n, 0);
    }

    #[test]
    fn counts_every_invalid_byte() {
        // The exact byte sequence from the SME's report.
        let (s, n) = from_utf8_lossy_counted(b"a\xff\xfe\x80\x81\xc0\xc1b");
        assert_eq!(
            n, 6,
            "expected all 6 invalid bytes counted, got {n} ({s:?})"
        );
        assert!(s.starts_with('a') && s.ends_with('b'));
    }

    #[test]
    fn matches_std_lossy_output_exactly() {
        for case in [
            b"\xff\xfe\x80\x81\xc0\xc1".as_slice(),
            b"ok\xffmid\xc3".as_slice(),
            b"\xe2\x82".as_slice(), // truncated 3-byte sequence at EOF
            b"plain".as_slice(),
            b"\xf0\x9f\x92\xa9 emoji survives".as_slice(),
        ] {
            let (ours, _) = from_utf8_lossy_counted(case);
            assert_eq!(
                ours,
                String::from_utf8_lossy(case),
                "diverged from std on {case:?}"
            );
        }
    }

    #[test]
    fn line_structure_survives_replacement() {
        // Line numbers must stay correct: newlines can never be part
        // of an invalid UTF-8 sequence.
        let raw = b"line1\n\xff\xfe\nline3\n\x80line4\n";
        let (s, n) = from_utf8_lossy_counted(raw);
        assert_eq!(n, 3);
        assert_eq!(s.lines().count(), 4);
        assert_eq!(s.lines().next().unwrap(), "line1");
        assert_eq!(s.lines().nth(2).unwrap(), "line3");
        assert!(s.lines().nth(3).unwrap().ends_with("line4"));
    }
}
