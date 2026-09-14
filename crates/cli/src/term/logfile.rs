//! Thin BufWriter wrapper for `--log-file`.
//!
//! Writes every raw byte the serial port emits to a file. Flushes
//! on drop. Ignores write errors on the second attempt so a full
//! disk doesn't crash the whole terminal — the terminal keeps
//! working; the log file just stops growing.

use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct LogFile {
    writer: BufWriter<File>,
    // Went into a broken state after a write failed once. Further
    // writes become no-ops. Prevents a wedged filesystem from
    // making every byte an error.
    broken: bool,
    /// Prefix every logged line with an ISO-8601 UTC timestamp. Off
    /// by default (matches minicom/picocom); opt-in for boot-trace
    /// captures where correlating byte spans with wall-clock is
    /// useful.
    timestamps: bool,
    /// Whether the next byte written is at the start of a line.
    /// Serial chunks arrive without respecting line boundaries, so
    /// we track this across calls and only prepend the timestamp
    /// when we transition from "just after \n" → "about to write a
    /// non-newline byte".
    at_line_start: bool,
}

/// Open mode for the log file. Default (`Refuse`) protects a user's
/// captured logs from being clobbered on a re-run — a three-hour boot
/// capture accidentally overwritten by `bootintel term ... --log-file
/// boot.log` on the second try is a very bad afternoon. Caller must
/// opt into destructive behavior explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFileMode {
    /// Refuse to open if the file already exists. Default.
    Refuse,
    /// Open in append mode; preserves existing content.
    Append,
    /// Overwrite (truncate) an existing file. Opt-in destructive.
    Overwrite,
}

impl LogFile {
    pub fn create(path: &Path, mode: LogFileMode) -> Result<Self> {
        let (append, truncate) = match mode {
            LogFileMode::Refuse => {
                if path.exists() {
                    anyhow::bail!(
                        "log file already exists: {}\n\n  bootintel refuses to overwrite existing logs by default (a captured boot session is often expensive to reproduce).\n  To keep the existing content and add to it, re-run with:\n    --log-append\n  To discard the existing file and start fresh, re-run with:\n    --log-overwrite\n  Or pick a different --log-file path.",
                        path.display()
                    );
                }
                (false, true)
            }
            LogFileMode::Append => (true, false),
            LogFileMode::Overwrite => (false, true),
        };
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(truncate)
            .open(path)
            .with_context(|| format!("opening log file {}", path.display()))?;
        // 8 KiB buffer — big enough that a boot log's typical burst
        // rate doesn't hit syscalls per byte, small enough that a
        // crash doesn't lose more than a couple seconds of data.
        Ok(Self {
            writer: BufWriter::with_capacity(8 * 1024, file),
            broken: false,
            timestamps: false,
            // Treat the very first byte as "start of line" so append
            // mode gets a fresh timestamp even if the previous
            // capture ended without a trailing \n.
            at_line_start: true,
        })
    }

    /// Enable/disable line-leading ISO-8601 UTC timestamps. Chainable
    /// so callers can do `LogFile::create(...)?.with_timestamps(true)`.
    pub fn with_timestamps(mut self, on: bool) -> Self {
        self.timestamps = on;
        self
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        if self.broken || bytes.is_empty() {
            return;
        }
        let res = if self.timestamps {
            self.write_with_timestamps(bytes)
        } else {
            self.writer.write_all(bytes)
        };
        if let Err(e) = res {
            eprintln!("[bootintel] log-file write failed: {e}. Further writes suppressed.");
            self.broken = true;
        }
    }

    /// Split `bytes` on '\n' boundaries and emit a timestamp before
    /// each non-empty line segment that starts at a line boundary.
    /// A chunk that starts mid-line (i.e. previous chunk didn't end
    /// with \n) writes without a leading timestamp — the timestamp
    /// pins to the line's first byte, not to arbitrary chunk splits.
    fn write_with_timestamps(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        for &b in bytes {
            if self.at_line_start && b != b'\n' {
                write!(self.writer, "[{}] ", iso_utc_now())?;
                self.at_line_start = false;
            }
            self.writer.write_all(std::slice::from_ref(&b))?;
            if b == b'\n' {
                self.at_line_start = true;
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) {
        if self.broken {
            return;
        }
        if let Err(e) = self.writer.flush() {
            eprintln!("[bootintel] log-file flush failed: {e}");
            self.broken = true;
        }
    }
}

impl Drop for LogFile {
    fn drop(&mut self) {
        self.flush();
    }
}

/// ISO-8601 UTC with millisecond precision, e.g. `2026-08-24T09:12:03.487Z`.
/// Deliberately zero-dep — computed from `SystemTime` and a fixed
/// civil-time algorithm. Cheaper than pulling in `chrono` for one
/// output format, and the output is stable across timezones
/// (always UTC) so log diffs across machines stay comparable.
fn iso_utc_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let (y, m, d, hh, mm, ss) = civil_from_unix(secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

/// Convert a Unix timestamp (seconds since 1970-01-01 UTC) into
/// (year, month, day, hour, minute, second). Uses Howard Hinnant's
/// days-from-civil algorithm (public domain, well-tested).
fn civil_from_unix(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let time_of_day = secs % 86_400;
    let hh = (time_of_day / 3_600) as u32;
    let mm = ((time_of_day % 3_600) / 60) as u32;
    let ss = (time_of_day % 60) as u32;

    // Shift epoch to March 1, 0000 so leap-day is at end of year.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d, hh, mm, ss)
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn writes_bytes_and_flushes_on_drop() {
        let dir = tempdir_or_current();
        let path = dir.join("bootintel-logfile-test.txt");
        let _ = std::fs::remove_file(&path);
        {
            let mut lf = LogFile::create(&path, LogFileMode::Overwrite).unwrap();
            lf.write_bytes(b"first chunk\n");
            lf.write_bytes(b"second chunk\n");
            // drop: should flush
        }
        let mut contents = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "first chunk\nsecond chunk\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_write_is_noop() {
        let dir = tempdir_or_current();
        let path = dir.join("bootintel-logfile-empty-test.txt");
        let _ = std::fs::remove_file(&path);
        let mut lf = LogFile::create(&path, LogFileMode::Overwrite).unwrap();
        lf.write_bytes(b"");
        drop(lf);
        // File exists but empty.
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_mode_preserves_existing_content() {
        let dir = tempdir_or_current();
        let path = dir.join("bootintel-logfile-append-test.txt");
        std::fs::write(&path, b"prior content\n").unwrap();
        {
            let mut lf = LogFile::create(&path, LogFileMode::Append).unwrap();
            lf.write_bytes(b"appended\n");
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "prior content\nappended\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refuse_mode_bails_when_file_exists() {
        let dir = tempdir_or_current();
        let path = dir.join("bootintel-logfile-refuse-test.txt");
        std::fs::write(&path, b"prior content\n").unwrap();
        let res = LogFile::create(&path, LogFileMode::Refuse);
        assert!(
            res.is_err(),
            "expected refuse-mode to bail on existing file"
        );
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("already exists"), "got: {msg}");
        assert!(
            msg.contains("--log-append") || msg.contains("--log-overwrite"),
            "got: {msg}"
        );
        // File must NOT have been clobbered.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "prior content\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refuse_mode_creates_file_when_absent() {
        let dir = tempdir_or_current();
        let path = dir.join("bootintel-logfile-refuse-new-test.txt");
        let _ = std::fs::remove_file(&path);
        let mut lf = LogFile::create(&path, LogFileMode::Refuse).unwrap();
        lf.write_bytes(b"fresh\n");
        drop(lf);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "fresh\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn timestamps_prefix_line_starts_only() {
        let dir = tempdir_or_current();
        let path = dir.join("bootintel-logfile-timestamps-test.txt");
        let _ = std::fs::remove_file(&path);
        {
            let mut lf = LogFile::create(&path, LogFileMode::Overwrite)
                .unwrap()
                .with_timestamps(true);
            // Chunk 1 starts a line, ends mid-line
            lf.write_bytes(b"line one\nline two, part A ");
            // Chunk 2 finishes line two, starts line three
            lf.write_bytes(b"and part B\nline three\n");
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        // Exactly three ISO-timestamp brackets (one per line-start).
        let ts_count = contents.matches("[2").filter(|_| true).count();
        assert_eq!(ts_count, 3, "want 3 timestamps, got contents: {contents}");
        // Line 2 was split across chunks — its "and part B" fragment
        // must NOT have its own timestamp.
        assert!(
            contents.contains("part A and part B"),
            "line 2 split incorrectly: {contents}"
        );
        // Timestamp format is ISO-8601 with ms + Z suffix.
        let re = regex_like_iso(&contents);
        assert!(re, "timestamps aren't ISO-8601 shaped: {contents}");
        let _ = std::fs::remove_file(&path);
    }

    fn regex_like_iso(s: &str) -> bool {
        // Zero-dep sanity check: find a substring of shape
        // `[YYYY-MM-DDTHH:MM:SS.mmmZ]`
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix('[') {
                if let Some(idx) = rest.find(']') {
                    let ts = &rest[..idx];
                    if ts.len() == 24
                        && ts.chars().nth(4) == Some('-')
                        && ts.chars().nth(10) == Some('T')
                        && ts.ends_with('Z')
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn tempdir_or_current() -> std::path::PathBuf {
        // Prefer $CARGO_TARGET_TMPDIR when set (cargo test provides
        // it); fall back to std::env::temp_dir(); fall back to CWD.
        if let Ok(p) = std::env::var("CARGO_TARGET_TMPDIR") {
            return std::path::PathBuf::from(p);
        }
        std::env::temp_dir()
    }
}
