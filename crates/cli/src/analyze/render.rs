//! Finding-render helpers.
//!
//! Two audiences:
//!
//! 1. **Inline display** during the analyze loop — one `[bootintel]`
//!    line per new finding, printed to stdout in raw mode (CRLF, not
//!    LF, so the caret returns to column 0 on the user's terminal).
//!    Colorized when stdout is a real TTY, plain otherwise.
//!
//! 2. **Save-to-file summary** for Ctrl-A s — a small JSON block with
//!    the same shape as `bootintel scan --format json` produces, so
//!    downstream tools can read the same schema whether the input
//!    was a saved file or a live capture.

use std::io::{Result as IoResult, Write};

use bootintel_detectors::{Finding, CRITICAL_LABELS};
use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::{queue, style::Print};
use serde::Serialize;

/// Strip C0/C1 control bytes (except tab) from a string so a hostile
/// device can't emit terminal-injection escape sequences via detector
/// output.  A crafted UART stream can put arbitrary bytes in a boot
/// banner; those flow into the `source` / `value` / `detail` fields of
/// findings, and without sanitization would print verbatim to the
/// user's terminal — rewriting lines, hiding output, or worse.
///
/// Keep printable ASCII + UTF-8 multi-byte + horizontal tab. Drop
/// everything else (ESC 0x1b, BEL 0x07, backspace 0x08, CR 0x0d,
/// LF 0x0a, and the C1 range 0x80..=0x9f).
pub fn sanitize_for_term(s: &str) -> String {
    s.chars()
        .filter(|c| {
            let n = *c as u32;
            *c == '\t'                          // tab OK
                || (0x20..0x7f).contains(&n)      // printable ASCII
                || n >= 0xa0 // most Unicode (skip C1 controls)
        })
        .collect()
}

/// Print one finding as an inline `[bootintel]` line. Raw-mode-safe:
/// starts with \r\n so it lands on a fresh line under whatever the
/// serial stream had emitted before, then explicit \r\n at end.
///
/// Called with the loop's shared stdout handle. If colorization
/// enqueue fails, falls back to plain text without erroring the
/// caller — the finding still prints, just monochrome.
pub fn print_finding_inline<W: Write>(out: &mut W, f: &Finding, use_color: bool) -> IoResult<()> {
    let is_critical = CRITICAL_LABELS.contains(&f.label.as_str());
    let glyph = if is_critical { "⚠" } else { "●" };
    // Sanitize label + value + detail against terminal-injection: a
    // hostile boot log can smuggle ANSI escapes into detector fields.
    let label = sanitize_for_term(&f.label);
    let value = sanitize_for_term(&f.value);
    // Start on a fresh line under whatever serial had printed.
    write!(out, "\r\n")?;
    if use_color {
        let color = if is_critical {
            Color::Yellow
        } else {
            Color::Cyan
        };
        // crossterm::queue writes ANSI escapes to the buffer. If any
        // of these fail we just print without color — never bubble
        // color-only errors up to the caller.
        let _ = queue!(
            out,
            SetForegroundColor(color),
            Print(format!("[bootintel] {glyph}  ")),
            ResetColor,
        );
    } else {
        write!(out, "[bootintel] {glyph}  ")?;
    }
    write!(out, "{label}: {value}")?;
    if let Some(d) = &f.detail {
        // Detail sometimes has newlines from noisy log lines; strip.
        let cleaned = sanitize_for_term(d);
        write!(out, "  ({cleaned})")?;
    }
    write!(out, "\r\n")?;
    out.flush()
}

/// Print a compact intro banner when the analyze loop starts. Just
/// tells the user what the live-analysis prefix means; keeps the
/// terminal output readable.
pub fn print_intro<W: Write>(out: &mut W) -> IoResult<()> {
    writeln!(
        out,
        "[bootintel] live analysis on — findings surface as `[bootintel] ●` lines as detectors match"
    )
}

/// The saved-summary shape. Same envelope as `bootintel scan
/// --format json` output — top-level analysis_source, detector_count,
/// findings[]. Additional field: `captured_bytes` so the summary
/// records how much log the findings were derived from.
#[derive(Serialize)]
pub struct SavedSummary<'a> {
    pub bootintel_version: &'a str,
    pub analysis_source: &'a str,
    pub captured_bytes: usize,
    pub detector_count: usize,
    pub findings: Vec<SavedFinding<'a>>,
}

#[derive(Serialize)]
pub struct SavedFinding<'a> {
    pub label: &'a str,
    pub value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'a str>,
}

impl<'a> SavedFinding<'a> {
    pub fn from(f: &'a Finding) -> Self {
        Self {
            label: &f.label,
            value: &f.value,
            detail: f.detail.as_deref(),
            source: f.source.as_deref(),
        }
    }
}

/// Serialize a save-summary to a Writer as pretty JSON with a
/// trailing newline. Called by the Ctrl-A s hotkey path.
pub fn write_summary<W: Write>(
    out: &mut W,
    version: &str,
    captured_bytes: usize,
    detector_count: usize,
    findings: &[Finding],
) -> IoResult<()> {
    let s = SavedSummary {
        bootintel_version: version,
        analysis_source: "client",
        captured_bytes,
        detector_count,
        findings: findings.iter().map(SavedFinding::from).collect(),
    };
    serde_json::to_writer_pretty(&mut *out, &s).map_err(std::io::Error::other)?;
    writeln!(out)
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use bootintel_detectors::Finding;

    fn finding(label: &str, value: &str) -> Finding {
        Finding {
            label: label.to_string(),
            value: value.to_string(),
            detail: None,
            source: None,
        }
    }

    #[test]
    fn plain_inline_output_shape() {
        let mut buf = Vec::new();
        let f = finding("Bootloader", "U-Boot 2020.10");
        print_finding_inline(&mut buf, &f, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("[bootintel] ●  Bootloader: U-Boot 2020.10"));
        assert!(s.starts_with("\r\n"), "raw-mode-safe: leads with CRLF");
        assert!(s.ends_with("\r\n"), "raw-mode-safe: ends with CRLF");
    }

    #[test]
    fn critical_finding_uses_warning_glyph() {
        let mut buf = Vec::new();
        let f = finding("Autoboot interruptable", "Yes");
        print_finding_inline(&mut buf, &f, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("[bootintel] ⚠  Autoboot interruptable"));
    }

    #[test]
    fn detail_is_stripped_of_embedded_newlines() {
        let mut buf = Vec::new();
        let mut f = finding("Kernel", "Linux 5.15");
        f.detail = Some("gcc-11.2.0\nsecond line".to_string());
        print_finding_inline(&mut buf, &f, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("(gcc-11.2.0second line)"));
        // Only the leading CRLF and trailing CRLF — no embedded newline
        // from the detail field.
        assert_eq!(s.matches('\n').count(), 2);
    }

    #[test]
    fn sanitize_strips_ansi_escape_from_hostile_boot_log() {
        // Simulate a boot banner that tried to smuggle ANSI escapes
        // through the label/value fields.
        let s = sanitize_for_term("U-Boot\x1b[2J2020.10\x07 (BEL)");
        assert!(!s.contains('\x1b'), "ESC 0x1b must be stripped");
        assert!(!s.contains('\x07'), "BEL 0x07 must be stripped");
        assert_eq!(s, "U-Boot[2J2020.10 (BEL)");
    }

    #[test]
    fn sanitize_preserves_printable_and_unicode() {
        assert_eq!(sanitize_for_term("normal ascii 123!"), "normal ascii 123!");
        assert_eq!(sanitize_for_term("unicode ● ⚠ ok"), "unicode ● ⚠ ok");
        assert_eq!(
            sanitize_for_term("tab\there"),
            "tab\there",
            "tab is allowed"
        );
    }

    #[test]
    fn sanitize_drops_newlines_and_carriage_returns() {
        // These would break the inline-render CRLF invariant.
        let s = sanitize_for_term("line one\nline two\r\nline three");
        assert!(!s.contains('\n'));
        assert!(!s.contains('\r'));
    }

    #[test]
    fn print_finding_inline_sanitizes_hostile_value() {
        // A malicious device sends a bootloader banner containing
        // a screen-clear escape. The rendered inline finding must
        // not include the escape sequence.
        let mut buf = Vec::new();
        let f = finding("Bootloader", "U-Boot\x1b[2J1970.01");
        print_finding_inline(&mut buf, &f, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains('\x1b'), "ESC must not reach the terminal");
    }

    #[test]
    fn saved_summary_json_shape_matches_scan_output() {
        let f = vec![finding("Bootloader", "U-Boot 2020.10")];
        let mut buf = Vec::new();
        write_summary(&mut buf, "0.1.0", 1234, 9, &f).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["bootintel_version"], "0.1.0");
        assert_eq!(v["analysis_source"], "client");
        assert_eq!(v["captured_bytes"], 1234);
        assert_eq!(v["detector_count"], 9);
        assert_eq!(v["findings"][0]["label"], "Bootloader");
        assert_eq!(v["findings"][0]["value"], "U-Boot 2020.10");
    }
}
